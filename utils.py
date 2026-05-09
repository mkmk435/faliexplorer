import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64

import angr
import claripy
import globals
import archinfo
import techniques
import memHooks
import apiHooks

import traceback
import cle
import re
from cle.backends.pe.relocation.generic import DllImport
from typing import Optional
import json
from datetime import datetime




vuln_rips = []
past_ioctls = []
vulnerabilities_list = []
current_driver_file = None  # Will be set to the driver filename being analyzed
REPORT_DIR = "reports"
REPORT_FILE = None  # Will be set based on the driver name

def next_base_addr(size=0x10000):
    v = globals.FIRST_ADDR
    globals.FIRST_ADDR += size
    return v


# -------------------------------------------------------------------------
# Disassembly
# -------------------------------------------------------------------------

def disasm_file(file_path):
    """
    Disassemble .text section of PE file.
    Returns: (all_instructions, text_instructions)
    """
    instruction_list = []
    text_list = []

    pe = pefile.PE(file_path)

    if pe.FILE_HEADER.Machine == 0x014c:
        md = Cs(CS_ARCH_X86, CS_MODE_32)
    elif pe.FILE_HEADER.Machine == 0x8664:
        md = Cs(CS_ARCH_X86, CS_MODE_64)
    else:
        print(f"[-] Unsupported architecture")
        return [], []

    md.skipdata = True

    IMAGE_SCN_MEM_EXECUTE = 0x20000000

    for section in pe.sections:
        if section.Characteristics & IMAGE_SCN_MEM_EXECUTE:
            sec_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')

            code_bytes = section.get_data()
            base_address = pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress

            for instruction in md.disasm(code_bytes, base_address):
                instruction_list.append(instruction)
                if 'text' in sec_name:
                    # print(f"Instruction: {instruction.mnemonic} {instruction.op_str} at address: {hex(instruction.address)}")
                    text_list.append(instruction)

    return instruction_list, text_list

def detect_driver_framework(driver_path: str) -> str:
    """
    Best-effort classification for a Windows kernel driver framework.
    Returns one of: "kmdf/wdf", "wdm", "unknown".
    """
    try:
        pe = pefile.PE(driver_path)
    except Exception:
        return "unknown"

    imports = set()
    imported_dlls = set()

    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode("utf-8", errors="ignore").lower()
            imported_dlls.add(dll_name)

            for imp in entry.imports:
                if imp.name:
                    imports.add(imp.name.decode("utf-8", errors="ignore").lower())

    # Strong KMDF/WDF indicators:
    # - Imports from Wdf01000 (framework runtime)
    # - Wdf* APIs (WdfDriverCreate, WdfDeviceCreate, etc.)
    if "wdf01000.sys" in imported_dlls or "wdfldr.sys" in imported_dlls:
        return "kmdf/wdf"
    if any(name.startswith("wdf") for name in imports):
        return "kmdf/wdf"

    # WDM-style indicator: dispatch table setup via Io* APIs usually seen in DriverEntry.
    wdm_markers = {
        "iocreatedevice",
        "iocreatedevicesecure",
        "iocreatesymboliclink",
        "iodeletedevice",
        "iodeletesymboliclink",
    }
    if imports.intersection(wdm_markers):
        return "wdm"

    return "unknown"


def fixup_import_symbols(state):
    globals.star_ps_process_type = fix_object_type_import(state, "PsProcessType", globals.ps_process_type)

# List of functions that commonly derail WDF/WDM symbolic execution
    stub_functions = [
        'WdfVersionBind',
        'WdfVersionBindClass',
        'PcInitializeAdapterDriver',
        'IoCreateSymbolicLink',
        'IoOpenDriverRegistryKey',
        'RtlCopyUnicodeString',
        'RtlAppendUnicodeToString',
        'RtlInitUnicodeString'
    ]
    
    for func in stub_functions:
        globals.proj.hook_symbol(func, apiHooks.HookDoNothing(cc=globals.cc))


def fix_object_type_import(state: angr.SimState, object_type_name: str, object_type_import):    
    if not object_type_import:
        return None
    
    # An "object_type_import" points to a kernel memory containing our kernel-defined *ObjectType, which ioctlance intialize to 0
    ps_object_type = state.memory.load(object_type_import, state.arch.bytes, endness=state.arch.memory_endness)
    if not ps_object_type.concrete:
        print(f"Unable to correctly evaluate {object_type_name} import")
        return None

    # We need to store a symbolic value to represent the *ObjectType to recognize it later inside a kernel function hook
    star_ps_object_type = claripy.BVS(f'*{object_type_name}', state.arch.bits)
    state.memory.store(ps_object_type, star_ps_object_type, state.arch.bytes, endness=state.arch.memory_endness, disable_actions=True, inspect=False)
    return star_ps_object_type
    
def is_stack_address(state, addr_ast):
    """
    Checks if a given angr AST address definitively points to the stack.
    """
    stack_base = state.arch.initial_sp
    stack_limit = stack_base - 0x100000 # Standard 1MB stack limit in windows kernel
    
    # 1. Fast Path: If the address is concrete, we don't need the solver
    if addr_ast.concrete:
        # Extract the integer value from the AST
        addr_val = addr_ast.args[0] 
        return stack_limit <= addr_val <= stack_base
        
    # 2. Symbolic Path: If the address is symbolic, it might span multiple regions
    try:
        # Ask the solver: Is it mathematically possible for this address to be OUTSIDE the stack?
        can_be_outside = state.solver.satisfiable(extra_constraints=[
            state.solver.Or(addr_ast < stack_limit, addr_ast > stack_base)
        ])
        
        # Ask the solver: Is it mathematically possible for this address to be INSIDE the stack?
        can_be_inside = state.solver.satisfiable(extra_constraints=[
            addr_ast >= stack_limit,
            addr_ast <= stack_base
        ])
        
        # If it can be inside, but CANNOT be outside, it is definitely a stack buffer.
        if can_be_inside and not can_be_outside:
            return True
            
        # If it can be inside AND outside (can_be_inside and can_be_outside == True),
        # this is usually an unconstrained pointer (Arbitrary Write / Write-What-Where),
        # not a localized stack buffer. We return False to avoid false stack detections.
        return False

    except angr.errors.SimSolverError:
        # If constraints are too complex or contradictory, fail safely
        return False
    
def find_hook_func():
    # Use signature to find memset and memcpy because they are not imported function in Windows kernel.
    memset_hook_address = None
    memcpy_hook_address = None
    for func_addr in globals.cfg.kb.functions:
        func = globals.cfg.kb.functions[func_addr]

        prefetchnta_count = 0
        for block in func.blocks:
            if len(block.capstone.insns) > 2:
                if block.capstone.insns[0].mnemonic == 'movzx' and block.capstone.insns[0].op_str == 'edx, dl' and block.capstone.insns[1].mnemonic == 'movabs' and block.capstone.insns[1].op_str == 'r9, 0x101010101010101':
                    memset_hook_address = func_addr
                    break

            for insn in block.capstone.insns:
                if insn.mnemonic == 'prefetchnta':
                    prefetchnta_count += 1
        
        if prefetchnta_count >= 2:
            memcpy_hook_address = func_addr

    # memset and memcpy are compiled as a function in a complicated way, so we have to find and hook them.
    if memset_hook_address:
        print(f'memset_hook_address: {hex(memset_hook_address)}')
        globals.proj.hook(memset_hook_address, angr.procedures.SIM_PROCEDURES['libc']['memset'](cc=globals.cc))
    if memcpy_hook_address:
        print(f'memcpy_hook_address: {hex(memcpy_hook_address)}')
        globals.proj.hook(memcpy_hook_address, apiHooks.HookMemcpy(cc=globals.cc))




def read_buffer_from_unicode_string(state, unicode_string_pointer):
    us = state.mem[unicode_string_pointer].struct._UNICODE_STRING
    length_expr = us.Length.resolved
    max_length_expr = us.MaximumLength.resolved
    buffer_ptr_expr = us.Buffer.resolved

    length = state.solver.eval(length_expr)
    max_length = state.solver.eval(max_length_expr)
    buffer_addr = state.solver.eval(buffer_ptr_expr)

    if (length == 0) or (max_length == 0):
        return None
    
    raw_data = state.memory.load(buffer_addr, length, disable_actions=True, inspect=False)
    device_name_str = state.solver.eval(raw_data, cast_to=bytes).decode("utf-16le", errors="ignore")

    return device_name_str.strip() if device_name_str is not None else None


def initialize_driver_entry_args(state, driver_object_addr, registry_path_addr):
    driver_object_size = 0x400
    state.memory.store(
        driver_object_addr,
        claripy.BVV(0, driver_object_size * 8),
        driver_object_size,
        disable_actions=True,
        inspect=False
    )

    registry_path = "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\fali"
    registry_path_bytes = registry_path.encode("utf-16le")
    registry_buffer_addr = next_base_addr()
    state.memory.store(
        registry_buffer_addr,
        registry_path_bytes + b"\x00\x00",
        len(registry_path_bytes) + 2,
        disable_actions=True,
        inspect=False
    )

    unistr = state.mem[registry_path_addr].struct._UNICODE_STRING
    state.memory.store(
        registry_path_addr,
        claripy.BVV(0, unistr._type.size),
        unistr._type.size // 8,
        disable_actions=True,
        inspect=False
    )
    unistr.Length = len(registry_path_bytes)
    unistr.MaximumLength = len(registry_path_bytes) + 2
    unistr.Buffer = registry_buffer_addr


def find_ioctl_handler(driver_path):
    # calcola il write address dell'ioctl handler
    try:

        globals.phase = 1
        # _, text_instructions = disasm_file(driver_path)

        driver_object_addr = next_base_addr()
        # device_object_addr = next_base_addr()
        registry_path_addr = next_base_addr()
        state = globals.proj.factory.call_state(
            globals.proj.entry,
            driver_object_addr,
            registry_path_addr,
            cc=globals.cc
        )

        state.globals['open_section_handles'] = ()
        state.globals['tainted_unicode_strings'] = ()
        state.globals['ioctl_handler'] = 0

        fixup_import_symbols(state)

        state.inspect.b('mem_write', mem_write_address=driver_object_addr + (0xe0 if globals.proj.arch.name == archinfo.ArchAMD64.name else 0x70), when=angr.BP_AFTER, action=memHooks.b_write_ioctl_handler)
        state.inspect.b('mem_write', mem_write_address=driver_object_addr + (0x60 if globals.proj.arch.name == archinfo.ArchAMD64.name else 0x30), when=angr.BP_AFTER, action=memHooks.b_mem_write_DriverStartIo)
        state.inspect.b('call', when=angr.BP_BEFORE, action=memHooks.b_call)
        # state.inspect.b('call', when=angr.BP_BEFORE, action=memHooks.universal_hook)

        globals.simgr = globals.proj.factory.simgr(state)
        globals.simgr.use_technique(angr.exploration_techniques.DFS())

        # globals.simgr.use_technique(angr.exploration_techniques.LoopSeer(cfg=globals.cfg, functions=None, bound=globals.args.bound))
        #globals.simgr.use_technique(angr.exploration_techniques.LocalLoopSeer(bound=globals.args.bound))
        # globals.simgr.use_technique(angr.exploration_techniques.LengthLimiter(globals.args.length))


        ed = techniques.ExplosionDetector(threshold=10000)
        globals.simgr.use_technique(ed)

        def filter_func(s):
            # Return false if ioctl handler not found.
            if not s.globals['ioctl_handler']:
                return False
            # If the complete mode on, we need to keep analyzing until the return value is STATUS_SUCCESS.
            if globals.args.complete:
                retval = globals.cc.return_val(angr.types.BASIC_TYPES['long int']).get_value(s)
                return s.solver.satisfiable(extra_constraints=[retval == 0])
            else:
                return True

        # Start symbolic execution to find the ioctl handler.
        for i in range(0x300000):
            try:
                globals.simgr.step(num_inst=1)
                # globals.simgr.step()
            except Exception as e:
                print(f'error on state {globals.simgr.active}: {str(e)}')
                globals.simgr.move(from_stash='active', to_stash='_Drop')

            # utils.print_debug(f'simgr: {globals.simgr}\n\tactive: {globals.simgr.active}\n\tdeferred: {globals.simgr.deferred}\n\terrored: {globals.simgr.errored}\n\tdeadneded: {globals.simgr.deadended}')
            
            # If a state reach deadended, we check if the condition is satisfied with filter_func.
            globals.simgr.move(from_stash='deadended', to_stash='found', filter_func=filter_func)

            # Once there is a state in the found stash, or there is no active and deferred states, we break the loop.
            if len(globals.simgr.found) or (not len(globals.simgr.active) and not len(globals.simgr.deferred)):
                break
        else:
            print('ERROR:ioctl handler not found')
        
        if globals.simgr.errored:
            for s in globals.simgr.errored:
                print(f'ERROR: {repr(s)}')

        # Return the ioctl handler address and a usable state.
        if len(globals.simgr.found):
            success_state = globals.simgr.found[0]
            return globals.ioctl_handler, success_state
        if globals.ioctl_handler:
            for stash_name in ("active", "deferred", "deadended", "_Drop"):
                stash = getattr(globals.simgr, stash_name, None)
                if stash and len(stash):
                    return globals.ioctl_handler, stash[0]
        return globals.ioctl_handler, None
    except Exception as e:
        print(f'Error in find_ioctl_handler: {str(e)}')
        traceback.print_exc()
        return None, None


def _fixup_driver_entry_discovery_imports(state):
    globals.star_ps_process_type = fix_object_type_import(state, "PsProcessType", globals.ps_process_type)

    stub_functions = [
        'WdfVersionBind',
        'WdfVersionBindClass',
        'PcInitializeAdapterDriver',
        'IoOpenDriverRegistryKey',
        'RtlAppendUnicodeToString',
    ]

    for func in stub_functions:
        globals.proj.hook_symbol(func, apiHooks.HookDoNothing(cc=globals.cc))


def _state_stash_snapshot(simgr):
    for stash_name in ("active", "deferred", "deadended"):
        stash = getattr(simgr, stash_name, None)
        if stash and len(stash):
            return stash[0].copy()
    return None


def _strip_discovery_breakpoints(state):
    try:
        for event_type in state.inspect._breakpoints:
            state.inspect._breakpoints[event_type] = []
    except Exception:
        pass
    return state


def _call_arg(state, index):
    if state.arch.name == archinfo.ArchAMD64.name:
        regs = (state.regs.rcx, state.regs.rdx, state.regs.r8, state.regs.r9)
        if index < len(regs):
            return regs[index]

        stack_index = index - len(regs)
        return state.memory.load(
            state.regs.rsp + 0x20 + state.arch.bytes * stack_index,
            state.arch.bytes,
            endness=state.arch.memory_endness
        )

    return state.memory.load(
        state.regs.sp + state.arch.bytes * (index + 1),
        state.arch.bytes,
        endness=state.arch.memory_endness
    )


def _read_wdf_evt_device_add(state, driver_config_ptr):
    try:
        config_size = state.solver.eval(state.memory.load(
            driver_config_ptr,
            4,
            endness=state.arch.memory_endness
        ))
        if config_size < 0x10 or config_size > 0x100:
            return 0

        return state.solver.eval(state.memory.load(
            driver_config_ptr + state.arch.bytes,
            state.arch.bytes,
            endness=state.arch.memory_endness
        ))
    except Exception:
        return 0


def _read_wdf_evt_io_device_control(state, queue_config_ptr):
    try:
        evt_io_device_control_offset = 0x10 + (3 * state.arch.bytes)
        config_size = state.solver.eval(state.memory.load(
            queue_config_ptr,
            4,
            endness=state.arch.memory_endness
        ))
        if config_size < evt_io_device_control_offset + state.arch.bytes or config_size > 0x300:
            return 0

        return state.solver.eval(state.memory.load(
            queue_config_ptr + evt_io_device_control_offset,
            state.arch.bytes,
            endness=state.arch.memory_endness
        ))
    except Exception:
        return 0


def find_ioctl_handler_wdf2(driver_path):
    """
    Find a usable IOCTL entry point for both WDM dispatch-table drivers and
    KMDF/WDF EvtIoDeviceControl callbacks.
    """
    try:
        globals.phase = 1
        globals.ioctl_handler = 0

        driver_object_addr = next_base_addr()
        registry_path_addr = next_base_addr()
        state = globals.proj.factory.call_state(
            globals.proj.entry,
            driver_object_addr,
            registry_path_addr,
            cc=globals.cc
        )
        initialize_driver_entry_args(state, driver_object_addr, registry_path_addr)

        state.globals['open_section_handles'] = ()
        state.globals['tainted_unicode_strings'] = ()
        state.globals['ioctl_handler'] = 0
        state.globals['ioctl_handler_kind'] = None
        state.globals['evt_driver_device_add'] = 0

        _fixup_driver_entry_discovery_imports(state)

        wdf_driver_create_addr = resolve_import_symbol(globals.proj.loader, "WdfDriverCreate")
        wdf_io_queue_create_addr = resolve_import_symbol(globals.proj.loader, "WdfIoQueueCreate")
        ioctl_major_function_offset = 0xe0 if globals.proj.arch.name == archinfo.ArchAMD64.name else 0x70

        found = {
            'handler': 0,
            'state': None,
            'kind': None,
            'evt_device_add': 0,
            'last_printed_handler': 0,
            'last_printed_evt_device_add': 0,
        }
        wdm_settle_steps_remaining = None

        def remember_handler(s, handler_addr, kind):
            if not handler_addr or not _addr_in_main_object(handler_addr):
                return

            globals.ioctl_handler = handler_addr
            s.globals['ioctl_handler'] = handler_addr
            s.globals['ioctl_handler_kind'] = kind
            found['handler'] = handler_addr
            found['kind'] = kind
            found['state'] = _strip_discovery_breakpoints(s.copy())

        def capture_wdm_dispatch(s):
            nonlocal wdm_settle_steps_remaining

            try:
                handler_addr = s.solver.eval(s.inspect.mem_write_expr)
            except Exception:
                return

            remember_handler(s, handler_addr, 'wdm')
            wdm_settle_steps_remaining = 20000
            if found['last_printed_handler'] != handler_addr:
                found['last_printed_handler'] = handler_addr
                print(f"IRP_MJ_DEVICE_CONTROL handler candidate: {hex(handler_addr)}")

        def capture_wdf_registration(s):
            try:
                call_targets = s.solver.eval_upto(s.inspect.function_address, 2)
            except Exception:
                call_targets = []

            call_target = call_targets[0] if len(call_targets) == 1 else None
            known_wdf_driver_create = wdf_driver_create_addr and call_target == wdf_driver_create_addr
            known_wdf_io_queue_create = wdf_io_queue_create_addr and call_target == wdf_io_queue_create_addr

            # KMDF wrappers often call through the WdfFunctions table, so the
            # target may not resolve to an import. Table thunks also pass
            # WdfDriverGlobals as arg0, shifting the public WDF API arguments.
            driver_config_indexes = (3,) if known_wdf_driver_create else (3, 4)
            if known_wdf_driver_create or not found['evt_device_add']:
                for driver_config_index in driver_config_indexes:
                    try:
                        driver_config_ptr = s.solver.eval(_call_arg(s, driver_config_index))
                        evt_device_add = _read_wdf_evt_device_add(s, driver_config_ptr)
                    except Exception:
                        evt_device_add = 0

                    if evt_device_add and _addr_in_main_object(evt_device_add):
                        s.globals['evt_driver_device_add'] = evt_device_add
                        found['evt_device_add'] = evt_device_add
                        if found['last_printed_evt_device_add'] != evt_device_add:
                            found['last_printed_evt_device_add'] = evt_device_add
                            print(f"WDF EvtDriverDeviceAdd: {hex(evt_device_add)}")
                        break

            queue_config_indexes = (1,) if known_wdf_io_queue_create else (1, 2)
            if known_wdf_io_queue_create or not found['handler']:
                for queue_config_index in queue_config_indexes:
                    try:
                        queue_config_ptr = s.solver.eval(_call_arg(s, queue_config_index))
                        evt_io_device_control = _read_wdf_evt_io_device_control(s, queue_config_ptr)
                    except Exception:
                        evt_io_device_control = 0

                    if evt_io_device_control:
                        remember_handler(s, evt_io_device_control, 'wdf_evt_io_device_control')
                        print(f"WDF EvtIoDeviceControl handler: {hex(evt_io_device_control)}")
                        break

        state.inspect.b(
            'mem_write',
            mem_write_address=driver_object_addr + ioctl_major_function_offset,
            when=angr.BP_AFTER,
            action=capture_wdm_dispatch
        )
        state.inspect.b('call', when=angr.BP_BEFORE, action=capture_wdf_registration)
        state.inspect.b('call', when=angr.BP_BEFORE, action=memHooks.b_call)

        globals.simgr = globals.proj.factory.simgr(state)
        globals.simgr.use_technique(angr.exploration_techniques.DFS())
        ed = techniques.ExplosionDetector(threshold=10000)
        globals.simgr.use_technique(ed)

        driver_state = None
        for _ in range(0x300000):
            if found['handler'] and found['kind'] == 'wdf_evt_io_device_control':
                return found['handler'], found['state']

            if not len(globals.simgr.active) and not len(globals.simgr.deferred):
                break

            try:
                globals.simgr.step(num_inst=1)
            except Exception as e:
                print(f'error on state {globals.simgr.active}: {str(e)}')
                globals.simgr.move(from_stash='active', to_stash='_Drop')

            if found['handler'] and found['kind'] == 'wdm' and wdm_settle_steps_remaining is not None:
                wdm_settle_steps_remaining -= 1
                if wdm_settle_steps_remaining <= 0:
                    return found['handler'], found['state']

            if ed.state_exploded_bool:
                break

        driver_state = _state_stash_snapshot(globals.simgr)
        if found['handler']:
            return found['handler'], found['state']

        if found['evt_device_add'] and not found['handler']:
            evt_state = _strip_discovery_breakpoints(driver_state or state.copy())
            evt_state.globals['open_section_handles'] = evt_state.globals.get('open_section_handles', ())
            evt_state.globals['tainted_unicode_strings'] = evt_state.globals.get('tainted_unicode_strings', ())
            evt_state.inspect.b('call', when=angr.BP_BEFORE, action=capture_wdf_registration)
            evt_state.inspect.b('call', when=angr.BP_BEFORE, action=memHooks.b_call)

            wdf_driver_handle = evt_state.globals.get('wdf_driver_handle', next_base_addr())
            device_init_addr = next_base_addr()
            evt_state.memory.store(
                device_init_addr,
                claripy.BVS('wdf_device_init', 0x200 * 8),
                0x200,
                disable_actions=True,
                inspect=False
            )

            globals.simgr = globals.proj.factory.simgr(globals.proj.factory.call_state(
                found['evt_device_add'],
                wdf_driver_handle,
                device_init_addr,
                cc=globals.cc,
                base_state=evt_state
            ))
            globals.simgr.use_technique(angr.exploration_techniques.DFS())
            ed = techniques.ExplosionDetector(threshold=10000)
            globals.simgr.use_technique(ed)

            for _ in range(0x200000):
                if found['handler']:
                    return found['handler'], found['state']

                if not len(globals.simgr.active) and not len(globals.simgr.deferred):
                    break

                try:
                    globals.simgr.step(num_inst=1)
                except Exception as e:
                    print(f'error on EvtDriverDeviceAdd state {globals.simgr.active}: {str(e)}')
                    globals.simgr.move(from_stash='active', to_stash='_Drop')

                if ed.state_exploded_bool:
                    break

        if globals.simgr.errored:
            for s in globals.simgr.errored:
                print(f'ERROR: {repr(s)}')

        total_instr, _ = disasm_file(driver_path)
        static_wdf_candidate = _find_static_wdf_evt_io_device_control_assignment(total_instr)
        if static_wdf_candidate and static_wdf_candidate['handler_addr']:
            handler_addr = static_wdf_candidate['handler_addr']
            instr = static_wdf_candidate['instr']
            print(f"Static WDF EvtIoDeviceControl assignment at {hex(instr.address)}: {instr.mnemonic} {instr.op_str}")
            print(f"Resolved WDF EvtIoDeviceControl handler: {hex(handler_addr)}")
            globals.ioctl_handler = handler_addr
            recovered_state = _make_synthetic_wdf_ioctl_base_state()
            recovered_state.globals['ioctl_handler'] = handler_addr
            return handler_addr, recovered_state

        static_candidate = _find_static_major_function_ioctl_assignment(total_instr, ioctl_major_function_offset)
        if static_candidate and static_candidate['handler_addr'] and _addr_in_main_object(static_candidate['handler_addr']):
            handler_addr = static_candidate['handler_addr']
            print(f"Static IRP_MJ_DEVICE_CONTROL handler: {hex(handler_addr)}")
            globals.ioctl_handler = handler_addr
            recovered_state = _recover_state_at_address(state, static_candidate['instr'].address)
            if recovered_state is None:
                recovered_state = _make_synthetic_ioctl_base_state()
            recovered_state.globals['ioctl_handler'] = handler_addr
            recovered_state.globals['ioctl_handler_kind'] = 'wdm'
            return handler_addr, _strip_discovery_breakpoints(recovered_state)

        return None, None
    except Exception as e:
        print(f'Error in find_ioctl_handler_wdf2: {str(e)}')
        traceback.print_exc()
        return None, None

def _canonical_register_name(reg_name):
    reg_name = reg_name.lower().strip()
    aliases = {
        'rax': {'rax', 'eax', 'ax', 'al', 'ah'},
        'rbx': {'rbx', 'ebx', 'bx', 'bl', 'bh'},
        'rcx': {'rcx', 'ecx', 'cx', 'cl', 'ch'},
        'rdx': {'rdx', 'edx', 'dx', 'dl', 'dh'},
        'rsi': {'rsi', 'esi', 'si', 'sil'},
        'rdi': {'rdi', 'edi', 'di', 'dil'},
        'rbp': {'rbp', 'ebp', 'bp', 'bpl'},
        'rsp': {'rsp', 'esp', 'sp', 'spl'},
    }
    for i in range(8, 16):
        aliases[f'r{i}'] = {f'r{i}', f'r{i}d', f'r{i}w', f'r{i}b'}

    for canonical, names in aliases.items():
        if reg_name in names:
            return canonical
    return reg_name


def _split_instruction_operands(op_str):
    return [part.strip().lower() for part in op_str.split(',')]


def _parse_int_literal(value):
    value = value.lower().strip()
    value = value.replace('offset ', '')
    if re.fullmatch(r'[0-9a-f]+h', value):
        return int(value[:-1], 16)
    try:
        return int(value, 0)
    except ValueError:
        return None


def _extract_mem_base_offset(operand):
    normalized = operand.lower().replace(' ', '')
    match = re.search(r'\[([a-z][a-z0-9]*)([+-])(0x[0-9a-f]+|\d+)\]', normalized)
    if not match:
        return None, None

    base_reg = _canonical_register_name(match.group(1))
    offset = int(match.group(3), 0)
    if match.group(2) == '-':
        offset = -offset
    return base_reg, offset


def _resolve_rip_relative_operand(instr):
    match = re.search(r'\[rip\s*([+-])\s*(0x[0-9a-f]+|\d+)\]', instr.op_str.lower())
    if not match:
        return None

    displacement = int(match.group(2), 0)
    if match.group(1) == '-':
        displacement = -displacement
    return instr.address + instr.size + displacement


def _read_project_word(addr):
    try:
        return globals.proj.loader.memory.unpack_word(addr)
    except Exception:
        return None


def _addr_in_main_object(addr):
    try:
        main_obj = globals.proj.loader.main_object
        return main_obj.min_addr <= addr < main_obj.max_addr
    except Exception:
        return False


def _resolve_static_source_value(instructions, instr_index, src_op):
    src_op = src_op.lower().strip()
    literal = _parse_int_literal(src_op)
    if literal is not None:
        return literal

    if not re.fullmatch(r'[a-z][a-z0-9]*', src_op):
        return None

    target_reg = _canonical_register_name(src_op)
    for prev in reversed(instructions[max(0, instr_index - 40):instr_index]):
        if not (prev.mnemonic.startswith('mov') or prev.mnemonic == 'lea'):
            continue

        parts = _split_instruction_operands(prev.op_str)
        if len(parts) < 2:
            continue

        dst_reg = _canonical_register_name(parts[0])
        if dst_reg != target_reg:
            continue

        prev_src = parts[-1]
        if prev.mnemonic == 'lea':
            rip_target = _resolve_rip_relative_operand(prev)
            if rip_target is not None:
                return rip_target
            return None

        literal = _parse_int_literal(prev_src)
        if literal is not None:
            return literal

        rip_target = _resolve_rip_relative_operand(prev)
        if rip_target is not None:
            return _read_project_word(rip_target)

        return None

    return None


def _find_static_major_function_ioctl_assignment(instructions, target_offset):
    driver_object_neighbor_offsets = {0x68, 0x70, 0x78, 0x80, 0x148}
    candidates = []

    for idx, instr in enumerate(instructions):
        if not instr.mnemonic.startswith('mov'):
            continue

        parts = _split_instruction_operands(instr.op_str)
        if len(parts) < 2:
            continue

        dst_op = parts[0]
        src_op = parts[-1]
        base_reg, offset = _extract_mem_base_offset(dst_op)
        if offset != target_offset:
            continue

        handler_addr = _resolve_static_source_value(instructions, idx, src_op)
        score = 0

        if handler_addr is not None and _addr_in_main_object(handler_addr):
            score += 10

        for neighbor in instructions[max(0, idx - 40):min(len(instructions), idx + 40)]:
            neighbor_parts = _split_instruction_operands(neighbor.op_str)
            if not neighbor_parts:
                continue

            neighbor_base, neighbor_offset = _extract_mem_base_offset(neighbor_parts[0])
            if neighbor_base == base_reg and neighbor_offset in driver_object_neighbor_offsets:
                score += 3

        candidates.append({
            'score': score,
            'instr': instr,
            'src_op': src_op,
            'handler_addr': handler_addr,
        })

    if not candidates:
        return None

    candidates.sort(key=lambda c: (c['score'], c['instr'].address), reverse=True)
    return candidates[0]


def _find_static_wdf_evt_io_device_control_assignment(instructions):
    evt_io_device_control_offset = 0x10 + (3 * globals.proj.arch.bytes)
    candidates = []

    for idx, instr in enumerate(instructions):
        if not instr.mnemonic.startswith('mov'):
            continue

        parts = _split_instruction_operands(instr.op_str)
        if len(parts) < 2:
            continue

        dst_base, dst_offset = _extract_mem_base_offset(parts[0])
        if dst_base is None or dst_offset is None:
            continue

        handler_addr = _resolve_static_source_value(instructions, idx, parts[-1])
        if handler_addr is None or not _addr_in_main_object(handler_addr):
            continue

        config_offset = dst_offset - evt_io_device_control_offset
        score = 0

        for neighbor in instructions[max(0, idx - 80):min(len(instructions), idx + 80)]:
            neighbor_parts = _split_instruction_operands(neighbor.op_str)
            if len(neighbor_parts) < 2:
                continue

            if neighbor.mnemonic.startswith('mov'):
                size_base, size_offset = _extract_mem_base_offset(neighbor_parts[0])
                if size_base == dst_base and size_offset == config_offset:
                    score += 5

            if neighbor.mnemonic == 'lea':
                arg_reg = _canonical_register_name(neighbor_parts[0])
                cfg_base, cfg_offset = _extract_mem_base_offset(neighbor_parts[-1])
                if cfg_base == dst_base and cfg_offset == config_offset and arg_reg in {'rdx', 'r8'}:
                    score += 8

        if score:
            candidates.append({
                'score': score,
                'instr': instr,
                'handler_addr': handler_addr,
            })

    if not candidates:
        return None

    candidates.sort(key=lambda c: (c['score'], c['instr'].address), reverse=True)
    return candidates[0]


def _recover_state_at_address(initial_state, target_addr, max_steps=0x20000):
    simgr = globals.proj.factory.simulation_manager(initial_state)
    simgr.use_technique(angr.exploration_techniques.DFS())
    ed = techniques.ExplosionDetector(threshold=10000)
    simgr.use_technique(ed)

    for _ in range(max_steps):
        for stash_name in ("active", "deferred"):
            stash = getattr(simgr, stash_name, None)
            if not stash:
                continue
            for state in stash:
                if state.addr == target_addr:
                    return state

        if not len(simgr.active) and not len(simgr.deferred):
            break

        try:
            simgr.step(num_inst=1)
        except Exception:
            simgr.move(from_stash='active', to_stash='_Drop')

        if ed.state_exploded_bool:
            break

    return None


def _make_synthetic_ioctl_base_state():
    state = globals.proj.factory.blank_state()
    state.globals['open_section_handles'] = ()
    state.globals['tainted_unicode_strings'] = ()

    device_object_addr = next_base_addr()
    device_extension_addr = next_base_addr()
    state.globals['device_object_addr'] = device_object_addr

    state.memory.store(
        device_object_addr,
        claripy.BVV(0, 0x400 * 8),
        0x400,
        disable_actions=True,
        inspect=False
    )
    state.memory.store(
        device_extension_addr,
        claripy.BVS('device_extension', 0x400 * 8),
        0x400,
        disable_actions=True,
        inspect=False
    )

    state.mem[device_object_addr].DEVICE_OBJECT.Flags = 0
    state.mem[device_object_addr].DEVICE_OBJECT.DeviceExtension = device_extension_addr
    fixup_import_symbols(state)
    return state


def _make_synthetic_wdf_ioctl_base_state():
    state = globals.proj.factory.blank_state()
    state.globals['open_section_handles'] = ()
    state.globals['tainted_unicode_strings'] = ()
    state.globals['ioctl_handler_kind'] = 'wdf_evt_io_device_control'
    state.globals['wdf_queue_handle'] = next_base_addr()
    fixup_import_symbols(state)
    return state


def find_ioctl_handler_wdf(driver_path):
    print("WDF/Heuristic driver detected, using heuristics to find IOCTL handler")
    try:
        globals.phase = 1
        total_instr, text_instr = disasm_file(driver_path)

        driver_object_addr = next_base_addr()
        registry_path_addr = next_base_addr()
        
        state = globals.proj.factory.call_state(
            globals.proj.entry, 
            driver_object_addr, 
            registry_path_addr, 
            cc=globals.cc
        )
        initialize_driver_entry_args(state, driver_object_addr, registry_path_addr)

        state.globals['open_section_handles'] = ()
        state.globals['tainted_unicode_strings'] = ()
        state.globals['ioctl_handler'] = 0
        state.globals['wdf_ioctl_handler_found'] = False
        fixup_import_symbols(state)
        
        ioctl_major_function_offset = 0xe0 if globals.proj.arch.name == archinfo.ArchAMD64.name else 0x70

        static_candidate = _find_static_major_function_ioctl_assignment(total_instr, ioctl_major_function_offset)
        if static_candidate and static_candidate['handler_addr'] is not None:
            handler_addr = static_candidate['handler_addr']
            instr = static_candidate['instr']
            print(f"Static IRP_MJ_DEVICE_CONTROL assignment at {hex(instr.address)}: {instr.mnemonic} {instr.op_str}")
            print(f"Resolved IOCTL handler: {hex(handler_addr)}")
            globals.ioctl_handler = handler_addr
            recovered_state = _recover_state_at_address(state, instr.address)
            if recovered_state is None:
                print("Unable to recover DriverEntry state at the IOCTL registration point; using synthesized IOCTL base state.")
                recovered_state = _make_synthetic_ioctl_base_state()
            return handler_addr, recovered_state

        wdf_io_queue_create_addr = resolve_import_symbol(globals.proj.loader, "WdfIoQueueCreate")
        evt_io_device_control_offset = 0x10 + (3 * globals.proj.arch.bytes)
        post_write_steps_remaining = None

        def b_capture_major_function_ioctl(s):
            nonlocal post_write_steps_remaining
            try:
                ioctl_handler_addr = s.solver.eval(s.inspect.mem_write_expr)
            except Exception:
                return

            globals.ioctl_handler = ioctl_handler_addr
            s.globals['ioctl_handler'] = ioctl_handler_addr
            s.globals['wdf_ioctl_handler_found'] = True
            post_write_steps_remaining = 10000
            print(f"IRP_MJ_DEVICE_CONTROL handler: {hex(ioctl_handler_addr)}")

        def b_capture_wdf_ioctl_handler(s):
            nonlocal post_write_steps_remaining
            if s.globals.get('wdf_ioctl_handler_found') or not wdf_io_queue_create_addr:
                return

            try:
                call_target = s.solver.eval(s.inspect.function_address)
            except Exception:
                return

            if call_target != wdf_io_queue_create_addr:
                return

            try:
                if s.arch.name == archinfo.ArchAMD64.name:
                    io_queue_config_ptr = s.solver.eval(s.regs.rdx)
                else:
                    sp = s.regs.sp
                    io_queue_config_ptr = s.solver.eval(
                        s.memory.load(sp + s.arch.bytes * 2, s.arch.bytes, endness=s.arch.memory_endness)
                    )
            except Exception:
                return

            if io_queue_config_ptr == 0:
                return

            try:
                evt_handler = s.memory.load(
                    io_queue_config_ptr + evt_io_device_control_offset,
                    s.arch.bytes,
                    endness=s.arch.memory_endness
                )
                evt_handler_addr = s.solver.eval(evt_handler)
            except Exception:
                return

            if evt_handler_addr == 0:
                return

            globals.ioctl_handler = evt_handler_addr
            s.globals['ioctl_handler'] = evt_handler_addr
            s.globals['wdf_ioctl_handler_found'] = True
            post_write_steps_remaining = 10000
            print(f"WDF EvtIoDeviceControl handler: {hex(evt_handler_addr)}")

        state.inspect.b(
            'mem_write',
            mem_write_address=driver_object_addr + ioctl_major_function_offset,
            when=angr.BP_AFTER,
            action=b_capture_major_function_ioctl
        )
        state.inspect.b('call', when=angr.BP_BEFORE, action=b_capture_wdf_ioctl_handler)

        globals.simgr = globals.proj.factory.simulation_manager(state)
        globals.simgr.use_technique(angr.exploration_techniques.DFS())
        ed = techniques.ExplosionDetector(threshold=10000)
        globals.simgr.use_technique(ed)

        dynamic_state = None
        for _ in range(0x100000):
            try:
                globals.simgr.step(num_inst=1)
            except Exception as e:
                print(f'error on state {globals.simgr.active}: {str(e)}')
                globals.simgr.move(from_stash='active', to_stash='_Drop')

            if globals.ioctl_handler:
                for stash_name in ("active", "deferred", "deadended", "_Drop"):
                    stash = getattr(globals.simgr, stash_name, None)
                    if stash and len(stash):
                        dynamic_state = stash[0]
                        break
                if dynamic_state is None:
                    dynamic_state = state

                if post_write_steps_remaining is not None:
                    post_write_steps_remaining -= 1
                    if post_write_steps_remaining <= 0:
                        break

            if not len(globals.simgr.active) and not len(globals.simgr.deferred):
                break

        if globals.simgr.errored:
            for s in globals.simgr.errored:
                print(f'ERROR in state: {repr(s)}')

        if globals.ioctl_handler:
            return globals.ioctl_handler, dynamic_state or state

        if static_candidate:
            instr = static_candidate['instr']
            print(f"Found possible IOCTL assignment at {hex(instr.address)}, but could not resolve handler: {instr.mnemonic} {instr.op_str}")
        else:
            print("Could not find IOCTL handler assignment via dynamic or static heuristics.")

        return None, None

    except Exception as e:
        print(f'Error in find_ioctl_handler_wdf: {str(e)}')
        traceback.print_exc()
        return None, None


# def find_ioctl_handler_wdf(driver_path):
#     # Find IOCTL handler for WDF drivers.
#     # Primary path: EvtIoDeviceControl callback registered via WdfIoQueueCreate.
#     # Fallback path: direct write to DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL]
#     # (hybrid KMDF/WDM or PortCls-style drivers may do this and import no WdfIoQueueCreate).
#     try:
#         globals.phase = 1
#         driver_object_addr = next_base_addr()
#         registry_path_addr = next_base_addr()
#         state = globals.proj.factory.call_state(
#             globals.proj.entry,
#             driver_object_addr,
#             registry_path_addr,
#             cc=globals.cc
#         )

#         state.globals['open_section_handles'] = ()
#         state.globals['tainted_unicode_strings'] = ()
#         state.globals['ioctl_handler'] = 0
#         state.globals['wdf_ioctl_handler_found'] = False

#         fixup_import_symbols(state)

#         wdf_io_queue_create_addr = resolve_import_symbol(globals.proj.loader, "WdfIoQueueCreate")
#         if not wdf_io_queue_create_addr:
#             print("WARNING: WdfIoQueueCreate import not found, using dispatch-table fallback")

#         evt_io_device_control_offset = 0x10 + (3 * globals.proj.arch.bytes)
#         ioctl_major_function_offset = 0xe0 if globals.proj.arch.name == archinfo.ArchAMD64.name else 0x70

#         def b_capture_wdf_ioctl_handler(s):
#             if s.globals.get('wdf_ioctl_handler_found'):
#                 return

#             if not wdf_io_queue_create_addr:
#                 return

#             try:
#                 call_target = s.solver.eval(s.inspect.function_address)
#             except Exception:
#                 return

#             if call_target != wdf_io_queue_create_addr:
#                 return

#             try:
#                 if s.arch.name == archinfo.ArchAMD64.name:
#                     io_queue_config_ptr = s.solver.eval(s.regs.rdx)
#                 else:
#                     sp = s.regs.sp
#                     io_queue_config_ptr = s.solver.eval(
#                         s.memory.load(sp + s.arch.bytes * 2, s.arch.bytes, endness=s.arch.memory_endness)
#                     )
#             except Exception:
#                 return

#             if io_queue_config_ptr == 0:
#                 return

#             try:
#                 evt_handler = s.memory.load(
#                     io_queue_config_ptr + evt_io_device_control_offset,
#                     s.arch.bytes,
#                     endness=s.arch.memory_endness
#                 )
#                 evt_handler_addr = s.solver.eval(evt_handler)
#             except Exception:
#                 return

#             if evt_handler_addr == 0:
#                 return

#             globals.ioctl_handler = int(evt_handler_addr)
#             s.globals['ioctl_handler'] = int(evt_handler_addr)
#             s.globals['wdf_ioctl_handler_found'] = True
#             print(f"WDF EvtIoDeviceControl handler: {hex(globals.ioctl_handler)}")

#         # Fallback for hybrid drivers that manually assign IRP_MJ_DEVICE_CONTROL.
#         state.inspect.b(
#             'mem_write',
#             mem_write_address=driver_object_addr + ioctl_major_function_offset,
#             when=angr.BP_AFTER,
#             action=memHooks.b_write_ioctl_handler
#         )
#         state.inspect.b('call', when=angr.BP_BEFORE, action=memHooks.b_call)
#         state.inspect.b('call', when=angr.BP_BEFORE, action=b_capture_wdf_ioctl_handler)

#         globals.simgr = globals.proj.factory.simgr(state)
#         globals.simgr.use_technique(angr.exploration_techniques.DFS())

#         # globals.simgr.use_technique(angr.exploration_techniques.LoopSeer(cfg=globals.cfg, functions=None, bound=globals.args.bound))
#         #globals.simgr.use_technique(angr.exploration_techniques.LocalLoopSeer(bound=globals.args.bound))
#         # globals.simgr.use_technique(angr.exploration_techniques.LengthLimiter(globals.args.length))


#         ed = techniques.ExplosionDetector(threshold=10000)
#         globals.simgr.use_technique(ed)

#         def filter_func(s):
#             # Return false if ioctl handler not found.
#             if not s.globals['ioctl_handler']:
#                 return False
#             # If the complete mode on, we need to keep analyzing until the return value is STATUS_SUCCESS.
#             if globals.args.complete:
#                 retval = globals.mycc.return_val(angr.types.BASIC_TYPES['long int']).get_value(s)
#                 return s.solver.satisfiable(extra_constraints=[retval == 0])
#             else:
#                 return True

#         # Start symbolic execution to find the ioctl handler.
#         for _ in range(0x100000):
#             try:
#                 globals.simgr.step(num_inst=1)
#             except Exception as e:
#                 print(f'error on state {globals.simgr.active}: {str(e)}')
#                 globals.simgr.move(from_stash='active', to_stash='_Drop')
#             globals.simgr.move(from_stash='deadended', to_stash='found', filter_func=filter_func)
#             if len(globals.simgr.found) or (not len(globals.simgr.active) and not len(globals.simgr.deferred)):
#                 break
#         else:
#             print('ERROR:ioctl handler not found')
        
#         if globals.simgr.errored:
#             for s in globals.simgr.errored:
#                 print(f'ERROR: {repr(s)}')

#         # Return the ioctl handler address and a usable state.
#         if len(globals.simgr.found):
#             success_state = globals.simgr.found[0]
#             return globals.ioctl_handler, success_state
#         if globals.ioctl_handler:
#             for stash_name in ("active", "deferred", "deadended", "_Drop"):
#                 stash = getattr(globals.simgr, stash_name, None)
#                 if stash and len(stash):
#                     return globals.ioctl_handler, stash[0]
#         return globals.ioctl_handler, None
#     except Exception as e:
#         print(f'Error in find_ioctl_handler: {str(e)}')
#         traceback.print_exc()
#         return None, None



def tainted_buffer(buffer):
    # if len(state.variables) != 1:
    #     return ''

    str_buf = str(buffer)
    for buf in globals.controllable_buffers:
        if buf in str_buf:
            return buf
    return ''

def set_current_driver(driver_path):
    """Set the current driver being analyzed. Should be called at the start of analysis."""
    global current_driver_file, REPORT_FILE, vulnerabilities_list
    import os
    vulnerabilities_list = []  # Reset vulnerabilities for new driver
    current_driver_file = os.path.splitext(os.path.basename(driver_path))[0]
    REPORT_FILE = os.path.join(REPORT_DIR, f"{current_driver_file}_report.json")
    print(f"[INFO] Starting analysis for driver: {current_driver_file}")


def print_vuln(vuln_type, access_type, state, additional_info, address_info):
    """Print vulnerability information and generate structured JSON report."""
    rip = state.solver.eval(state.regs.rip)
    ioctl = state.solver.eval(globals.IoControlCode)
    # if ioctl  in past_ioctls:
    #     return
    # past_ioctls.append(ioctl)
    # if rip in vuln_rips:
    #     return
    # vuln_rips.append(rip)
    
    # Check for duplicate vulnerability (same type, access type, and IOCTL)
    ioctl_hex = hex(ioctl)
    if _is_vulnerability_duplicate(vuln_type, access_type, ioctl_hex):
        print(f"[INFO] Skipping duplicate vulnerability: {vuln_type} - {access_type} on IOCTL {ioctl_hex}")
        return
    
    # Print to console
    print("____________________________________________________________")
    print(f"[VULN] {vuln_type} - {access_type}")
    print(f"  State: {state}")
    print(f"IOCTL: {ioctl_hex}")
    print(f"RIP: {hex(rip)}")


    for key, value in additional_info.items():
        print(f"  {key}: {value}")
    for key, value in address_info.items():
        print(f"  {key}: {value}")
    print("____________________________________________________________")
    
    # Generate structured report entry
    vuln_entry = {
        "timestamp": datetime.now().isoformat(),
        "vulnerability_type": vuln_type,
        "access_type": access_type,
        "ioctl": ioctl_hex,
        "rip": hex(rip),
        "additional_info": _serialize_for_json(additional_info),
        "address_info": _serialize_for_json(address_info)
    }
    
    # Add to vulnerabilities list
    vulnerabilities_list.append(vuln_entry)
    
    # Write updated report to file (overwrite mode)
    _write_json_report()

def print_debug(msg):
    """Print debug information if DEBUG mode is enabled."""
    if getattr(globals, 'DEBUG', False):
        print(f"[DEBUG] {msg}")


def _is_vulnerability_duplicate(vuln_type, access_type, ioctl_hex):
    """Check if a vulnerability with the same type, access type, and IOCTL already exists."""
    for vuln in vulnerabilities_list:
        if (vuln["vulnerability_type"] == vuln_type and 
            vuln["access_type"] == access_type and 
            vuln["ioctl"] == ioctl_hex):
            return True
    return False


def _serialize_for_json(obj):
    """Convert an object to a JSON-serializable format."""
    if isinstance(obj, dict):
        return {key: _serialize_for_json(value) for key, value in obj.items()}
    elif isinstance(obj, (list, tuple)):
        return [_serialize_for_json(item) for item in obj]
    elif isinstance(obj, str):
        return obj
    elif hasattr(obj, '__str__'):
        return str(obj)
    else:
        return str(obj)


def _write_json_report():
    """Write the vulnerabilities list to a JSON report file (overwrite mode)."""
    import os
    try:
        # Create reports directory if it doesn't exist
        os.makedirs(REPORT_DIR, exist_ok=True)
        
        report_data = {
            "driver_name": current_driver_file,
            "generated_at": datetime.now().isoformat(),
            "total_vulnerabilities": len(vulnerabilities_list),
            "vulnerabilities": vulnerabilities_list
        }
        with open(REPORT_FILE, 'w') as f:
            json.dump(report_data, f, indent=2)
        print(f"[INFO] Vulnerability report updated: {REPORT_FILE}")
    except Exception as e:
        print(f"[ERROR] Failed to write report file: {e}")


def resolve_import_symbol_in_object(pe_object: cle.backends.pe.pe.PE, symbol_name: str) -> Optional[int]:
    if symbol_name not in pe_object.imports:
        return None
    
    sym_import: DllImport = pe_object.imports[symbol_name]
    return pe_object.min_addr + sym_import.relative_addr

def resolve_import_symbol(loader: cle.loader.Loader, symbol_name: str) -> Optional[int]:
    for obj in loader.all_objects:
       result = resolve_import_symbol_in_object(obj, symbol_name)
       if result:
            return result
    
    return None


# Viene usato negli hoo a Zw*File
# Serve per analizzare praticamente se le funzioni hanno parametri taintati
# si chiama cosi' perche' tutte queste funzioni hanno un parametro ObjectAttributes che contiene un UNICODE_STRING 
# che potrebbe essere controllabile e portare a vulnerabilità di tipo Arbitrary File Read/Write
def analyze_ObjectAttributes(func_name, state, ObjectAttributes):
    ObjectName = state.mem[ObjectAttributes].struct._OBJECT_ATTRIBUTES.ObjectName.resolved
    Attributes = state.mem[ObjectAttributes].struct._OBJECT_ATTRIBUTES.Attributes.resolved
    Buffer = state.mem[ObjectName].struct._UNICODE_STRING.Buffer.resolved
    tmp_state = state.copy()

    # Attrbitues is not OBJ_FORCE_ACCESS_CHECK.
    tmp_state.solver.add(Attributes & 1024 == 0)
    
    # Check if the ObjectName is controllable.
    if tmp_state.satisfiable() and (str(state.mem[ObjectName].struct._UNICODE_STRING.Buffer.resolved) in state.globals['tainted_unicode_strings'] or tainted_buffer(state.memory.load(Buffer, 0x80))):
        ret_addr = hex(state.callstack.ret_addr)
        print_vuln(f'ObjectName in ObjectAttributes controllable', func_name, state, {'ObjectAttributes': {'ObjectName': str(ObjectName), 'ObjectName.Buffer': str(state.memory.load(Buffer, 0x80).reversed), 'Attributes': str(Attributes)}}, {'return address': ret_addr})
    
    return
