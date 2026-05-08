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
from cle.backends.pe.relocation.generic import DllImport
from typing import Optional




vuln_rips = []
past_ioctls = []

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
                retval = globals.mycc.return_val(angr.types.BASIC_TYPES['long int']).get_value(s)
                return s.solver.satisfiable(extra_constraints=[retval == 0])
            else:
                return True

        # Start symbolic execution to find the ioctl handler.
        for i in range(0x100000):
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

# def find_ioctl_handler_wdf(driver_path):
#     print("WDF driver detected, using heuristics to find IOCTL handler")
#     total_instr, text_instr = disasm_file(driver_path)

#     driver_object_addr = next_base_addr()
#     registry_path_addr = next_base_addr()
    
#     state = globals.proj.factory.call_state(
#         globals.proj.entry, 
#         driver_object_addr, 
#         registry_path_addr, 
#         cc=globals.cc
#     )

#     state.globals['open_section_handles'] = ()
#     state.globals['tainted_unicode_strings'] = ()
#     state.globals['ioctl_handler'] = 0
#     fixup_import_symbols(state)
    
#     target_instr = None
#     for x, instr in enumerate(total_instr):
#         if instr.mnemonic == 'mov':
#             # Looking for MajorFunction[14] / IRP_MJ_DEVICE_CONTROL assignment (0xe0 offset)
#             if '[rbx + 0xe0]' in instr.op_str:
#                 target_reg = instr.op_str.split(',')[-1].strip()
#                 if target_reg == 'rax':
#                     print(f"Found at {hex(instr.address)}, register: {target_reg}")
#                     print(f"Instruction: {instr.mnemonic} {instr.op_str}")
#                     target_instr = (instr, target_reg, x)
#                     # break # Good practice to break once found
#             elif '[rdi + 0xe0]' in instr.op_str:
#                 target_reg = instr.op_str.split(',')[-1].strip()
#                 if target_reg == 'rcx':
#                     print(f"Found at {hex(instr.address)}, register: {target_reg}")
#                     print(f"Instruction: {instr.mnemonic} {instr.op_str}")
#                     target_instr = (instr, target_reg, x)
#                     # break # Good practice to break once found
#     if not target_instr:
#         print("Could not find IOCTL handler assignment.")
#         exit(1)

#     globals.simgr = globals.proj.factory.simulation_manager(state)
#     globals.simgr.explore(find=target_instr[0].address)

#     if globals.simgr.found:
#         state = globals.simgr.found[0]
#         print(f"Reached address {hex(target_instr[0].address)}")
        
#         # Safely grab the register value and convert AST to concrete Int
#         reg_value_ast = getattr(state.regs, target_instr[1])
#         addr_final = state.solver.eval(reg_value_ast)
        
#         return addr_final, state

#     else:
#         print("Not reached")
#         # exit(1)

#         return target_instr[0].address, None
def find_ioctl_handler_wdf(driver_path):
    print("WDF/Heuristic driver detected, using heuristics to find IOCTL handler")
    try:
        total_instr, text_instr = disasm_file(driver_path)

        driver_object_addr = next_base_addr()
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
        
        # 1. Determine MajorFunction[IRP_MJ_DEVICE_CONTROL] offset dynamically
        is_64bit = globals.proj.arch.name == angr.archinfo.ArchAMD64.name
        target_offset = '0xe0' if is_64bit else '0x70'
        
        target_instr = None
        
        # 2. Robustly parse instructions for ANY register base
        for x, instr in enumerate(total_instr):
            if instr.mnemonic.startswith('mov'):
                op_str = instr.op_str.lower()
                # Split destination and source operands
                parts = [p.strip() for p in op_str.split(',')]
                
                if len(parts) >= 2:
                    dst_op = parts[0]
                    src_op = parts[-1]
                    
                    # Look for a memory write to the target offset (e.g., [rax + 0xe0])
                    if target_offset in dst_op and '[' in dst_op and ']' in dst_op:
                        # Extract the source register 
                        target_reg = src_op
                        
                        # Ensure the source is a standard register (alphanumeric)
                        if target_reg.isalnum():
                            print(f"Found assignment at {hex(instr.address)}, register: {target_reg}")
                            print(f"Instruction: {instr.mnemonic} {instr.op_str}")
                            target_instr = (instr, target_reg, x)
                            break 
                            
        if not target_instr:
            print("Could not find IOCTL handler assignment via static heuristics.")
            return None, None

        globals.simgr = globals.proj.factory.simulation_manager(state)
        
        # 3. Add exploration techniques from the non-WDF function to prevent hangs
        globals.simgr.use_technique(angr.exploration_techniques.DFS())
        ed = techniques.ExplosionDetector(threshold=10000)
        globals.simgr.use_technique(ed)

        # Explore to the identified instruction address
        globals.simgr.explore(find=target_instr[0].address)

        if globals.simgr.found:
            success_state = globals.simgr.found[0]
            print(f"Reached address {hex(target_instr[0].address)}")
            
            # Safely grab the register value and convert AST to concrete Int
            reg_value_ast = getattr(success_state.regs, target_instr[1])
            addr_final = success_state.solver.eval(reg_value_ast)
            
            return addr_final, success_state

        else:
            print("Target instruction was not reached by symbolic execution.")
            if globals.simgr.errored:
                for s in globals.simgr.errored:
                    print(f'ERROR in state: {repr(s)}')
            
            # Return the statically found address anyway, but no state
            return target_instr[0].address, None

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

def print_vuln(vuln_type, access_type, state, additional_info, address_info):
    rip = state.solver.eval(state.regs.rip)
    ioctl = state.solver.eval(globals.IoControlCode)
    # if ioctl  in past_ioctls:
    #     return
    # past_ioctls.append(ioctl)
    # if rip in vuln_rips:
    #     return
    # vuln_rips.append(rip)
    """Print vulnerability information."""
    print("____________________________________________________________")
    print(f"[VULN] {vuln_type} - {access_type}")
    print(f"  State: {state}")
    print(f"IOCTL: {hex(ioctl)  }")
    print(f"RIP: {hex(rip)}")


    for key, value in additional_info.items():
        print(f"  {key}: {value}")
    for key, value in address_info.items():
        print(f"  {key}: {value}")
    print("____________________________________________________________")

def print_debug(msg):
    """Print debug information if DEBUG mode is enabled."""
    if getattr(globals, 'DEBUG', False):
        print(f"[DEBUG] {msg}")


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