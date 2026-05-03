import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64

import angr
import claripy
import globals
import archinfo
import techniques
import memHooks
import apiHooks

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
                    text_list.append(instruction)

    return instruction_list, text_list


def fixup_import_symbols(state):
    globals.star_ps_process_type = fix_object_type_import(state, "PsProcessType", globals.ps_process_type)


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



def find_ioctl_handler(driver_path):
    # calcola il write address dell'ioctl handler
    def b_write_ioctl_handler(state):
            # Store the address of ioctl handler when writing into the memory.
        ioctl_handler_addr = state.solver.eval(state.inspect.mem_write_expr)
        state.globals['ioctl_handler'] = ioctl_handler_addr
        globals.ioctl_handler = ioctl_handler_addr
        #globals.simgr.move(from_stash='deadended', to_stash='_Drop')

    def b_mem_write_DriverStartIo(state):
        # Store the address of DriverStartIo when writing into the memory.
        DriverStartIo_addr = state.solver.eval(state.inspect.mem_write_expr)
        globals.DriverStartIo = int(DriverStartIo_addr)
        globals.basic_info['DriverStartIo'] = hex(globals.DriverStartIo)
        print(f'DriverStartIo: {hex(globals.DriverStartIo)}')


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

    # fixup_import_symbols(state)

    state.inspect.b('mem_write', mem_write_address=driver_object_addr + (0xe0 if globals.proj.arch.name == archinfo.ArchAMD64.name else 0x70), when=angr.BP_AFTER, action=b_write_ioctl_handler)
    state.inspect.b('mem_write', mem_write_address=driver_object_addr + (0x60 if globals.proj.arch.name == archinfo.ArchAMD64.name else 0x30), when=angr.BP_AFTER, action=b_mem_write_DriverStartIo)
    # state.inspect.b('call', when=angr.BP_BEFORE, action=memHooks.b_call)

    globals.simgr = globals.proj.factory.simgr(state)
    globals.simgr.use_technique(angr.exploration_techniques.DFS())

    # globals.simgr.use_technique(angr.exploration_techniques.LoopSeer(cfg=globals.cfg, functions=None, bound=globals.args.bound))
    # globals.simgr.use_technique(angr.exploration_techniques.LocalLoopSeer(bound=globals.args.bound))
    # globals.simgr.use_technique(angr.exploration_techniques.LengthLimiter(globals.args.length))


    ed = techniques.ExplosionDetector(threshold=10000)
    globals.simgr.use_technique(ed)

    def filter_func(s):
        # Return false if ioctl handler not found.
        if not s.globals['ioctl_handler']:
            return False
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

    # Return the ioctl handler address and the state.
    if len(globals.simgr.found):
        success_state = globals.simgr.found[0]
        return globals.ioctl_handler, success_state
    else:
        return globals.ioctl_handler, None

def tainted_buffer(buffer):
    # if len(state.variables) != 1:
    #     return ''

    str_buf = str(buffer)
    for buf in globals.controllable_buffers:
        if buf in str_buf:
            return buf
    return ''

def print_vuln(vuln_type, access_type, state, additional_info, address_info):
    """Print vulnerability information."""
    print("____________________________________________________________")
    print(f"[VULN] {vuln_type} - {access_type}")
    print(f"  State: {state}")
    print(f"IOCTL: {hex(state.solver.eval(globals.IoControlCode))}")
    for key, value in additional_info.items():
        print(f"  {key}: {value}")
    for key, value in address_info.items():
        print(f"  {key}: {value}")
    print("____________________________________________________________")

def print_debug(msg):
    """Print debug information if DEBUG mode is enabled."""
    if getattr(globals, 'DEBUG', False):
        print(f"[DEBUG] {msg}")