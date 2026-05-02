import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64

import angr
import claripy
import globals



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



def find_ioctl_handler(driver_path):
    _, text_instructions = disasm_file(driver_path)

    driver_object_addr = next_base_addr()
    device_object_addr = next_base_addr()
    registry_path_addr = next_base_addr()
    state = globals.proj.factory.call_state(
        globals.proj.entry,
        driver_object_addr,
        registry_path_addr,
        cc= globals.cc,
    )

    state.globals['open_section_handles'] = ()
    state.globals['tainted_unicode_strings'] = ()
    state.globals['ioctl_handler'] = 0

    target_instr = None
    for x, instr in enumerate(text_instructions):
        if instr.mnemonic == 'mov':
            # Looking for MajorFunction[14] / IRP_MJ_DEVICE_CONTROL assignment (0xe0 offset)
            if 'qword ptr [rbx + 0xe0]' in instr.op_str:
                target_reg = instr.op_str.split(',')[-1].strip()
                print(f"Found at {hex(instr.address)}, register: {target_reg}")
                target_instr = (instr, target_reg, x)
                break # Good practice to break once found

    if not target_instr:
        print("Could not find IOCTL handler assignment.")
        exit(1)

    globals.simgr = globals.proj.factory.simulation_manager(state)
    globals.simgr.explore(find=target_instr[0].address)

    if globals.simgr.found:
        state = globals.simgr.found[0]
        print(f"Reached address {hex(target_instr[0].address)}")
        
        # Safely grab the register value and convert AST to concrete Int
        reg_value_ast = getattr(state.regs, target_instr[1])
        addr_final = state.solver.eval(reg_value_ast)
        
        return addr_final, state

    else:
        print("Not reached")
        exit(1)

# def tainted_buffer(buffer):
#     """Returns True if the buffer AST's variable set intersects with controllable buffer names."""
#     if buffer is None:
#         return False
#     if hasattr(buffer, 'variables'):
#         vars = buffer.variables
#         if isinstance(vars, set):
#             for b in globals.controllable_buffers:
#                 for v in vars:
#                     if b in v:
#                         return True
#         else:
#             buffer_str = str(buffer)
#             for b in globals.controllable_buffers:
#                 if b in buffer_str:
#                     return True
#     return False


def tainted_buffer(state):
    if len(state.variables) != 1:
        return ''

    str_state = str(state)
    for buf in globals.controllable_buffers:
        if buf in str_state:
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