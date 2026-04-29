import argparse
import globals

import angr
import archinfo
import utils
import op_hooks
import kertypes



# find ioctl handler much shorter
def find_ioct_handler(driver_path):
    _, text_instr = utils.disasm_file(driver_path)

    state = globals.proj.factory.entry_state()

    target_instr = None
    for x,instr in enumerate(text_instr):
        if instr.mnemonic == 'mov':
            if 'qword ptr [rbx + 0xe0]' in instr.op_str:
                print(f"Trovata a {hex(instr.address)}, registro: {instr.op_str[-3:]}")
                target_instr = (instr,instr.op_str[-3:],x)

    simgr = globals.proj.factory.simulation_manager(state)
    simgr.explore(find=target_instr[0].address)

    # Controlla se siamo arrivati
    if simgr.found:
        state = simgr.found[0]
        print(f"Raggiunto l'indirizzo {hex(target_instr[0].address)}")
        print("=== Dump registri ===")

        print(eval(f'state.regs.{target_instr[1]}'))

        addr_final = eval(f'state.regs.{target_instr[1]}').args[0]
        return addr_final, base_state

    else:
        print("Non raggiunto")
        exit(1)




def hook_dangerous_asm(driver_path):
    total_instr, text_instr = utils.disasm_file(driver_path)

    for instr in text_instr:
        if instr.mnemonic == 'wrmsr':
            utils.print_debug(f'wrmsr at: {instr.address}')
            globals.proj.hook(instr.address, op_hooks.wrmsr_hook, instr.size)
        # elif instr.mnemonic == 'rdmsr':
        #     utils.print_debug(f'rdmsr at: {instr.address}')

# SEMPLICEMENTE cerca memcpy e memset con delle sig
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
        utils.print_debug(f'memset_hook_address: {hex(memset_hook_address)}')
        globals.proj.hook(memset_hook_address, angr.procedures.SIM_PROCEDURES['libc']['memset'](cc=globals.mycc))
    if memcpy_hook_address:
        utils.print_debug(f'memcpy_hook_address: {hex(memcpy_hook_address)}')
        globals.proj.hook(memcpy_hook_address, hooks.HookMemcpy(cc=globals.mycc))

def hunting(ioctl_handler_addr, drv_base_state):
    irp = claripy.BVS('irp_buf', 8 * 0x200)
    # per 64 bits
    device_object_addr = claripy.BVS('device_object_addr', 64)


    state: angr.SimState = globals.proj.factory.call_state(ioctl_handler_addr, device_object_addr, globals.irp_addr, cc=globals.mycc,
                                                base_state=drv_base_state)
    
    # Simbolizza cr8 che contiene IRQL cosi'da esplorare anche aree che richiedono IRQL maggiore
    cr8 = claripy.BVS('cr8', state.arch.bits)
    state.registers.store('cr8', cr8)

    irp = claripy.BVS('irp_buf', 8 * 0x200)

    globals.SystemBuffer = claripy.BVS('SystemBuffer', state.arch.bits)
    globals.Type3InputBuffer = claripy.BVS('Type3InputBuffer', state.arch.bits)
    globals.UserBuffer = claripy.BVS('UserBuffer', state.arch.bits)

    # Crea alcuni campi di IO_STACK_LOCS come BVS
    major_func, minor_func, globals.OutputBufferLength, globals.InputBufferLength, globals.IoControlCode = map(lambda x: claripy.BVS(*x), [
    ("MajorFunction", 8), ("MinorFunction", 8), ('OutputBufferLength', 32), ('InputBufferLength', 32),
    ('IoControlCode', 32)])

    

def analyze_driver(file_path):
    globals.cfg = globals.proj.analyses.CFGFast()
    
    # Customize calling convention for the SimProcs.
    if globals.proj.arch.name == archinfo.ArchX86.name:
        globals.mycc = angr.calling_conventions.SimCCStdcall(globals.proj.arch)
    else:
        globals.mycc = angr.calling_conventions.SimCCMicrosoftAMD64(globals.proj.arch)

    print("This is the graph:", globals.cfg.model.graph)

    # hooka memcpy e memset
    find_hook_func()


    # solo un hook
    globals.proj.hook_symbol('ZwMapViewOfSection', hooks.HookZwMapViewOfSection(cc=globals.mycc))


    
    # Hook indirect jump.
    for indirect_jump in globals.cfg.indirect_jumps:
        indirect_jum_ins_addr = globals.cfg.indirect_jumps[indirect_jump].ins_addr
        if len(globals.proj.factory.block(indirect_jum_ins_addr).capstone.insns):
            op = globals.proj.factory.block(indirect_jum_ins_addr).capstone.insns[0].op_str
            if op == 'rax' or op == 'rbx' or op == 'rcx' or op == 'rdx':
                utils.print_debug(f'indirect jmp {hex(globals.cfg.indirect_jumps[indirect_jump].ins_addr)}')
                globals.proj.hook(globals.cfg.indirect_jumps[indirect_jump].ins_addr, opcodes.indirect_jmp_hook, 0)


    ioctl_handler_addr, base_state = find_ioct_handler(driver)
    print(f'ioctl_handler_addr: {ioctl_handler_addr}')

    hunting(ioctl_handler_addr, base_state)



if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('path', type=str, help='dir (including subdirectory) or file path to the driver(s) to analyze')
    parser.add_argument('-d', '--debug', default=False, action='store_true', help='print debug info while analyzing (default False)')

    args = parser.parse_args()

    driver = args.path

    print(f"ANALYZING DRIVER: {driver}")
    instrs, text_instr = utils.disasm_file(driver)

    globals.proj = angr.Project(driver, auto_load_libs=False)


    # analyze_driver(driver)