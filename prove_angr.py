import argparse
import globals

import angr
import archinfo
import utils
import op_hooks
import kertypes
import hooks
import claripy



def find_ioct_handler(driver_path):
    _, text_instr = utils.disasm_file(driver_path)

    driver_object_addr = 0xAAAA0000  
    registry_path_addr = 0xBBBB0000  
    
    state = globals.proj.factory.call_state(
        globals.proj.entry, 
        driver_object_addr, 
        registry_path_addr, 
        cc=globals.mycc
    )

    target_instr = None
    for x, instr in enumerate(text_instr):
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
    device_object_addr = claripy.BVS('device_object_addr', drv_base_state.arch.bits)


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

    # Set the initial value of the IRP.
    state.mem[globals.irp_addr].IRP.Tail.Overlay.s.u.CurrentStackLocation = globals.irsp_addr
    state.mem[globals.irp_addr].IRP.AssociatedIrp.SystemBuffer = globals.SystemBuffer
    state.mem[globals.irp_addr].IRP.UserBuffer = globals.UserBuffer
    state.mem[globals.irp_addr].IRP.RequestorMode = 1
    state.mem[globals.irsp_addr].IO_STACK_LOCATION.MajorFunction = 14
    state.mem[globals.irsp_addr].IO_STACK_LOCATION.MinorFunction = minor_func

    # Set the initial value of the IO_STACK_LOCATION.
    _params = state.mem[globals.irsp_addr].IO_STACK_LOCATION.Parameters
    _params.DeviceIoControl.OutputBufferLength.val = globals.OutputBufferLength
    _params.DeviceIoControl.InputBufferLength.val = globals.InputBufferLength
    _params.DeviceIoControl.Type3InputBuffer = globals.Type3InputBuffer

    # Add check for custom ioctl codes
    _params.DeviceIoControl.IoControlCode.val = globals.IoControlCode

    globals.simgr = globals.proj.factory.simgr(state)
    globals.simgr.populate('found', [])    
    globals.simgr.use_technique(angr.exploration_techniques.DFS())
    

    # ed = techniques.ExplosionDetector(threshold=10000)
    # globals.simgr.use_technique(ed)

        # Start symbolic execution to hunt vulnerabilities.

    while (len(globals.simgr.active) > 0 or len(globals.simgr.deferred) > 0):# and not ed.state_exploded_bool:
        try:
            # globals.simgr.step(num_inst=1)
            globals.simgr.step()

        except Exception as e:
            # utils.print_error(f'error on state {globals.simgr.active}: {str(e)}')
            globals.simgr.move(from_stash='active', to_stash='_Drop')
        # utils.print_debug(f'simgr: {globals.simgr},\n\tactive: {globals.simgr.active}\n\tdeferred: {globals.simgr.deferred}\n\terrored: {globals.simgr.errored}\n\tdeadneded: {globals.simgr.deadended}')

    # if ed.state_exploded_bool:
    #     # utils.print_error('state explosion')
    #     print('state explosion')
    if globals.simgr.errored:
        for s in globals.simgr.errored:
            # utils.print_error(f'{repr(s)}')
            print(f'{repr(s)}')

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

    hook_dangerous_asm(driver)
    
    # # Hook indirect jump.
    # for indirect_jump in globals.cfg.indirect_jumps:
    #     indirect_jum_ins_addr = globals.cfg.indirect_jumps[indirect_jump].ins_addr
    #     if len(globals.proj.factory.block(indirect_jum_ins_addr).capstone.insns):
    #         op = globals.proj.factory.block(indirect_jum_ins_addr).capstone.insns[0].op_str
    #         if op == 'rax' or op == 'rbx' or op == 'rcx' or op == 'rdx':
    #             utils.print_debug(f'indirect jmp {hex(globals.cfg.indirect_jumps[indirect_jump].ins_addr)}')
    #             globals.proj.hook(globals.cfg.indirect_jumps[indirect_jump].ins_addr, opcodes.indirect_jmp_hook, 0)


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


    analyze_driver(driver)