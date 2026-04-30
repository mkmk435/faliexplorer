import argparse
import globals
import breakpoints

import angr
import archinfo
import utils
import op_hooks
import kertypes
import hooks
import claripy
import logging

def fixup_import_symbols(state):
    globals.star_ps_process_type = fix_object_type_import(state, "PsProcessType", globals.ps_process_type)

def fix_object_type_import(state: angr.SimState, object_type_name: str, object_type_import):    
    if not object_type_import:
        return None
    
    # An "object_type_import" points to a kernel memory containing our kernel-defined *ObjectType, which ioctlance intialize to 0
    ps_object_type = state.memory.load(object_type_import, state.arch.bytes, endness=state.arch.memory_endness)
    if not ps_object_type.concrete:
        utils.print_error(f"Unable to correctly evaluate {object_type_name} import")
        return None

    # We need to store a symbolic value to represent the *ObjectType to recognize it later inside a kernel function hook
    star_ps_object_type = claripy.BVS(f'*{object_type_name}', state.arch.bits)
    state.memory.store(ps_object_type, star_ps_object_type, state.arch.bytes, endness=state.arch.memory_endness, disable_actions=True, inspect=False)
    return star_ps_object_type

def find_ioct_handler(driver_path):
    _, text_instr = utils.disasm_file(driver_path)

    driver_object_addr = utils.next_base_addr()
    registry_path_addr = utils.next_base_addr()
    
    state = globals.proj.factory.call_state(
        globals.proj.entry, 
        driver_object_addr, 
        registry_path_addr, 
        cc=globals.mycc
    )

    state.globals['open_section_handles'] = ()
    state.globals['tainted_unicode_strings'] = ()
    state.globals['ioctl_handler'] = 0
    fixup_import_symbols(state)
    
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

    drv_base_state.globals['open_section_handles'] = ()
    state: angr.SimState = globals.proj.factory.call_state(ioctl_handler_addr, device_object_addr, globals.irp_addr, cc=globals.mycc,
                                                base_state=drv_base_state)
    
    # Simbolizza cr8 che contiene IRQL cosi'da esplorare anche aree che richiedono IRQL maggiore
    cr8 = claripy.BVS('cr8', state.arch.bits)
    state.registers.store('cr8', cr8)

    irp = claripy.BVS('irp_buf', 8 * 0x200)


    # === SYSTEM BUFFER ===
    sysbuf_addr = utils.next_base_addr()
    sysbuf_content = claripy.BVS('SystemBuffer', 8 * 0x200)
    state.memory.store(sysbuf_addr, sysbuf_content, disable_actions=True, inspect=False)
    globals.SystemBuffer = sysbuf_addr

    # === TYPE3 INPUT BUFFER (METHOD_NEITHER) ===
    type3_addr = utils.next_base_addr()
    type3_content = claripy.BVS('Type3InputBuffer', 8 * 0x200)
    state.memory.store(type3_addr, type3_content, disable_actions=True, inspect=False)
    globals.Type3InputBuffer = type3_addr

    # === USER BUFFER ===
    userbuf_addr = utils.next_base_addr()
    userbuf_content = claripy.BVS('UserBuffer', 8 * 0x200)
    state.memory.store(userbuf_addr, userbuf_content, disable_actions=True, inspect=False)
    globals.UserBuffer = userbuf_addr



    # while len(state.inspect._breakpoints['mem_write']) > 0:
    #     state.inspect._breakpoints['mem_write'].pop()
    # while len(state.inspect._breakpoints['call']) > 0:
    #     state.inspect._breakpoints['call'].pop()
    # state.inspect.b('mem_read', when=angr.BP_BEFORE, action=breakpoints.b_mem_read)
    # state.inspect.b('mem_write', when=angr.BP_BEFORE, action=breakpoints.b_mem_write)
    # state.inspect.b('call', when=angr.BP_BEFORE, action=breakpoints.b_call)


    state.memory.store(globals.irp_addr, irp)

    # Crea alcuni campi di IO_STACK_LOCS come BVS
    major_func, minor_func, globals.OutputBufferLength, globals.InputBufferLength, globals.IoControlCode = map(lambda x: claripy.BVS(*x), [
    ("MajorFunction", 8), ("MinorFunction", 8), ('OutputBufferLength', 32), ('InputBufferLength', 32),
    ('IoControlCode', 32)])

    fixup_import_symbols(state)

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
            globals.simgr.step(num_inst=1)
            # globals.simgr.step()

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
    globals.proj.hook_symbol('ZwOpenSection', hooks.HookZwOpenSection(cc=globals.mycc))
    globals.proj.hook_symbol('ObReferenceObjectByHandle', hooks.HookObReferenceObjectByHandle(cc=globals.mycc))
    globals.proj.hook_symbol('RtlInitUnicodeString', hooks.HookRtlInitUnicodeString(cc=globals.mycc))
    globals.proj.hook_symbol('IoCreateDevice', hooks.HookIoCreateDevice(cc=globals.mycc))    
    globals.proj.hook_symbol('HalTranslateBusAddress', hooks.HookHalTranslateBusAddress(cc=globals.mycc))
    globals.proj.hook_symbol('IoCreateSymbolicLink', hooks.HookIoCreateSymbolicLink(cc=globals.mycc))




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

    globals.ps_process_type = utils.resolve_import_symbol_in_object(globals.proj.loader.main_object, "PsProcessType")


    ioctl_handler_addr, base_state = find_ioct_handler(driver)
    print(f'ioctl_handler_addr: {hex(ioctl_handler_addr)}')

    hunting(ioctl_handler_addr, base_state)



if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('path', type=str, help='dir (including subdirectory) or file path to the driver(s) to analyze')
    parser.add_argument('-d', '--debug', default=False, action='store_true', help='print debug info while analyzing (default False)')

    globals.args = parser.parse_args()

    driver = globals.args.path

    print(f"ANALYZING DRIVER: {driver}")
    instrs, text_instr = utils.disasm_file(driver)

    globals.proj = angr.Project(driver)#, auto_load_libs=False)
    logging.getLogger('angr').setLevel(logging.ERROR)

    analyze_driver(driver)