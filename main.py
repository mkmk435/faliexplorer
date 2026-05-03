import argparse
import utils
import globals
import angr
import logging
import archinfo
import apiHooks
import ophooks
import kertypes
import claripy
import memHooks



def hook_dangerous_asm(driver_path):
    total_instr, text_instr = utils.disasm_file(driver_path)

    for instr in text_instr:
        if instr.mnemonic == 'wrmsr':
            utils.print_debug(f'wrmsr at: {instr.address}')
            globals.proj.hook(instr.address, ophooks.wrmsr_hook, instr.size)
        # elif instr.mnemonic == 'rdmsr':
        #     utils.print_debug(f'rdmsr at: {instr.address}')

def find_vulns(driver_path, ioctl_handler_addr, ioctl_handler_state):

    globals.phase = 2
    irp = claripy.BVS('irp_buf', 8 * 0x200)
    device_object_addr = claripy.BVS('device_object_addr', ioctl_handler_state.arch.bits)

    # ioctl_handler_state.globals['open_section_handles'] = ()

    state = globals.proj.factory.call_state(
        ioctl_handler_addr,
        device_object_addr,
        globals.irp_addr,
        cc=globals.cc,
        base_state=ioctl_handler_state
    )
    
    # symbolic cr8 to explore also higher IRQL areas
    cr8 = claripy.BVS('cr8', state.arch.bits)
    state.registers.store('cr8', cr8)


    globals.SystemBuffer = claripy.BVS('SystemBuffer', state.arch.bits)
    globals.Type3InputBuffer = claripy.BVS('Type3InputBuffer', state.arch.bits)
    globals.UserBuffer = claripy.BVS('UserBuffer', state.arch.bits)




    state.inspect.b('mem_read', when=angr.BP_BEFORE, action=memHooks.b_mem_read)
    state.inspect.b('mem_write', when=angr.BP_BEFORE, action=memHooks.b_mem_write)
    # state.inspect.b('call', when=angr.BP_BEFORE, action=breakpoints.b_call)


    state.memory.store(globals.irp_addr, irp)

        # Crea alcuni campi di IO_STACK_LOCS come BVS
    major_func, minor_func, globals.OutputBufferLength, globals.InputBufferLength, globals.IoControlCode = map(lambda x: claripy.BVS(*x), [
    ("MajorFunction", 8), ("MinorFunction", 8), ('OutputBufferLength', 32), ('InputBufferLength', 32),
    ('IoControlCode', 32)])

    # fixup_import_symbols(state)

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
    
    
    while (len(globals.simgr.active) > 0 or len(globals.simgr.deferred) > 0):# and not ed.state_exploded_bool:
        try:
            globals.simgr.step(num_inst=1)
            # globals.simgr.step()

        except Exception as e:
            # utils.print_error(f'error on state {globals.simgr.active}: {str(e)}')
            globals.simgr.move(from_stash='active', to_stash='_Drop')
        # utils.print_debug(f'simgr: {globals.simgr},\n\tactive: {globals.simgr.active}\n\tdeferred: {globals.simgr.deferred}\n\terrored: {globals.simgr.errored}\n\tdeadneded: {globals.simgr.deadended}')


    if globals.simgr.errored:
        for s in globals.simgr.errored:
            # utils.print_error(f'{repr(s)}')
            print(f'{repr(s)}')

def hookDriver(driver_path):

    globals.cfg = globals.proj.analyses.CFGFast()

    hook_dangerous_asm(driver_path)

    #hook di memcpy e memset, non sono importate nel win kernel e sono lentissime
    #necessario per se vengono usate
    utils.find_hook_func()


    globals.proj.hook_symbol('memmove', apiHooks.HookMemcpy(cc=globals.cc))
    globals.proj.hook_symbol('memcpy', apiHooks.HookMemcpy(cc=globals.cc))
    globals.proj.hook_symbol('ZwOpenSection', apiHooks.HookZwOpenSection(cc=globals.cc))
    globals.proj.hook_symbol('RtlInitUnicodeString', apiHooks.HookRtlInitUnicodeString(cc=globals.cc))
    globals.proj.hook_symbol('HalTranslateBusAddress', apiHooks.HookHalTranslateBusAddress(cc=globals.cc))
    globals.proj.hook_symbol('IoStartPacket', apiHooks.HookIoStartPacket(cc=globals.cc))

    globals.proj.hook_symbol('ZwMapViewOfSection', apiHooks.HookZwMapViewOfSection(cc=globals.cc))
    globals.proj.hook_symbol('MmMapIoSpace', apiHooks.HookMmMapIoSpace(cc=globals.cc))
    globals.proj.hook_symbol('MmMapIoSpaceEx', apiHooks.HookMmMapIoSpaceEx(cc=globals.cc))
    globals.proj.hook_symbol('ZwTerminateProcess', apiHooks.HookZwTerminateProcess(cc=globals.cc))

    globals.proj.hook_symbol("ExAllocatePoolWithTag", apiHooks.HookExAllocatePoolWithTag(cc=globals.cc))

    ioctl_handler_addr, ioctl_handler_state = utils.find_ioctl_handler(driver_path)
    print(f"IOCTL handler address: {hex(ioctl_handler_addr)}")

    find_vulns(driver_path, ioctl_handler_addr, ioctl_handler_state)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('path', type=str, help='dir (including subdirectory) or file path to the driver(s) to analyze')
    parser.add_argument('-d', '--debug', default=False, action='store_true', help='print debug info while analyzing (default False)')
    parser.add_argument('-T', '--total_timeout', type=int, default=1200, help='total timeout for the whole symbolic execution (default 1200, 0 to unlimited)')
    parser.add_argument('-t', '--timeout', type=int, default=40, help='timeout for analyze each IoControlCode (default 40, 0 to unlimited)')
    parser.add_argument('-r', '--recursion', default=False, action='store_true', help='do not kill state if detecting recursion (default False)')
    parser.add_argument('-l', '--length', type=int, default=0, help='the limit of number of instructions for technique LengthLimiter (default 0, 0 to unlimited)')
    parser.add_argument('-b', '--bound', type=int, default=0, help='the bound for technique LoopSeer (default 0, 0 to unlimited)')
    
    globals.args = parser.parse_args()

    driver = globals.args.path

    print(f"ANALYZING DRIVER: {driver}")
    instrs, text_instr = utils.disasm_file(driver)

    globals.proj = angr.Project(driver, auto_load_libs=False)

    
    # Customize calling convention for the SimProcs.
    if globals.proj.arch.name == archinfo.ArchX86.name:
        globals.cc = angr.calling_conventions.SimCCStdcall(globals.proj.arch)
    else:
        globals.cc = angr.calling_conventions.SimCCMicrosoftAMD64(globals.proj.arch)

    logging.getLogger('angr').setLevel(logging.ERROR)

    hookDriver(driver)

