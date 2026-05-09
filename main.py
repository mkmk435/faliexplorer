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
import techniques
import traceback

def hook_dangerous_asm(driver_path):
    total_instr, text_instr = utils.disasm_file(driver_path)


    for instr in text_instr:
        if instr.mnemonic == 'wrmsr':
            utils.print_debug(f'wrmsr at: {instr.address}')
            globals.proj.hook(instr.address, ophooks.wrmsr_hook, instr.size)
        elif instr.mnemonic == 'rdmsr':
            utils.print_debug(f'rdmsr at: {instr.address}')
            globals.proj.hook(instr.address, ophooks.rdmsr_hook, instr.size)

        elif instr.mnemonic == 'out':
            utils.print_debug(f'out at: {instr.address}')
            globals.proj.hook(instr.address, ophooks.out_hook, instr.size)
        elif instr.mnemonic == 'outsb':
            utils.print_debug(f'outsb at: {instr.address}')
            globals.proj.hook(instr.address, ophooks.outs_hook, instr.size)
        elif instr.mnemonic == 'outsw':
            utils.print_debug(f'outsw at: {instr.address}')
            globals.proj.hook(instr.address, ophooks.outs_hook, instr.size)
        elif instr.mnemonic == 'outsd':
            utils.print_debug(f'outsd at: {instr.address}')
            globals.proj.hook(instr.address, ophooks.outs_hook, instr.size)

        elif instr.mnemonic == 'in':
            utils.print_debug(f'in at: {instr.address}')
            globals.proj.hook(instr.address, ophooks.in_hook, instr.size)
        elif instr.mnemonic == 'insb':
            utils.print_debug(f'insb at: {instr.address}')
            globals.proj.hook(instr.address, ophooks.ins_hook, instr.size)
        elif instr.mnemonic == 'insw':
            utils.print_debug(f'insw at: {instr.address}')
            globals.proj.hook(instr.address, ophooks.ins_hook, instr.size)
        elif instr.mnemonic == 'insd':
            utils.print_debug(f'insd at: {instr.address}')
            globals.proj.hook(instr.address, ophooks.ins_hook, instr.size)
        elif instr.mnemonic == 'mov':
            for cr in globals.control_registers:
                operands = [op.strip() for op in instr.op_str.split(',')]
                if operands[0] == cr:
                    globals.proj.hook(instr.address, ophooks.wr_cr_hook, instr.size)
                elif operands[1] == cr:
                    globals.proj.hook(instr.address, ophooks.r_cr_hook, instr.size)

        
def find_vulns(driver_path, ioctl_handler_addr, ioctl_handler_state, specific_ioctl_code=None):

    globals.phase = 2
    irp = claripy.BVS('irp_buf', 8 * 0x200)
    device_object_addr = claripy.BVS('device_object_addr', ioctl_handler_state.arch.bits)
    ioctl_handler_kind = ioctl_handler_state.globals.get('ioctl_handler_kind')
    if globals.driver_framework == 'kmdf/wdf' or ioctl_handler_kind == 'wdm':
        device_object_addr = ioctl_handler_state.globals.get('device_object_addr', device_object_addr)

    major_func, minor_func, globals.OutputBufferLength, globals.InputBufferLength, globals.IoControlCode = map(lambda x: claripy.BVS(*x), [
    ("MajorFunction", 8), ("MinorFunction", 8), ('OutputBufferLength', 32), ('InputBufferLength', 32),
    ('IoControlCode', 32)])

    # ioctl_handler_state.globals['open_section_handles'] = ()

    ioctl_handler_state.globals['tainted_ProbeForRead'] = ()
    ioctl_handler_state.globals['tainted_ProbeForWrite'] = ()
    ioctl_handler_state.globals['tainted_MmIsAddressValid'] = ()
    ioctl_handler_state.globals['tainted_eprocess'] = ()
    ioctl_handler_state.globals['tainted_handles'] = ()
    ioctl_handler_state.globals['tainted_objects'] = ()
    ioctl_handler_state.globals['tainted_process_context_changing'] = ()

    ioctl_handler_state.globals['active_buffers'] = []
    ioctl_handler_state.globals['freed_buffers'] = []
    # ioctl_handler_state.globals['tainted_translated_addresses'] = ()

    def extend_to_arch(value):
        if value.size() >= ioctl_handler_state.arch.bits:
            return value
        return claripy.ZeroExt(ioctl_handler_state.arch.bits - value.size(), value)

    if ioctl_handler_kind == 'wdf_evt_io_device_control':
        wdf_queue = ioctl_handler_state.globals.get(
            'wdf_queue_handle',
            claripy.BVS('wdf_queue_handle', ioctl_handler_state.arch.bits)
        )
        wdf_request = ioctl_handler_state.globals.get('wdf_request_handle', utils.next_base_addr())
        state = globals.proj.factory.call_state(
            ioctl_handler_addr,
            wdf_queue,
            wdf_request,
            extend_to_arch(globals.OutputBufferLength),
            extend_to_arch(globals.InputBufferLength),
            extend_to_arch(globals.IoControlCode),
            cc=globals.cc,
            base_state=ioctl_handler_state
        )
        state.globals['wdf_request_handle'] = wdf_request
    else:
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

    def materialize_indirect_wdf_request_buffer(s):
        if ioctl_handler_kind != 'wdf_evt_io_device_control':
            return

        try:
            request_arg = utils._call_arg(s, 0)
            expected_request = s.globals.get('wdf_request_handle')
            if isinstance(expected_request, int):
                expected_request = claripy.BVV(expected_request, s.arch.bits)
            if expected_request is None or not s.solver.satisfiable(extra_constraints=[request_arg == expected_request]):
                return

            buffer_out = utils._call_arg(s, 2)
            if not utils.is_stack_address(s, buffer_out):
                return

            s.memory.store(
                buffer_out,
                globals.SystemBuffer,
                s.arch.bytes,
                endness=s.arch.memory_endness,
                disable_actions=True,
                inspect=False
            )

            length_out = utils._call_arg(s, 3)
            if not s.solver.is_true(length_out == 0) and utils.is_stack_address(s, length_out):
                s.memory.store(
                    length_out,
                    extend_to_arch(globals.InputBufferLength),
                    s.arch.bytes,
                    endness=s.arch.memory_endness,
                    disable_actions=True,
                    inspect=False
                )
        except Exception:
            return




    state.inspect.b('mem_read', when=angr.BP_BEFORE, action=memHooks.b_mem_read)
    state.inspect.b('mem_write', when=angr.BP_BEFORE, action=memHooks.b_mem_write)
    # state.inspect.b('call', when=angr.BP_BEFORE, action=memHooks.b_call)
    if ioctl_handler_kind == 'wdf_evt_io_device_control':
        state.inspect.b('call', when=angr.BP_BEFORE, action=materialize_indirect_wdf_request_buffer)
        state.inspect.b('call', when=angr.BP_BEFORE, action=memHooks.b_call)
    state.inspect.b('call', when=angr.BP_BEFORE, action=memHooks.inspect_args_hook)
    #state.inspect.b('call', when=angr.BP_BEFORE, action=memHooks.universal_hook)



    state.memory.store(globals.irp_addr, irp)

    utils.fixup_import_symbols(state)

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
    if specific_ioctl_code is not None:
        _params.DeviceIoControl.IoControlCode.val = specific_ioctl_code
        state.add_constraints(globals.IoControlCode == specific_ioctl_code)
    else:
        _params.DeviceIoControl.IoControlCode.val = globals.IoControlCode

    globals.simgr = globals.proj.factory.simgr(state)
    globals.simgr.populate('found', [])    
    globals.simgr.use_technique(angr.exploration_techniques.DFS())

    ed = techniques.ExplosionDetector(threshold=10000)
    globals.simgr.use_technique(ed)

    
    
    while (len(globals.simgr.active) > 0 or len(globals.simgr.deferred) > 0) and not ed.state_exploded_bool:
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
    # globals.cfg = globals.proj.analyses.CFGEmulated(keep_state=True)
    # globals.proj.analyses.CompleteCallingConventions(
    #     recover_variables=True, 
    #     cfg=globals.cfg,
    #     analyze_callsites=True   # <-- helps with custom functions
    # )
    # Run CompleteCallingConventionsAnalysis on all functions to recover prototypes
    # print("Analyzing calling conventions for all functions...")
    # globals.proj.analyses.CompleteCallingConventions(recover_variables=True, cfg=globals.cfg)

    hook_dangerous_asm(driver_path)

    #hook di memcpy e memset, non sono importate nel win kernel e sono lentissime
    #necessario per se vengono usate
    utils.find_hook_func()

    globals.DO_NOTHING = utils.next_base_addr()
    globals.proj.hook(globals.DO_NOTHING, apiHooks.HookDoNothing(cc=globals.cc))

    globals.proj.hook_symbol('memmove', apiHooks.HookMemcpy(cc=globals.cc))
    globals.proj.hook_symbol('memcpy', apiHooks.HookMemcpy(cc=globals.cc))
    globals.proj.hook_symbol('ZwOpenSection', apiHooks.HookZwOpenSection(cc=globals.cc))

    globals.proj.hook_symbol('RtlInitUnicodeString', apiHooks.HookRtlInitUnicodeString(cc=globals.cc))
    globals.proj.hook_symbol('RtlCopyUnicodeString', apiHooks.HookRtlCopyUnicodeString(cc=globals.cc))
    globals.proj.hook_symbol('RtlQueryRegistryValues', apiHooks.HookRtlQueryRegistryValues(cc=globals.cc))

    globals.proj.hook_symbol('HalTranslateBusAddress', apiHooks.HookHalTranslateBusAddress(cc=globals.cc))
    globals.proj.hook_symbol('PsLookupProcessByProcessId', apiHooks.HookPsLookupProcessByProcessId(cc=globals.cc))
    globals.proj.hook_symbol('ObOpenObjectByPointer', apiHooks.HookObOpenObjectByPointer(cc=globals.cc))
    globals.proj.hook_symbol('ObReferenceObjectByHandle', apiHooks.HookObReferenceObjectByHandle(cc=globals.cc))
    globals.proj.hook_symbol('KeStackAttachProcess', apiHooks.HookKeStackAttachProcess(cc=globals.cc))
   
    globals.proj.hook_symbol('ObCloseHandle', apiHooks.HookObCloseHandle(cc=globals.cc))

    globals.proj.hook_symbol('ZwQueryInformationProcess', apiHooks.HookZwQueryInformationProcess(cc=globals.cc))
    globals.proj.hook_symbol('NdisRegisterProtocolDriver', apiHooks.HookNdisRegisterProtocolDriver(cc=globals.cc))

    globals.proj.hook_symbol('ZwQueryValueKey', apiHooks.HookZwQueryValueKey(cc=globals.cc))
    globals.proj.hook_symbol('ZwDeleteValueKey', apiHooks.HookZwDeleteValueKey(cc=globals.cc))
    globals.proj.hook_symbol('ZwOpenKey', apiHooks.HookZwOpenKey(cc=globals.cc))
    globals.proj.hook_symbol('ZwCreateKey', apiHooks.HookZwCreateKey(cc=globals.cc))

    globals.proj.hook_symbol('IoCreateFileSpecifyDeviceObjectHint', apiHooks.HookIoCreateFileSpecifyDeviceObjectHint(cc=globals.cc))
    globals.proj.hook_symbol('IoCreateFileEx', apiHooks.HookIoCreateFileEx(cc=globals.cc))
    globals.proj.hook_symbol('IoCreateFile', apiHooks.HookIoCreateFile(cc=globals.cc))
    globals.proj.hook_symbol('ZwWriteFile', apiHooks.HookZwWriteFile(cc=globals.cc))
    globals.proj.hook_symbol('ZwCreateFile', apiHooks.HookZwCreateFile(cc=globals.cc))
    globals.proj.hook_symbol('ZwOpenFile', apiHooks.HookZwOpenFile(cc=globals.cc))
    globals.proj.hook_symbol('ZwDeleteFile', apiHooks.HookZwDeleteFile(cc=globals.cc))   

    globals.proj.hook_symbol('PsGetVersion', apiHooks.HookPsGetVersion(cc=globals.cc))
    globals.proj.hook_symbol('RtlGetVersion', apiHooks.HookRtlGetVersion(cc=globals.cc))
    globals.proj.hook_symbol('MmIsAddressValid', apiHooks.HookMmIsAddressValid(cc=globals.cc))
    globals.proj.hook_symbol('MmGetSystemRoutineAddress', apiHooks.HookMmGetSystemRoutineAddress(cc=globals.cc))


    globals.proj.hook_symbol('IoCreateSymbolicLink', apiHooks.HookIoCreateSymbolicLink(cc=globals.cc))
    globals.proj.hook_symbol('IoCreateDevice', apiHooks.HookIoCreateDevice(cc=globals.cc))
    globals.proj.hook_symbol('IoStartPacket', apiHooks.HookIoStartPacket(cc=globals.cc))
    globals.proj.hook_symbol('WdfDriverCreate', apiHooks.HookWdfDriverCreate(cc=globals.cc))
    globals.proj.hook_symbol('WdfDeviceCreate', apiHooks.HookWdfDeviceCreate(cc=globals.cc))
    globals.proj.hook_symbol('WdfIoQueueCreate', apiHooks.HookWdfIoQueueCreate(cc=globals.cc))
    globals.proj.hook_symbol('WdfRequestRetrieveInputBuffer', apiHooks.HookWdfRequestRetrieveInputBuffer(cc=globals.cc))
    globals.proj.hook_symbol('WdfRequestRetrieveOutputBuffer', apiHooks.HookWdfRequestRetrieveOutputBuffer(cc=globals.cc))
    globals.proj.hook_symbol('WdfRequestRetrieveUnsafeUserInputBuffer', apiHooks.HookWdfRequestRetrieveUnsafeUserInputBuffer(cc=globals.cc))
    globals.proj.hook_symbol('WdfRequestRetrieveUnsafeUserOutputBuffer', apiHooks.HookWdfRequestRetrieveUnsafeUserOutputBuffer(cc=globals.cc))


    
    globals.proj.hook_symbol('ProbeForRead', apiHooks.HookProbeForRead(cc=globals.cc))
    globals.proj.hook_symbol('ProbeForWrite', apiHooks.HookProbeForWrite(cc=globals.cc))


    globals.proj.hook_symbol('ZwTerminateProcess', apiHooks.HookZwTerminateProcess(cc=globals.cc))

    globals.proj.hook_symbol('ZwMapViewOfSection', apiHooks.HookZwMapViewOfSection(cc=globals.cc))
    globals.proj.hook_symbol('MmMapIoSpace', apiHooks.HookMmMapIoSpace(cc=globals.cc))
    globals.proj.hook_symbol('MmMapIoSpaceEx', apiHooks.HookMmMapIoSpaceEx(cc=globals.cc))

    globals.proj.hook_symbol('ExAllocatePool', apiHooks.HookExAllocatePool(cc=globals.cc))
    globals.proj.hook_symbol("ExAllocatePool2", apiHooks.HookExAllocatePool2(cc=globals.cc))
    globals.proj.hook_symbol("ExAllocatePool3", apiHooks.HookExAllocatePool3(cc=globals.cc))
    globals.proj.hook_symbol("ExAllocatePoolWithTag", apiHooks.HookExAllocatePoolWithTag(cc=globals.cc))

    globals.proj.hook_symbol("ExFreePoolWithTag", apiHooks.HookExFreePoolWithTag(cc=globals.cc))
    globals.proj.hook_symbol("ExFreePool2", apiHooks.HookExFreePool2(cc=globals.cc))
    globals.proj.hook_symbol("ExFreePool", apiHooks.HookExFreePool(cc=globals.cc))


    globals.proj.hook_symbol('IoIs32bitProcess', apiHooks.HookIoIs32bitProcess(cc=globals.cc))
    globals.proj.hook_symbol('Vsnprintf', apiHooks.HookVsnprintf(cc=globals.cc))
    globals.proj.hook_symbol('ExInitializeResourceLite', apiHooks.HookExInitializeResourceLite(cc=globals.cc))
    globals.proj.hook_symbol('ExQueryDepthSList', apiHooks.HookExQueryDepthSList(cc=globals.cc))
    globals.proj.hook_symbol('ExpInterlockedPopEntrySList', apiHooks.HookExpInterlockedPopEntrySList(cc=globals.cc))
    globals.proj.hook_symbol('ExpInterlockedPushEntrySList', apiHooks.HookExpInterlockedPushEntrySList(cc=globals.cc))
    globals.proj.hook_symbol('KeWaitForSingleObject', apiHooks.HookKeWaitForSingleObject(cc=globals.cc))
    globals.proj.hook_symbol('RtlWriteRegistryValue', apiHooks.HookRtlWriteRegistryValue(cc=globals.cc))
    globals.proj.hook_symbol('IoGetDeviceProperty', apiHooks.HookIoGetDeviceProperty(cc=globals.cc))
    globals.proj.hook_symbol('KeReleseMutex', apiHooks.HookKeReleaseMutex(cc=globals.cc))

    globals.ps_process_type = utils.resolve_import_symbol_in_object(globals.proj.loader.main_object, "PsProcessType")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('path', type=str, help='dir (including subdirectory) or file path to the driver(s) to analyze')
    parser.add_argument('-d', '--debug', default=False, action='store_true', help='print debug info while analyzing (default False)')
    parser.add_argument('-T', '--total_timeout', type=int, default=1200, help='total timeout for the whole symbolic execution (default 1200, 0 to unlimited)')
    parser.add_argument('-t', '--timeout', type=int, default=40, help='timeout for analyze each IoControlCode (default 40, 0 to unlimited)')
    parser.add_argument('-r', '--recursion', default=False, action='store_true', help='do not kill state if detecting recursion (default False)')
    parser.add_argument('-l', '--length', type=int, default=0, help='the limit of number of instructions for technique LengthLimiter (default 0, 0 to unlimited)')
    parser.add_argument('-b', '--bound', type=int, default=0, help='the bound for technique LoopSeer (default 0, 0 to unlimited)')
    parser.add_argument('-i', '--ioctlcode', nargs='*', default=[], help='analyze specified IoControlCode(s) (e.g. 22201c 222020 222024). If not specified, all will be analyzed')
    parser.add_argument('-c', '--complete', default=False, action='store_true', help='only report vulnerabilities with complete execution paths to STATUS_SUCCESS (default False)')
    parser.add_argument('-a', '--address', type=str, default=None, help='manually specify the address of the IOCTL handler (in hex, e.g. 0x12345678). If not specified, it will be automatically detected by traversing DriverEntry')
    globals.args = parser.parse_args()

    driver = globals.args.path

    print(f"ANALYZING DRIVER: {driver}")
    utils.set_current_driver(driver)
    globals.driver_framework = utils.detect_driver_framework(driver)
    print(f"Driver framework: {globals.driver_framework}")
    
    globals.proj = angr.Project(driver, auto_load_libs=False,     main_opts={'os': 'windows'})
    instrs, text_instr = utils.disasm_file(driver)

    entry = globals.proj.entry
    print(f"Driver entry point: {hex(entry)}")

    
    # Customize calling convention for the SimProcs.
    if globals.proj.arch.name == archinfo.ArchX86.name:
        globals.cc = angr.calling_conventions.SimCCStdcall(globals.proj.arch)
    else:
        globals.cc = angr.calling_conventions.SimCCMicrosoftAMD64(globals.proj.arch)

    logging.getLogger('angr').setLevel(logging.ERROR)

    hookDriver(driver)

    # Get IOCTL handler
            # Find and return the address of ioctl handler by traversing DriverEntry and monitorirng ioctl handler.
    if globals.args.address:
        ioctl_handler, ioctl_handler_state = int(globals.args.address, 16), None
    else:
        ioctl_handler, ioctl_handler_state = utils.find_ioctl_handler(driver)
        if not ioctl_handler_state:

            ioctl_handler, ioctl_handler_state = utils.find_ioctl_handler_wdf2(driver)
    if not ioctl_handler:
        print("ERROR: unable to find IOCTL handler")
        raise SystemExit(1)
    print(f"IOCTL handler address: {hex(ioctl_handler)}")
    if not ioctl_handler_state:
        # utils.print_info(f'Use blank state to hunt vulnerabilities.')
        print(f'Unable to recover a usable state for the IOCTL handler, using a blank state to hunt vulnerabilities (results may be inaccurate).')
        ioctl_handler_state = globals.proj.factory.blank_state()


    # if not ioctl_handler_addr or ioctl_handler_state is None:
    #     print("ERROR: unable to recover a usable IOCTL handler state; aborting vulnerability analysis.")
    #     raise SystemExit(1)

    # Handle IOCTL codes
    if globals.args.ioctlcode:
        # If specific IOCTL codes are provided, analyze each one
        print(f"Analyzing {len(globals.args.ioctlcode)} specified IoControlCode(s)...")
        for ioctl_code_str in globals.args.ioctlcode:
            try:
                ioctl_code_int = int(ioctl_code_str, 16)
                print(f"\n{'='*60}")
                print(f"Analyzing IoControlCode: {hex(ioctl_code_int)} ({ioctl_code_str})")
                print(f"{'='*60}")
                find_vulns(driver, ioctl_handler, ioctl_handler_state, specific_ioctl_code=ioctl_code_int)
            except ValueError:
                print(f"Error: Invalid hex value for IoControlCode: {ioctl_code_str}")
    else:
        # If no specific IOCTL codes, analyze all
        print("Analyzing all IoControlCodes...")
        find_vulns(driver, ioctl_handler, ioctl_handler_state)
