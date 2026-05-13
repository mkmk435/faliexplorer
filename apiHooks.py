import angr
import claripy
import utils
import globals



# NTSTATUS IoCreateSymbolicLink(
#   [in] PUNICODE_STRING SymbolicLinkName,
#   [in] PUNICODE_STRING DeviceName
# );
# printa e basta il symbolic link name e il device name
class HookIoCreateSymbolicLink(angr.SimProcedure):
    def run(self, SymbolicLinkName, DeviceName):
        # Retrieve the symbolic link name.
        device_name_str = utils.read_buffer_from_unicode_string(self.state, DeviceName)
        if (device_name_str == "") or (device_name_str is None):
            return 0
        
        symbolic_link_str = utils.read_buffer_from_unicode_string(self.state, SymbolicLinkName)
        if (symbolic_link_str == "") and (symbolic_link_str == None):
            return 0
        
        print(f'Symbolic link \"{symbolic_link_str}\" to \"{device_name_str}\"')

        if "SymbolicLink" not in globals.basic_info:
            globals.basic_info["SymbolicLink"] = []

        if(symbolic_link_str not in globals.basic_info["SymbolicLink"]):
            globals.basic_info["SymbolicLink"].append(symbolic_link_str)
        return 0    


# alloca device obj in indirizzo, e crea un device object simbolico che mettera' a quell' indirizzo, poi filla alcuni campi
#
class HookIoCreateDevice(angr.SimProcedure):
    def run(self, DriverObject, DeviceExtensionSize, DeviceName, DeviceType, DeviceCharacteristics, Exclusive, DeviceObject):
        # Initialize device object.
        devobjaddr = utils.next_base_addr()
        self.state.globals['device_object_addr'] = devobjaddr
        device_object = claripy.BVS('device_object', 8 * 0x400)
        self.state.memory.store(devobjaddr, device_object, 0x400, disable_actions=True, inspect=False)
        self.state.mem[devobjaddr].DEVICE_OBJECT.Flags = 0
        self.state.mem[DeviceObject].PDEVICE_OBJECT = devobjaddr

        # Initialize device extension.
        new_device_extension_addr = utils.next_base_addr()
        size = self.state.solver.min(DeviceExtensionSize)
        device_extension = claripy.BVV(0, 8 * size)
        self.state.memory.store(new_device_extension_addr, device_extension, size, disable_actions=True, inspect=False)
        self.state.mem[devobjaddr].DEVICE_OBJECT.DeviceExtension = new_device_extension_addr

        # Retrieve the device name.
        device_name_str = utils.read_buffer_from_unicode_string(self.state, DeviceName)
        if (device_name_str == "") or (device_name_str == None):
            return 0
        
        # utils.print_info(f'device name: {device_name_str}')
        if "DeviceName" not in globals.basic_info:
            globals.basic_info["DeviceName"] = []
        
        if(device_name_str not in globals.basic_info["DeviceName"]):
            globals.basic_info["DeviceName"].append(device_name_str)
        return 0


class HookWdfDriverCreate(angr.SimProcedure):
    def run(self, DriverObject, RegistryPath, DriverAttributes, DriverConfig, Driver):
        if not self.state.solver.is_true(Driver == 0):
            driver_handle = utils.next_base_addr()
            self.state.memory.store(
                Driver,
                claripy.BVV(driver_handle, self.state.arch.bits),
                self.state.arch.bytes,
                endness=self.state.arch.memory_endness,
                disable_actions=True,
                inspect=False
            )
            self.state.globals['wdf_driver_handle'] = driver_handle
        return 0


class HookWdfDeviceCreate(angr.SimProcedure):
    def run(self, DeviceInit, DeviceAttributes, Device):
        device_handle = utils.next_base_addr()
        self.state.memory.store(
            device_handle,
            claripy.BVS('wdf_device', 0x400 * 8),
            0x400,
            disable_actions=True,
            inspect=False
        )

        if not self.state.solver.is_true(Device == 0):
            self.state.memory.store(
                Device,
                claripy.BVV(device_handle, self.state.arch.bits),
                self.state.arch.bytes,
                endness=self.state.arch.memory_endness,
                disable_actions=True,
                inspect=False
            )

        self.state.globals['wdf_device_handle'] = device_handle
        return 0


class HookWdfIoQueueCreate(angr.SimProcedure):
    def run(self, Device, Config, QueueAttributes, Queue):
        queue_handle = utils.next_base_addr()
        self.state.memory.store(
            queue_handle,
            claripy.BVS('wdf_queue', 0x200 * 8),
            0x200,
            disable_actions=True,
            inspect=False
        )

        if not self.state.solver.is_true(Queue == 0):
            self.state.memory.store(
                Queue,
                claripy.BVV(queue_handle, self.state.arch.bits),
                self.state.arch.bytes,
                endness=self.state.arch.memory_endness,
                disable_actions=True,
                inspect=False
            )

        self.state.globals['wdf_queue_handle'] = queue_handle
        return 0

# 
def _store_optional_pointer(state, dst, value, size=None):
    if value is None:
        return

    if state.solver.is_true(dst == 0):
        return

    if size is None:
        size = state.arch.bytes

    if isinstance(value, int):
        value = claripy.BVV(value, state.arch.bits)

    if value.size() < state.arch.bits:
        value = claripy.ZeroExt(state.arch.bits - value.size(), value)

    state.memory.store(
        dst,
        value,
        size,
        endness=state.arch.memory_endness,
        disable_actions=True,
        inspect=False
    )


# Semplice helper per scrivere 0 in IoStatusBlock 
def _write_success_io_status_block(state, IoStatusBlock, information=0):
    if state.solver.is_true(IoStatusBlock == 0):
        return

    if isinstance(information, int):
        information = claripy.BVV(information, state.arch.bits)
    elif information.size() < state.arch.bits:
        information = claripy.ZeroExt(state.arch.bits - information.size(), information)

    try:
        isb = state.mem[IoStatusBlock].struct._IO_STATUS_BLOCK
        isb.u.Status = 0
        isb.Information = information
    except Exception:
        return


def _analyze_object_attributes(func_name, state, ObjectAttributes):
    try:
        utils.analyze_ObjectAttributes(func_name, state, ObjectAttributes)
    except Exception:
        return


def _read_object_attributes_info(state, ObjectAttributes):
    info = {
        'object_name': None,
        'object_name_ptr': None,
        'object_name_buffer': None,
        'attributes': None,
        'controlled': False,
    }

    if state.solver.is_true(ObjectAttributes == 0):
        return info

    try:
        object_name_ptr = state.mem[ObjectAttributes].struct._OBJECT_ATTRIBUTES.ObjectName.resolved
        attributes = state.mem[ObjectAttributes].struct._OBJECT_ATTRIBUTES.Attributes.resolved
        buffer = state.mem[object_name_ptr].struct._UNICODE_STRING.Buffer.resolved
    except Exception:
        return info

    info['object_name_ptr'] = object_name_ptr
    info['object_name_buffer'] = buffer
    info['attributes'] = attributes

    try:
        info['object_name'] = state.mem[object_name_ptr].struct._UNICODE_STRING.Buffer.deref.wstring.concrete
    except Exception:
        info['object_name'] = str(buffer)

    tmp_state = state.copy()
    try:
        tmp_state.solver.add(attributes & 1024 == 0)
        force_access_check_missing = tmp_state.satisfiable()
    except Exception:
        force_access_check_missing = False

    tainted_unicode_strings = state.globals.get('tainted_unicode_strings', ())
    try:
        controlled_buffer = utils.tainted_buffer(state.memory.load(buffer, 0x80, disable_actions=True, inspect=False))
    except Exception:
        controlled_buffer = ''

    info['controlled'] = (
        force_access_check_missing and
        (str(buffer) in tainted_unicode_strings or bool(controlled_buffer))
    )
    return info


# semplice helper per aggiungere info agli handle aperti
def _track_file_handle(state, handle, object_info, DesiredAccess=None, CreateDisposition=None, CreateOptions=None):
    state.globals['open_file_handles'] += ((
        handle,
        object_info.get('object_name'),
        DesiredAccess,
        CreateDisposition,
        CreateOptions,
        object_info.get('controlled', False),
    ),)


# semplice check per vedere se un file handle e' controllabile
def _lookup_file_handle(state, FileHandle):
    for handle_info in state.globals.get('open_file_handles', ()):
        handle = handle_info[0]
        if str(handle) == str(FileHandle):
            return handle_info
    return None


# helper per controllare se DesiredAccess di un file handle contiene permessi di scrittura,
def _file_access_may_write(state, DesiredAccess):
    if DesiredAccess is None:
        return True

    file_write_mask = 0x10000000 | 0x40000000 | 0x2 | 0x4
    try:
        tmp_state = state.copy()
        tmp_state.solver.add((DesiredAccess & file_write_mask) != 0)
        return tmp_state.satisfiable()
    except Exception:
        return True


class HookWdfRequestRetrieveInputBuffer(angr.SimProcedure):
    def run(self, Request, MinimumRequiredLength, Buffer, Length):
        _store_optional_pointer(self.state, Buffer, globals.SystemBuffer)
        _store_optional_pointer(self.state, Length, globals.InputBufferLength)
        return 0


class HookWdfRequestRetrieveOutputBuffer(angr.SimProcedure):
    def run(self, Request, MinimumRequiredLength, Buffer, Length):
        _store_optional_pointer(self.state, Buffer, globals.SystemBuffer)
        _store_optional_pointer(self.state, Length, globals.OutputBufferLength)
        return 0


class HookWdfRequestRetrieveUnsafeUserInputBuffer(angr.SimProcedure):
    def run(self, Request, MinimumRequiredLength, InputBuffer, Length):
        _store_optional_pointer(self.state, InputBuffer, globals.Type3InputBuffer)
        _store_optional_pointer(self.state, Length, globals.InputBufferLength)
        return 0


class HookWdfRequestRetrieveUnsafeUserOutputBuffer(angr.SimProcedure):
    def run(self, Request, MinimumRequiredLength, OutputBuffer, Length):
        _store_optional_pointer(self.state, OutputBuffer, globals.UserBuffer)
        _store_optional_pointer(self.state, Length, globals.OutputBufferLength)
        return 0

# Restituisce EPROCESS tado un pid
# NTSTATUS PsLookupProcessByProcessId(
#   [in]  HANDLE    ProcessId,
#   [out] PEPROCESS *Process
# );
# Semplice hook per vedere se posso controllare il ProcessID, e quindi fillo l'eprocess con un valore simbolico
class HookPsLookupProcessByProcessId(angr.SimProcedure):
    def run(self, ProcessId, Process):
        if utils.tainted_buffer(ProcessId):
            utils.print_vuln('lookup process', 'PsLookupProcessByProcessId - ProcessId tainted', self.state, {'ProcessId': str(ProcessId), 'Process': str(Process)}, {'return address': hex(self.state.callstack.ret_addr)})
        ret_addr = hex(self.state.callstack.ret_addr)
        eprocess_bvs = claripy.BVS(f'PsLookupProcessByProcessId_{ret_addr}', self.state.arch.bits)
        self.state.memory.store(Process, eprocess_bvs, self.state.arch.bytes, endness=self.state.arch.memory_endness, disable_actions=True, inspect=False)
        self.state.globals['tainted_eprocess'] += (str(eprocess_bvs), )

        return 0
    
class HookZwOpenProcess(angr.SimProcedure):
    def run(self, ProcessHandle, DesiredAccess, ObjectAttributes, ClientId):
        if globals.phase == 2:
            # Resolve ClientId and Attrbutes of ObjectAttributes.
            cid = self.state.mem[ClientId].struct._CLIENT_ID.resolved
            Attributes = self.state.mem[ObjectAttributes].struct._OBJECT_ATTRIBUTES.Attributes.resolved

            # SImbolizzo hanle e lo metto in memoria a ProcessHandle
            handle = claripy.BVS(f"ZwOpenProcess_{hex(self.state.callstack.ret_addr)}", self.state.arch.bits)
            self.state.memory.store(ProcessHandle, handle, self.state.arch.bytes, endness=self.state.arch.memory_endness, disable_actions=True, inspect=False)

            # Attrbitues is not OBJ_FORCE_ACCESS_CHECK.
            tmp_state = self.state.copy()
            tmp_state.solver.add(Attributes & 1024 == 0)

            # Check se controlliamo il PID.
            if tmp_state.satisfiable() and (utils.tainted_buffer(ClientId) or utils.tainted_buffer(cid.UniqueProcess)):
                ret_addr = hex(self.state.callstack.ret_addr)
                self.state.globals['tainted_handles'] += (str(handle), )
                utils.print_vuln('controllable process handle', 'ZwOpenProcess - ClientId controllable', self.state, {'ClientId': str(ClientId), 'ClientId.UniqueProcess': str(cid.UniqueProcess)}, {'return address': ret_addr})
        
        return 0



# NTSYSAPI NTSTATUS ZwOpenSection(
#   [out] PHANDLE            SectionHandle,   (ptr)
#   [in]  ACCESS_MASK        DesiredAccess,
#   [in]  POBJECT_ATTRIBUTES ObjectAttributes (ptr)
# );
# Praticamente crea un Handle come variabile simbolica
class HookZwOpenSection(angr.SimProcedure):
    def run(self, SectionHandle, DesiredAccess, ObjectAttributes):
        # print("Dentro ZwOpenSection Function hook")
        ret_addr = hex(self.state.callstack.ret_addr)

        # crea handle come variabile simbolica e salvalo in memoria a SectionHandle
        handle = claripy.BVS(f'ZwOpenSection_{ret_addr}', self.state.arch.bits)
        self.state.memory.store(SectionHandle, handle, self.state.arch.bytes, endness=self.state.arch.memory_endness, disable_actions=True, inspect=False)

        # Get the object name.
        object_name_struct = self.state.mem[ObjectAttributes].OBJECT_ATTRIBUTES.ObjectName.deref
        try:
            object_name = object_name_struct.Buffer.deref.wstring.concrete
        except:
            return 0

        # aggiungi agli handles aperti la handle e il nome dell'oggetto
        self.state.globals['open_section_handles'] += ((handle, object_name),)
        return 0

# hook che controlla se posso mappare memoria fisica in modo arbitrario/semi arbitrario
class HookZwMapViewOfSection(angr.SimProcedure):
    def run(self, SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, Win32Protect):
        # if globals.phase == 2:
        # print("Dentro ZwMapViewOfFunction hook")
        # print("Open section handles: ", self.state.globals['open_section_handles'])

# controllo se handle e' simbolico (ereditato da ZwOpenSection) e se ProcessHandle, BaseAddress, CommitSize, ViewSize sono simbolici (controllati dal system buufer)
        if SectionHandle.symbolic and (ProcessHandle.symbolic or self.state.solver.eval(ProcessHandle == -1) or BaseAddress.symbolic or (CommitSize.symbolic and ViewSize.symbolic)):
            ret_addr = hex(self.state.callstack.ret_addr)
            # Se handle ereditato da ZwOpenSection, allora e' controllabile
            if any('ZwOpenSection' not in v for v in SectionHandle.variables):
                utils.print_vuln('map physical memory', 'ZwMapViewOfSection - SectionHandle controllable', self.state, {'SectionHandle': str(SectionHandle), 'ProcessHandle': str(ProcessHandle), 'BaseAddress': str(BaseAddress), 'CommitSize': str(CommitSize), 'ViewSize': str(ViewSize)}, {'return address': ret_addr})
            # altrimento controllo se handle e' memoria fisica o sconosciuto
            else:
                handles = dict(self.state.globals['open_section_handles'])
                if SectionHandle not in handles:
                    utils.print_vuln('map physical memory', 'ZwMapViewOfSection - unknown handle', self.state, {'SectionHandle': str(SectionHandle), 'ProcessHandle': str(ProcessHandle), 'BaseAddress': str(BaseAddress), 'CommitSize': str(CommitSize), 'ViewSize': str(ViewSize)}, {'return address': ret_addr})
                elif handles[SectionHandle] == '\\Device\\PhysicalMemory':
                    utils.print_vuln('map physical memory', 'ZwMapViewOfSection - map \\Device\\PhysicalMemory', self.state, {'SectionHandle': str(SectionHandle), 'ProcessHandle': str(ProcessHandle), 'BaseAddress': str(BaseAddress), 'CommitSize': str(CommitSize), 'ViewSize': str(ViewSize)}, {'return address': ret_addr})
        return 0


# PVOID MmMapIoSpace(
#   [in] PHYSICAL_ADDRESS    PhysicalAddress,
#   [in] SIZE_T              NumberOfBytes,
#   [in] MEMORY_CACHING_TYPE CacheType
# );
# Semplice hook per vedere se posso controllare indirizzo fisico da mapparmi o il numero di bytes da mappare, o entrambi
class HookMmMapIoSpace(angr.SimProcedure):
    def run(self, PhysicalAddress, NumberOfBytes, CacheType):
        # Controllo se i parametri di MmMapIoSpace sono controllabili uno per uno
        if utils.tainted_buffer(PhysicalAddress) and utils.tainted_buffer(NumberOfBytes):
            utils.print_vuln('map physical memory', 'MmMapIoSpace - PhysicalAddress and NumberOfBytes controllable', self.state, {'PhysicalAddress': str(PhysicalAddress), 'NumberOfBytes': str(NumberOfBytes), 'CacheType': str(CacheType)}, {'return address': hex(self.state.callstack.ret_addr)})
        elif utils.tainted_buffer(PhysicalAddress):
            utils.print_vuln('map physical memory', 'MmMapIoSpace - PhysicalAddress controllable', self.state, {'PhysicalAddress': str(PhysicalAddress), 'NumberOfBytes': str(NumberOfBytes), 'CacheType': str(CacheType)}, {'return address': hex(self.state.callstack.ret_addr)})
        elif utils.tainted_buffer(NumberOfBytes):
            utils.print_vuln('map physical memory', 'MmMapIoSpace - NumberOfBytes controllable', self.state, {'PhysicalAddress': str(PhysicalAddress), 'NumberOfBytes': str(NumberOfBytes), 'CacheType': str(CacheType)}, {'return address': hex(self.state.callstack.ret_addr)})
        return 0



# PVOID MmMapIoSpaceEx(
#   [in] PHYSICAL_ADDRESS PhysicalAddress,
#   [in] SIZE_T           NumberOfBytes,
#   [in] ULONG            Protect
# );
class HookMmMapIoSpaceEx(angr.SimProcedure):
    def run(self, PhysicalAddress, NumberOfBytes, Protect):
        # Controllo se i parametri di MmMapIoSpaceEx sono controllabili uno per uno
        if utils.tainted_buffer(PhysicalAddress) and utils.tainted_buffer(NumberOfBytes):
            utils.print_vuln('map physical memory', 'MmMapIoSpaceEx - PhysicalAddress and NumberOfBytes controllable', self.state, {'PhysicalAddress': str(PhysicalAddress), 'NumberOfBytes': str(NumberOfBytes), 'Protect': str(Protect)})
        elif utils.tainted_buffer(PhysicalAddress):
            utils.print_vuln('map physical memory', 'MmMapIoSpaceEx - PhysicalAddress controllable', self.state, {'PhysicalAddress': str(PhysicalAddress), 'NumberOfBytes': str(NumberOfBytes), 'Protect': str(Protect)})
        elif utils.tainted_buffer(NumberOfBytes):
            utils.print_vuln('map physical memory', 'MmMapIoSpaceEx - NumberOfBytes controllable', self.state, {'PhysicalAddress': str(PhysicalAddress), 'NumberOfBytes': str(NumberOfBytes), 'Protect': str(Protect)})

        return 0
    

            

# NTSTATUS ObOpenObjectByPointer(
#   [in]           PVOID           Object,
#   [in]           ULONG           HandleAttributes,
#   [in, optional] PACCESS_STATE   PassedAccessState,
#   [in]           ACCESS_MASK     DesiredAccess,
#   [in, optional] POBJECT_TYPE    ObjectType,
#   [in]           KPROCESSOR_MODE AccessMode,
#   [out]          PHANDLE         Handle
# );
# controlla se oggetto e' stato simbolizzato e tainted, e simbolizza handle per propagarlo
class HookObOpenObjectByPointer(angr.SimProcedure):
    def run(self, Object, HandleAttributes, PassedAccessState, DesiredAccess, ObjectType, AccessMode, Handle):
        if globals.phase == 2:

            ret_addr = hex(self.state.callstack.ret_addr)
            handle_bvs = claripy.BVS(f'ObOpenObjectByPointer_{ret_addr}', self.state.arch.bits)
            self.state.memory.store(Handle, handle_bvs, self.state.arch.bytes, endness=self.state.arch.memory_endness, disable_actions=True, inspect=False)
            
            # HandleAttributes is not OBJ_FORCE_ACCESS_CHECK.
            tmp_state = self.state.copy()
            tmp_state.solver.add(HandleAttributes & 1024 == 0)
            if tmp_state.satisfiable() and (utils.tainted_buffer(Object) or (str(Object) in self.state.globals['tainted_eprocess'])):
                utils.print_vuln('open object', 'ObOpenObjectByPointer - Object controllable', self.state, {'Object': str(Object), 'HandleAttributes': str(HandleAttributes), 'PassedAccessState': str(PassedAccessState), 'DesiredAccess': str(DesiredAccess), 'ObjectType': str(ObjectType), 'AccessMode': str(AccessMode), 'Handle': str(Handle)}, {'return address': hex(self.state.callstack.ret_addr)})
                self.state.globals['tainted_handles'] += (str(handle_bvs), )
        return 0

# NTSYSAPI NTSTATUS ZwTerminateProcess(
#   [in, optional] HANDLE   ProcessHandle,
#   [in]           NTSTATUS ExitStatus
# );
class HookZwTerminateProcess(angr.SimProcedure):
    def run(self, ProcessHandle, ExitStatus):
        # Controllo se il processHandle di ZwTerminateProcess e' controllabile
        if str(ProcessHandle) in self.state.globals['tainted_handles']:
            utils.print_vuln('terminate process', 'ZwTerminateProcess - ProcessHandle controllable', self.state, {'ProcessHandle': str(ProcessHandle), 'ExitStatus': str(ExitStatus)}, {'return address': hex(self.state.callstack.ret_addr)})


# Alloca dest str e ci copia la source String.
# Se la sourse string e' tainted e simbolica, la aggiunge alla lista di stringhe tainted
# altrimenti semplicemente la copia
class HookRtlInitUnicodeString(angr.SimProcedure):
    # input 2 puntatori, dest e src
    def run(self, DestinationString, SourceString):
        # print("Dentro Hook RtlInitUnicodeString")
        # stora in memoria la stringa SourceString

        ret_addr = hex(self.state.callstack.ret_addr)

        # prova a vedere se e' simbolico e tainted, altrimenti crea una stringa simbolica
        try:
            if SourceString.symbolic and utils.tainted_buffer(SourceString):
                print("SourceString is symbolic and tainted")
                raise
            string_orig = self.state.mem[SourceString].wstring.resolved
        except:
            string_orig = claripy.Concat(claripy.BVS(f"RtlInitUnicodeString_{ret_addr}", 8 * 10), claripy.BVV(0, 16))

        # inizializza la dest String, alloca in indirizzo nuovo una stringa unicode
        byte_length = string_orig.length // 8
        new_buffer = utils.next_base_addr()
        # print(f'RtlInitUnicodeString - initialize unicode string at {hex(new_buffer)} with length {byte_length} bytes')

        # Scrivo nel buffer la stringa che ho letto prima (o che ho creato come BVS)
        self.state.memory.store(new_buffer, string_orig, byte_length, disable_actions=True, inspect=False)
        
        unistr = self.state.mem[DestinationString].struct._UNICODE_STRING
        # mette a indirizzo dest la stringa unicode, o meglio un BVV di 16 bit a 0 per ora
        self.state.memory.store(DestinationString, claripy.BVV(0, unistr._type.size), unistr._type.size//8, disable_actions=True, inspect=False)

        unistr.Length = byte_length
        unistr.MaximumLength = byte_length
        unistr.Buffer = new_buffer

        # check se la source string e' tainted e simbolica
        if (not SourceString.symbolic and utils.tainted_buffer(self.state.memory.load(SourceString, 0x10, disable_actions=True, inspect=False))) or utils.tainted_buffer(SourceString) or str(SourceString) in self.state.globals['tainted_unicode_strings']:
            self.state.globals['tainted_unicode_strings'] += (str(unistr.Buffer.resolved), )

        return 0
    
# Semplice hook, che alla fine chiama memcpy della libc, ma prima estrae le stringhe 
class HookRtlCopyUnicodeString(angr.SimProcedure):
    def run(self, DestinationString, SourceString):
        # Restrict the length of the unicode string.
        src_unistr = self.state.mem[SourceString].struct._UNICODE_STRING
        src_len = src_unistr.Length
        conc_src_len = self.state.solver.min(src_len.resolved)
        self.state.solver.add(src_len.resolved == conc_src_len)

        dst_unistr = self.state.mem[DestinationString].struct._UNICODE_STRING
        dst_maxi_len = src_unistr.MaximumLength
        conc_dst_max_len = self.state.solver.min(dst_maxi_len.resolved)
        self.state.solver.add(dst_maxi_len.resolved == conc_dst_max_len)

        # Copy the unicode string.
        memcpy = angr.procedures.SIM_PROCEDURES['libc']['memcpy']
        self.inline_call(memcpy, dst_unistr.Buffer.resolved, src_unistr.Buffer.resolved, min(conc_src_len, conc_dst_max_len))

        # Store the unicode string if it is tainted.
        if utils.tainted_buffer(SourceString) or str(SourceString) in self.state.globals['tainted_unicode_strings']:
            self.state.globals['tainted_unicode_strings'] += (str(dst_unistr.Buffer.resolved), )

        return 0

# Scrivi in translated address il valore di BusNumber + BusAddress 
# Serve perche' per 'propagare' il valore di BusNumber e BusAddress al di fuori della funzione, 
# Es. serve per la funzione MmMapIoSpace per controllare se il buffer e' controllabile
class HookHalTranslateBusAddress(angr.SimProcedure):
    def run(self, InterfaceType, BusNumber, BusAddress, AddressSpace, TranslatedAddress):
        self.state.memory.store(TranslatedAddress, BusNumber + BusAddress, self.state.arch.bytes, endness=self.state.arch.memory_endness, disable_actions=True, inspect=False)
        return 1


class HookIoStartPacket(angr.SimProcedure):
    # Call DriverStartIo when IoStartPacket is called.
    def run(self, DeviceObject, Irp, Key, CancelFunction):
        if globals.DriverStartIo:
            new_state = self.state.project.factory.call_state(addr=globals.DriverStartIo, args=(DeviceObject, Irp), base_state=self.state)
            globals.simgr.deferred.append(new_state)


class HookExAllocatePool(angr.SimProcedure):
    # Trace the allocated buffer by ExAllocatePool.
    def run(self, PoolType, NumberOfBytes):
        if globals.phase == 2:
            # print("Dentro ExAllocatePoolWithTag Function hook")
            if utils.tainted_buffer(NumberOfBytes):
                utils.print_vuln('allocate pool', 'ExAllocatePool - NumberOfBytes controllable', self.state, {'PoolType': str(PoolType), 'NumberOfBytes': str(NumberOfBytes), 'Tag': str(Tag)})

            ret_addr = hex(self.state.callstack.ret_addr)
            allocated_ptr = claripy.BVS(f'ExAllocatePool_{ret_addr}', self.state.arch.bits)
            self.state.globals['active_buffers'].append((str(allocated_ptr), int(self.state.solver.eval(NumberOfBytes))))
            return allocated_ptr    
        else:
            return utils.next_base_addr()

#PVOID ExAllocatePoolWithTag(
#   [in] __drv_strictTypeMatch(__drv_typeExpr)POOL_TYPE PoolType,
#   [in] SIZE_T                                         NumberOfBytes,
#   [in] ULONG                                          Tag
# );
# L'hook controlla se possiamo controllare il numero di bytes allocati
# inoltre crea un sym value del puntatore allocato, cosi' da vedere se in futur potremo controllarlo
class HookExAllocatePoolWithTag(angr.SimProcedure):
    def run(self, PoolType, NumberOfBytes, Tag):
        if globals.phase == 2:
            # print("Dentro ExAllocatePoolWithTag Function hook")
            if utils.tainted_buffer(NumberOfBytes):
                utils.print_vuln('allocate pool', 'ExAllocatePoolWithTag - NumberOfBytes controllable', self.state, {'PoolType': str(PoolType), 'NumberOfBytes': str(NumberOfBytes), 'Tag': str(Tag)})

            ret_addr = hex(self.state.callstack.ret_addr)
            allocated_ptr = claripy.BVS(f'ExAllocatePoolWithTag_{ret_addr}', self.state.arch.bits)
            self.state.globals['active_buffers'].append((str(allocated_ptr), int(self.state.solver.eval(NumberOfBytes))))
            return allocated_ptr    
        else:
            return utils.next_base_addr()


# PVOID ExAllocatePoolWithQuotaTag(
#   [in] __drv_strictTypeMatch(__drv_typeExpr)POOL_TYPE PoolType,
#   [in] SIZE_T                                         NumberOfBytes,
#   [in] ULONG                                          Tag
# );



# DECLSPEC_RESTRICT PVOID ExAllocatePool2(
#   POOL_FLAGS Flags,
#   SIZE_T     NumberOfBytes,
#   ULONG      Tag
# );
class HookExAllocatePool2(angr.SimProcedure):
    def run(self, Flags, NumberOfBytes, Tag):
        if globals.phase == 2:
            if utils.tainted_buffer(NumberOfBytes):
                utils.print_vuln('allocate pool', 'ExAllocatePool2 - NumberOfBytes controllable', self.state, {'Flags': str(Flags), 'NumberOfBytes': str(NumberOfBytes), 'Tag': str(Tag)})

            ret_addr = hex(self.state.callstack.ret_addr)
            allocated_ptr = claripy.BVS(f'ExAllocatePool2_{ret_addr}', self.state.arch.bits)
            self.state.globals['active_buffers'].append((str(allocated_ptr), int(self.state.solver.eval(NumberOfBytes))))
            return allocated_ptr    
        else:
            return utils.next_base_addr()

# DECLSPEC_RESTRICT PVOID ExAllocatePool3(
#   POOL_FLAGS                Flags,
#   SIZE_T                    NumberOfBytes,
#   ULONG                     Tag,
#   PCPOOL_EXTENDED_PARAMETER ExtendedParameters,
#   ULONG                     ExtendedParametersCount
# );
class HookExAllocatePool3(angr.SimProcedure):
    def run(self, Flags, NumberOfBytes, Tag, ExtendedParameters, ExtendedParametersCount):
        if globals.phase == 2:
            if utils.tainted_buffer(NumberOfBytes):
                utils.print_vuln('allocate pool', 'ExAllocatePool3 - NumberOfBytes controllable', self.state, {'Flags': str(Flags), 'NumberOfBytes': str(NumberOfBytes), 'Tag': str(Tag), 'ExtendedParameters': str(ExtendedParameters), 'ExtendedParametersCount': str(ExtendedParametersCount)})

            ret_addr = hex(self.state.callstack.ret_addr)
            allocated_ptr = claripy.BVS(f'ExAllocatePool3_{ret_addr}', self.state.arch.bits)
            self.state.globals['active_buffers'].append((str(allocated_ptr), int(self.state.solver.eval(NumberOfBytes))))
            return allocated_ptr    
        else:
            return utils.next_base_addr()

# Altri hook a funzioni di allocazione di pool
class HookMmAllocateNonCachedMemory(angr.SimProcedure):
    # Trace the allocated buffer by MmAllocateNonCachedMemory.
    def run(self, NumberOfBytes):
        if globals.phase == 2:
            ret_addr = hex(self.state.callstack.ret_addr)
            allocated_ptr = claripy.BVS(f"MmAllocateNonCachedMemory_{ret_addr}", self.state.arch.bits)
            return allocated_ptr
        else:
            return utils.next_base_addr()
        
class HookMmAllocateContiguousMemorySpecifyCache(angr.SimProcedure):
    # Trace the allocated buffer by MmAllocateContiguousMemorySpecifyCache.
    def run(self, NumberOfBytes, LowestAcceptableAddress, HighestAcceptableAddress, BoundaryAddressMultiple, CacheType):
        if globals.phase == 2:
            ret_addr = hex(self.state.callstack.ret_addr)
            allocated_ptr = claripy.BVS(f"MmAllocateContiguousMemorySpecifyCache_{ret_addr}", self.state.arch.bits)
            return allocated_ptr
        else:
            return utils.next_base_addr()


# VOID ExFreePoolWithTag(
#   [in] PVOID P,
#   [in] ULONG Tag
# );
class HookExFreePoolWithTag(angr.SimProcedure):
    def run(self, P, Tag):
        # Controllo se il buffer liberato da ExFreePoolWithTag e' controllabile
        if globals.phase == 2:
            # print("Dentro ExFreePoolWithTagP: ", P)
            if utils.tainted_buffer(P):
                utils.print_vuln('free pool', 'ExFreePoolWithTag - buffer controllable', self.state, {'P': str(P), 'Tag': str(Tag)}, {'return address': hex(self.state.callstack.ret_addr)})

            # if P in globals.freed_set:
                
            if str(P) in self.state.globals['freed_buffers']:
                utils.print_vuln('double free', 'ExFreePoolWithTag - buffer already freed', self.state, {'P': str(P), 'Tag': str(Tag)}, {'return address': hex(self.state.callstack.ret_addr)})
            else:
                # Add to freed set
                self.state.globals['freed_buffers'].append(str(P))
                # globals.freed_set.add(P)
                # Remove from active buffers
                for active_buf in self.state.globals['active_buffers']:
                        
                    if str(P) == active_buf[0]:
                        print("Freeing buffer: ", P)
                        self.state.globals['active_buffers'].remove(active_buf)
                        return
                
# VOID ExFreePool(
#   [in] PVOID P
# );
class HookExFreePool(angr.SimProcedure):
    def run(self, P):
        # Controllo se il buffer liberato da ExFreePoolWithTag e' controllabile
        if globals.phase == 2:
            # print("Dentro ExFreePoolWithTagP: ", P)
            if utils.tainted_buffer(P):
                utils.print_vuln('free pool', 'ExFreePool - buffer controllable', self.state, {'P': str(P)}, {'return address': hex(self.state.callstack.ret_addr)})

            # if P in globals.freed_set:
                
            if str(P) in self.state.globals['freed_buffers']:
                utils.print_vuln('double free', 'ExFreePool - buffer already freed', self.state, {'P': str(P)}, {'return address': hex(self.state.callstack.ret_addr)})
            else:
                # Add to freed set
                self.state.globals['freed_buffers'].append(str(P))
                # globals.freed_set.add(P)
                # Remove from active buffers
                for active_buf in self.state.globals['active_buffers']:
                        
                    if str(P) == active_buf[0]:
                        print("Freeing buffer: ", P)
                        self.state.globals['active_buffers'].remove(active_buf)
                        return
                
                        
# VOID ExFreePool2(
#   [in]           PVOID                     P,
#   [in]           ULONG                     Tag,
#   [in, optional] PCPOOL_EXTENDED_PARAMETER ExtendedParameters,
#   [in]           ULONG                     ExtendedParametersCount
# );
class HookExFreePool2(angr.SimProcedure):
    def run(self, P, Tag, ExtendedParameters, ExtendedParametersCount):
        # Controllo se il buffer liberato da ExFreePoolWithTag e' controllabile
        if globals.phase == 2:
            # print("Dentro ExFreePoolWithTagP: ", P)
            if utils.tainted_buffer(P):
                utils.print_vuln('free pool', 'ExFreePool2 - buffer controllable', self.state, {'P': str(P), 'Tag': str(Tag), 'ExtendedParameters': str(ExtendedParameters), 'ExtendedParametersCount': str(ExtendedParametersCount)}, {'return address': hex(self.state.callstack.ret_addr)})

            # if P in globals.freed_set:
                
            if str(P) in self.state.globals['freed_buffers']:
                utils.print_vuln('double free', 'ExFreePool2 - buffer already freed', self.state, {'P': str(P), 'Tag': str(Tag)}, {'return address': hex(self.state.callstack.ret_addr)})
            else:
                # Add to freed set
                self.state.globals['freed_buffers'].append(str(P))
                # globals.freed_set.add(P)
                # Remove from active buffers
                for active_buf in self.state.globals['active_buffers']:
                        
                    if str(P) == active_buf[0]:
                        print("Freeing buffer: ", P)
                        self.state.globals['active_buffers'].remove(active_buf)
                        return
                
                

# Hook per le operazioni di memset o memcpy
# Controlla per vari buffer overflows
class HookMemcpy(angr.SimProcedure):
    def run(self, dest, src, size):
        # print("HookMemcpy - dest: ", dest)
        # print("HookMemcpy - src: ", src)
        # print("HookMemcpy - size: ", size)
        
        if utils.tainted_buffer(size):
            is_pool_buffer = False  # Track if we identified this as a pool buffer
            
            # # 1. Check for Pool Buffer Overflow
            for pool in globals.pools:
                if pool in str(dest):
                    is_pool_buffer = True  # Mark that it belongs to a pool
                    buf_size = self.state.globals['active_buffers'][globals.pools.index(pool)][1]
                    # print("Buffer size: ", buf_size)

                    tmp_state = self.state.copy()
                    tmp_state.add_constraints(size > buf_size)

                    if tmp_state.solver.satisfiable():
                        utils.print_vuln('Pool buffer overflow', 'memcpy - size controllable and larger than buffer', self.state, {'dest': str(dest), 'src': str(src), 'size': str(size)}, {'return address': hex(self.state.callstack.ret_addr)})
                    
                    break  # We found the matching pool, no need to check other pools
            # for pool in self.state.globals['active_buffers']:
            #     # print("Checking pool: ", pool)
            #     if pool[0] in str(dest):
            #         is_pool_buffer = True  # Mark that it belongs to a pool
            #         buf_size = pool[1]
            #         # print("Buffer size: ", buf_size)

            #         tmp_state = self.state.copy()
            #         tmp_state.add_constraints(size > buf_size)

            #         if tmp_state.solver.satisfiable():
            #             utils.print_vuln('Pool buffer overflow', 'memcpy - size controllable and larger than buffer', self.state, {'dest': str(dest), 'src': str(src), 'size': str(size)}, {'return address': hex(self.state.callstack.ret_addr)})
                    
            #         break  # We found the matching pool, no need to check other pools
            # 2. Check for Stack Buffer Overflow (ONLY if it's not a pool buffer)
            if not is_pool_buffer:
            # if 1:
                tmp_state2 = self.state.copy()

                if utils.is_stack_address(tmp_state2, dest):
                    caller_rbp = self.state.regs.rbp # Recupera il Base Pointer del chiamante
                    return_addr_location = caller_rbp + 8

                    # Condizione: L'inizio del buffer + la dimensione della copia superano l'indirizzo di ritorno?
                    tmp_state2.add_constraints(dest + size > return_addr_location)

                    if tmp_state2.solver.satisfiable():
                        utils.print_vuln('Stack buffer overflow', 'memcpy - return address controllable', self.state, {'dest': str(dest), 'src': str(src), 'size': str(size)}, {'return address': hex(self.state.callstack.ret_addr)})
                
                # Check for memory disclosure, can copy data of arbitrary size inside my buffer
                elif utils.tainted_buffer(dest):
                    utils.print_vuln('Memory disclosure', 'memcpy - read out of bound inside my buffer', self.state, {'dest': str(dest), 'src': str(src), 'size': str(size)}, {'return address': hex(self.state.callstack.ret_addr)})
        # 3. Execute the actual memcpy behavior
        angr.procedures.SIM_PROCEDURES['libc']['memcpy'](cc=self.cc).execute(self.state, arguments=(dest, src, size))

        return 0
    
# VOID ProbeForRead(
#   [in] const volatile VOID *Address,
#   [in] SIZE_T              Length,
#   [in] ULONG               Alignment
# );
# Segna l'indirizzo probato, cosi' sapremo se la vulnerabilita' e' vera o falso positivo
class HookProbeForRead(angr.SimProcedure):
    def run(self, Address, Length, Alignment):
        if globals.phase == 2:
            if utils.tainted_buffer(Address):
                asts = [i for i in Address.children_asts()]
                target_base = asts[0] if len(asts) > 1 else Address
                # print("ProbeForRead - Address : ", target_base)

                self.state.globals['tainted_ProbeForRead'] += (str(target_base),)
            


# VOID ProbeForWrite(
#   [in, out] volatile VOID *Address,
#   [in]      SIZE_T        Length,
#   [in]      ULONG         Alignment
# );
# Segna l'indirizzo probato, cosi' sapremo se la vulnerabilita' e' vera o falso positivo
class HookProbeForWrite(angr.SimProcedure):
    def run(self, Address, Length, Alignment):
        if globals.phase == 2:
            if utils.tainted_buffer(Address):
                asts = [i for i in Address.recursive_children_asts]
                target_base = asts[0] if len(asts) > 1 else Address
                # ret_addr = hex(self.state.callstack.ret_addr)
                self.state.globals['tainted_ProbeForWrite'] += (str(target_base), )



# Hook alla funzione per risolvere a runtime le altre funzioni.
# Se possibile le 'Ri-hooko' con i miei hook, altrimenti le lascio come sono
class HookMmGetSystemRoutineAddress(angr.SimProcedure):
    def run(self, SystemRoutineName):
        try:
            wstring_addr = self.state.mem[SystemRoutineName].struct._UNICODE_STRING.Buffer.resolved
            SystemRoutineName_wstring = self.state.mem[wstring_addr].wstring.concrete
        except:
            SystemRoutineName_wstring = ""

        hooks = {
            "ZwQueryInformationProcess": HookZwQueryInformationProcess,
            "RtlQueryRegistryValuesEx": HookRtlQueryRegistryValues,
            "RtlQueryRegistryValues": HookRtlQueryRegistryValues,
        }

        for name, proc in hooks.items():
            if name == SystemRoutineName_wstring:
                addr = utils.next_base_addr()
                globals.proj.hook(addr, proc(cc=globals.cc))
                return addr

        return globals.DO_NOTHING

# BOOLEAN MmIsAddressValid(
#   [in] PVOID VirtualAddress
# );
# i don't think this tainting is really useful tainting the address, 
# so for now is commented until i understand why ioctlance taints it
class HookMmIsAddressValid(angr.SimProcedure):
    def run(self, Address):
        # if globals.phase == 2:
        #     if utils.tainted_buffer(Address):
        #         asts = [i for i in Address.recursive_children_asts]
        #         target_base = asts[0] if len(asts) > 1 else Address
        #         # ret_addr = hex(self.state.callstack.ret_addr)
        #         self.state.globals['tainted_MmIsAddressValid'] += (str(target_base), )
        return 1
    

class HookRtlGetVersion(angr.SimProcedure):
    # Hook RtlGetVersion to bypass version check.
    def run(self, lpVersionInformation):
        ret_addr = hex(self.state.callstack.ret_addr)
        VersionInformation = self.state.mem[lpVersionInformation].struct._OSVERSIONINFOW
        dwMajorVersion = claripy.BVS(f"RtlGetVersion_{ret_addr}", self.state.arch.bits // 2)
        VersionInformation.dwMajorVersion = dwMajorVersion
        dwMinorVersion = claripy.BVS(f"RtlGetVersion_{ret_addr}", self.state.arch.bits // 2)
        VersionInformation.dwMinorVersion = dwMinorVersion
        dwBuildNumber = claripy.BVS(f"RtlGetVersion_{ret_addr}", self.state.arch.bits // 2)
        VersionInformation.dwBuildNumber = dwBuildNumber
        return 0

class HookPsGetVersion(angr.SimProcedure):
    # Hook PsGetVersion to bypass version check.
    def run(self, MajorVersion, MinorVersion, BuildNumber, CSDVersion):
        ret_addr = hex(self.state.callstack.ret_addr)
        major_version = claripy.BVS(f"PsGetVersion_{ret_addr}", self.state.arch.bits)
        self.state.memory.store(MajorVersion, major_version, self.state.arch.bytes, endness=self.state.arch.memory_endness, disable_actions=True, inspect=False)
        minor_version = claripy.BVS(f"PsGetVersion_{ret_addr}", self.state.arch.bits)
        self.state.memory.store(MinorVersion, minor_version, self.state.arch.bytes, endness=self.state.arch.memory_endness, disable_actions=True, inspect=False)
        build_number = claripy.BVS(f"PsGetVersion_{ret_addr}", self.state.arch.bits)
        self.state.memory.store(BuildNumber, build_number, self.state.arch.bytes, endness=self.state.arch.memory_endness, disable_actions=True, inspect=False)
        csd_version= claripy.BVS(f"PsGetVersion_{ret_addr}", self.state.arch.bits * 2)
        self.state.memory.store(CSDVersion, csd_version, self.state.arch.bytes * 2, endness=self.state.arch.memory_endness, disable_actions=True, inspect=False)
        return 0




class HookZwDeleteFile(angr.SimProcedure):
    def run(self, ObjectAttributes):
        if globals.phase == 2:
            # Check if we can control the parameters of ZwDeleteFile.
            _analyze_object_attributes('ZwDeleteFile', self.state, ObjectAttributes)
            object_info = _read_object_attributes_info(self.state, ObjectAttributes)

            if object_info['controlled']:
                utils.print_vuln(
                    'arbitrary file delete',
                    'ZwDeleteFile - ObjectName controllable',
                    self.state,
                    {
                        'ObjectAttributes': str(ObjectAttributes),
                        'ObjectName': str(object_info['object_name']),
                        'ObjectName.Buffer': str(object_info['object_name_buffer']),
                        'Attributes': str(object_info['attributes']),
                    },
                    {'return address': hex(self.state.callstack.ret_addr)}
                )

        return 0


# simbolizza handle 
class HookZwOpenFile(angr.SimProcedure):
    def run(self, FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, OpenOptions):
        if globals.phase == 2:
            _analyze_object_attributes('ZwOpenFile', self.state, ObjectAttributes)
            object_info = _read_object_attributes_info(self.state, ObjectAttributes)

            # Check if we can control the parameters of ZwOpenFile.
            ret_addr = hex(self.state.callstack.ret_addr)
            handle = claripy.BVS(f'ZwOpenFile_{ret_addr}', self.state.arch.bits)
            self.state.memory.store(FileHandle, handle, self.state.arch.bytes, endness=self.state.arch.memory_endness, disable_actions=True, inspect=False)
            _write_success_io_status_block(self.state, IoStatusBlock)

            # aggiungi info handle alla lista state.globals['open_file_handles']
            _track_file_handle(self.state, handle, object_info, DesiredAccess=DesiredAccess, CreateOptions=OpenOptions)

        return 0

# Stesso di ZwOpenFile 
class HookZwCreateFile(angr.SimProcedure):
    def run(self, FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength):
        if globals.phase == 2:
            # Check if we can control the parameters of ZwCreateFile.
            _analyze_object_attributes('ZwCreateFile', self.state, ObjectAttributes)
            object_info = _read_object_attributes_info(self.state, ObjectAttributes)

            # Check if we can control the parameters of ZwOpenFile.
            ret_addr = hex(self.state.callstack.ret_addr)
            handle = claripy.BVS(f'ZwCreateFile_{ret_addr}', self.state.arch.bits)
            self.state.memory.store(FileHandle, handle, self.state.arch.bytes, endness=self.state.arch.memory_endness, disable_actions=True, inspect=False)
            _write_success_io_status_block(self.state, IoStatusBlock)
            _track_file_handle(self.state, handle, object_info, DesiredAccess=DesiredAccess, CreateDisposition=CreateDisposition, CreateOptions=CreateOptions)

        return 0
    
# Check if we can control the parameters of ZwWriteFile
class HookZwWriteFile(angr.SimProcedure):
    def run(self, FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key):
        if globals.phase == 2:
            # Check se l'handle e' stato simbolizzato da ZwOpenFile o ZwCreateFile, se si controllabile e se ha i permessi di scrittura
            handle_info = _lookup_file_handle(self.state, FileHandle)
            tracked_controlled_file = (
                handle_info is not None and
                handle_info[5] and
                _file_access_may_write(self.state, handle_info[2])
            )
            unknown_symbolic_file = handle_info is None and FileHandle.symbolic

            if tracked_controlled_file or unknown_symbolic_file:
                access_type = 'ZwWriteFile - write to controllable file handle' if tracked_controlled_file else 'ZwWriteFile - write to unknown symbolic file handle'
                additional_info = {
                    'FileHandle': str(FileHandle),
                    'Buffer': str(Buffer),
                    'Length': str(Length),
                    'ByteOffset': str(ByteOffset),
                }

                if handle_info is not None:
                    additional_info['ObjectName'] = str(handle_info[1])
                    additional_info['DesiredAccess'] = str(handle_info[2])
                    additional_info['CreateDisposition'] = str(handle_info[3])
                    additional_info['CreateOptions'] = str(handle_info[4])

                utils.print_vuln(
                    'arbitrary file write',
                    access_type,
                    self.state,
                    additional_info,
                    {'return address': hex(self.state.callstack.ret_addr)}
                )

            if utils.tainted_buffer(Buffer) or utils.tainted_buffer(Length) or utils.tainted_buffer(ByteOffset):
                utils.print_vuln(
                    'controlled file write parameters',
                    'ZwWriteFile - Buffer, Length, or ByteOffset controllable',
                    self.state,
                    {
                        'FileHandle': str(FileHandle),
                        'Buffer': str(Buffer),
                        'Length': str(Length),
                        'ByteOffset': str(ByteOffset),
                    },
                    {'return address': hex(self.state.callstack.ret_addr)}
                )

        _write_success_io_status_block(self.state, IoStatusBlock, Length)
        return 0



class HookZwReadFile(angr.SimProcedure):
    def run(self, FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock,
            Buffer, Length, ByteOffset, Key):

        if globals.phase == 2:
            handle_info = _lookup_file_handle(self.state, FileHandle)

            tracked_controlled_file = (
                handle_info is not None and
                handle_info[5]
            )
            unknown_symbolic_file = handle_info is None and FileHandle.symbolic

            if tracked_controlled_file or unknown_symbolic_file:
                additional_info = {
                    'FileHandle': str(FileHandle),
                    'Buffer': str(Buffer),
                    'Length': str(Length),
                    'ByteOffset': str(ByteOffset),
                }

                if handle_info is not None:
                    additional_info['ObjectName'] = str(handle_info[1])
                    additional_info['DesiredAccess'] = str(handle_info[2])
                    additional_info['CreateDisposition'] = str(handle_info[3])
                    additional_info['CreateOptions'] = str(handle_info[4])

                utils.print_vuln(
                    'arbitrary file read',
                    'ZwReadFile - read from controllable file handle',
                    self.state,
                    additional_info,
                    {'return address': hex(self.state.callstack.ret_addr)}
                )

            if utils.tainted_buffer(Buffer) or utils.tainted_buffer(Length) or utils.tainted_buffer(ByteOffset):
                utils.print_vuln(
                    'controlled file read parameters',
                    'ZwReadFile - Buffer, Length, or ByteOffset controllable',
                    self.state,
                    {
                        'FileHandle': str(FileHandle),
                        'Buffer': str(Buffer),
                        'Length': str(Length),
                        'ByteOffset': str(ByteOffset),
                    },
                    {'return address': hex(self.state.callstack.ret_addr)}
                )

            # Model successful read: data coming from a controlled/unknown file
            # should become symbolic so later uses can be detected.
            try:
                read_len = min(self.state.solver.eval(Length), 0x400)
                if read_len > 0:
                    ret_addr = hex(self.state.callstack.ret_addr)
                    data = claripy.BVS(f'ZwReadFile_data_{ret_addr}', read_len * 8)
                    self.state.memory.store(
                        Buffer,
                        data,
                        read_len,
                        disable_actions=True,
                        inspect=False
                    )
            except Exception:
                pass

        _write_success_io_status_block(self.state, IoStatusBlock, Length)
        return 0


class HookZwSetInformationFile(angr.SimProcedure):
    def run(self, FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass):
        if globals.phase == 2:
            handle_info = _lookup_file_handle(self.state, FileHandle)

            tracked_controlled_file = (
                handle_info is not None and
                handle_info[5] and
                _file_access_may_write(self.state, handle_info[2])
            )
            unknown_symbolic_file = handle_info is None and FileHandle.symbolic

            dangerous_classes = {
                10: 'FileRenameInformation',
                11: 'FileLinkInformation',
                13: 'FileDispositionInformation',
                20: 'FileEndOfFileInformation',
                64: 'FileDispositionInformationEx',
                65: 'FileRenameInformationEx',
                72: 'FileLinkInformationEx',
            }

            possible_classes = []
            for cls_value, cls_name in dangerous_classes.items():
                try:
                    tmp_state = self.state.copy()
                    tmp_state.solver.add(FileInformationClass == cls_value)
                    if tmp_state.satisfiable():
                        possible_classes.append(cls_name)
                except Exception:
                    pass

            if (tracked_controlled_file or unknown_symbolic_file) and possible_classes:
                additional_info = {
                    'FileHandle': str(FileHandle),
                    'FileInformation': str(FileInformation),
                    'Length': str(Length),
                    'FileInformationClass': str(FileInformationClass),
                    'PossibleClasses': ', '.join(possible_classes),
                }

                if handle_info is not None:
                    additional_info['ObjectName'] = str(handle_info[1])
                    additional_info['DesiredAccess'] = str(handle_info[2])
                    additional_info['CreateDisposition'] = str(handle_info[3])
                    additional_info['CreateOptions'] = str(handle_info[4])

                utils.print_vuln(
                    'arbitrary file modification',
                    'ZwSetInformationFile - dangerous operation on controllable file handle',
                    self.state,
                    additional_info,
                    {'return address': hex(self.state.callstack.ret_addr)}
                )

            if utils.tainted_buffer(FileInformation) or utils.tainted_buffer(Length) or utils.tainted_buffer(FileInformationClass):
                utils.print_vuln(
                    'controlled file information parameters',
                    'ZwSetInformationFile - FileInformation, Length, or FileInformationClass controllable',
                    self.state,
                    {
                        'FileHandle': str(FileHandle),
                        'FileInformation': str(FileInformation),
                        'Length': str(Length),
                        'FileInformationClass': str(FileInformationClass),
                    },
                    {'return address': hex(self.state.callstack.ret_addr)}
                )

        _write_success_io_status_block(self.state, IoStatusBlock)
        return 0



class HookIoCreateFile(angr.SimProcedure):
    def run(self, FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, Disposition, CreateOptions, EaBuffer, EaLength, CreateFileType, InternalParameters, Options):
        if globals.phase == 2:
            # Check if we can control the parameters of IoCreateFile.
            utils.analyze_ObjectAttributes('IoCreateFile', self.state, ObjectAttributes)

        return 0

class HookIoCreateFileEx(angr.SimProcedure):
    def run(self, FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, Disposition, CreateOptions, EaBuffer, EaLength, CreateFileType, InternalParameters, Options, DriverContext):
        if globals.phase == 2:
            # Check if we can control the parameters of IoCreateFileEx.
            utils.analyze_ObjectAttributes('IoCreateFileEx', self.state, ObjectAttributes)

        return 0
    
class HookIoCreateFileSpecifyDeviceObjectHint(angr.SimProcedure):
    def run(self, FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, Disposition, CreateOptions, EaBuffer, EaLength, CreateFileType, InternalParameters, Options, DeviceObject):
        if globals.phase == 2:
            # Check if we can control the parameters of IoCreateFileSpecifyDeviceObjectHint.
            utils.analyze_ObjectAttributes('IoCreateFileSpecifyDeviceObjectHint', self.state, ObjectAttributes)

        return 0


class HookZwQueryInformationFile(angr.SimProcedure):
    def run(self, FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass):
        ret_addr = hex(self.state.callstack.ret_addr)
        isb = self.state.mem[IoStatusBlock].struct._IO_STATUS_BLOCK
        # Ritorna status success
        isb.u.Status = 0
        # Alloca un buffer per FileInformation, cosi' da poterlo popolare e controllare se e' controllabile o meno
        isb.Information = utils.next_base_addr()
        # verifica  FileNameInformation, cioe' controlla se
        # La chiamata e' stat richiesta per leggere il nome del file, e se si,
        if self.state.solver.eval(FileInformationClass) == 9:
            fi = self.state.mem[FileInformation].struct._FILE_NAME_INFORMATION
            # Mette a un valore valido cosi' da evitare crash
            fi.FileNameLength = 0x10
        return 0

class HookZwCreateKey(angr.SimProcedure):
    def run(self, KeyHandle, DesiredAccess, ObjectAttributes, TitleIndex, Class, CreateOptions, Disposition):
        return 0
    
class HookZwOpenKey(angr.SimProcedure):
    def run(self, KeyHandle, DesiredAccess, ObjectAttributes):
        return 0
    
class HookZwDeleteValueKey(angr.SimProcedure):
    def run(self, KeyHandle, ValueName):
        return 0
    
class HookZwQueryValueKey(angr.SimProcedure):
    def run(self, KeyHandle, ValueName, KeyValueInformationClass, KeyValueInformation, Length, ResultLength):
        return 0
    

# serve a registrare un "Protocol Driver" (driver di protocollo) presso il sistema operativo, permettendogli di interfacciarsi con lo stack di rete di Windows.
# L'hook semplicevemente serve ad evitare che esegue quella originale e scrive un valore finto nell' handle
class HookNdisRegisterProtocolDriver(angr.SimProcedure):
    def run(self, ProtocolDriverContext, ProtocolCharacteristics, NdisProtocolHandle):
        self.state.memory.store(NdisProtocolHandle, 0x87, self.state.arch.bytes, endness=self.state.arch.memory_endness, disable_actions=True, inspect=False)
        return 0
    


# Hook ZwQueryInformationProcess per controllare se posso controllare 
# ProcessInformationClass, ProcessInformationLength o ReturnLength, e se ProcessInformationLength e' 0
class HookZwQueryInformationProcess(angr.SimProcedure):
    def run(self, ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength):
        if not ProcessInformationLength.symbolic and self.state.solver.eval(ProcessInformationLength) == 0:
            #0xC0000004 	0x00000018 	NT_STATUS_INFO_LENGTH_MISMATCH
            return 0xC0000004
        return 0
    

# L'hook serve a vedere se possiamo chiudere handle in processi 
# diversi da quello in cui sono stati creati, e se l'handle e' controllabile,
class HookObCloseHandle(angr.SimProcedure):
    def run(self, Handle, PreviousMode):
        if (globals.phase != 2) or (not utils.tainted_buffer(Handle)):
            return 0
        ret_addr = hex(self.state.callstack.ret_addr)

    # Controlla se ci sono processi taintati e che hanno cambiato
    # contesto con KeStackAttachProcess, 
        attached_process = self.state.globals['tainted_process_context_changing'] != ()

        if not attached_process:
            return 0
        
        vuln_title = "ObCloseHandle - Close controllable handle in different process context"
        vuln_description = "ObCloseHandle - Tainted handle in different process context"
        vuln_parameters = {'Handle': str(Handle)}
        vuln_others = {'return address': ret_addr}
        list_of_constraints = list()

        # Process explorer specific check
        for tainted_object in self.state.globals['tainted_objects']:
            for constraint in self.state.solver.constraints:
                if constraint.op != '__eq__':
                    continue
                if any(v in tainted_object for v in constraint.variables):
                    list_of_constraints.append(str(constraint))

        if len(list_of_constraints) > 0:
            vuln_others['obj_constraints'] = list_of_constraints

        utils.print_vuln(vuln_title, vuln_description, self.state, vuln_parameters, vuln_others)
        return 0


# La routine KeStackAttachProcess collega il thread corrente 
# allo spazio indirizzi del processo di destinazione.
# PROCESS e' punutatore all'EPROCESS del processo di destinazione, 
# ApcState e' un puntatore a una struttura KAPC_STATE che viene utilizzata 
# per memorizzare lo stato del thread prima dell'attaccamento, in modo da poterlo ripristinare
# successivamente con KeUnstackDetachProcess.
class HookKeStackAttachProcess(angr.SimProcedure):
    def run(self, PROCESS, ApcState):
        if globals.phase != 2:
            return 0
        
        ret_addr = hex(self.state.callstack.ret_addr)

        # Check if the eprocess is tainted (from the PsLookupProcessByProcessId)
        if ('tainted_eprocess' in self.state.globals) and (str(PROCESS) in self.state.globals['tainted_eprocess']):
            # The "process" element was tainted, so we consider it tainted also in this function.
            # In addition, we can consider that the process context is mutating by creating a new global variable.
            # Adding the tainted PROCESS to the global variable to track changes in the process context.
            self.state.globals['tainted_process_context_changing'] += (str(PROCESS), )
        
        # Create a symbolic variable for propagation (out parameter)
        apcstate = claripy.BVS(f'KeStackAttachProcess_{ret_addr}', self.state.arch.bits)
        self.state.memory.store(ApcState, apcstate, self.state.arch.bytes, endness=self.state.arch.memory_endness, disable_actions=True, inspect=False)

        return 0

# La funzione originale semplicemente dato un handle torna puntatore
# All' oggetto referenziato
class HookObReferenceObjectByHandle(angr.SimProcedure):
    # Trace the handle opened by ObReferenceObjectByHandle.
    def run(self, Handle, DesiredAccess, ObjectType, AccessMode, Object, HandleInformation):
        ret_addr = hex(self.state.callstack.ret_addr)
        object = claripy.BVS(f"ObReferenceObjectByHandle_{ret_addr}", self.state.arch.bits)
        self.state.memory.store(Object, object, self.state.arch.bytes, endness=self.state.arch.memory_endness, disable_actions=True, inspect=False)

    # check se controlliamo HANDLE, se e' un Processo
        if (globals.star_ps_process_type is not None) and self.state.solver.eval(ObjectType == globals.star_ps_process_type) and utils.tainted_buffer(Handle):
            self.state.globals['tainted_eprocess'] += (str(object), )
        return 0



class HookFltGetRoutineAddress(angr.SimProcedure):
    # Return the function address acquired by FltGetRoutineAddress.
    def run(self, FltMgrRoutineName):
        return globals.DO_NOTHING

class HookDoNothing(angr.SimProcedure):
    def run(self):
        return 0
    

class HookIoIs32bitProcess(angr.SimProcedure):
    def run(self):
        return 0

class HookVsnprintf(angr.SimProcedure):
    def run(self, buffer, count, format, argptr):
        return 0

class HookExInitializeResourceLite(angr.SimProcedure):
    def run(self, Resource):
        return 0
    
class HookExQueryDepthSList(angr.SimProcedure):
    def run(self, SListHead):
        return 0
    
class HookExpInterlockedPushEntrySList(angr.SimProcedure):
    def run(self, ListHead, ListEntry):
        return 0
    
class HookExpInterlockedPopEntrySList(angr.SimProcedure):
    def run(self, ListHead, Lock):
        return 0

class HookKeWaitForSingleObject(angr.SimProcedure):
    def run(self, Object, WaitReason, WaitMode, Alertable, Timeout):
        return 0
    
# Da scrivere forse
class HookRtlWriteRegistryValue(angr.SimProcedure):
    def run(self, RelativeTo, Path, ValueName, ValueType, ValueData, ValueLength):
        return 0
    
class HookIoGetDeviceProperty(angr.SimProcedure):
    def run(self, DeviceObject, DeviceProperty, BufferLength, PropertyBuffer, ResultLength):
        return 0

class HookKeReleaseMutex(angr.SimProcedure):
    def run(self, Mutex, Wait):
        return 0



class HookRtlQueryRegistryValues(angr.SimProcedure):
    def get_entry_context(state: angr.sim_state.SimState, Table, Index):
        entry_ptr = Table + Index * (state.mem.RTL_QUERY_REGISTRY_TABLE._type.size // 8)
        table_entry = state.mem[entry_ptr].RTL_QUERY_REGISTRY_TABLE
        return table_entry.EntryContext

    def search_for_termdd_like_vuln(originalState: angr.sim_state.SimState, directTableEntries, start_of_table_addr, end_of_table_addr):
        TAINTED_BUFFER_ALLOC = "TaintBufferInsideUnicodeString"
        ret_addr = hex(originalState.callstack.ret_addr)
        # Termdd-like vulnerability.
        # 1- We need to see if, by creating a REG_SZ key, we can control other 
        for index in range(0, len(directTableEntries)):
            state = originalState.copy()
            entry_context_index = directTableEntries[index]["Index"]
            entry_context_name = directTableEntries[index]["Name"]            
            entry_context_view = HookRtlQueryRegistryValues.get_entry_context(state, start_of_table_addr, entry_context_index)

            # First we need to assume that the EntryContext points to a UNICODE_STRING with a NULL Buffer
            # RtlQueryRegistryValues will allocate a buffer for us 
            unicode_str_view = entry_context_view.deref.UNICODE_STRING
            if state.solver.is_false(unicode_str_view.Buffer.resolved == 0):
                continue

            # We "simulate" the buffer allocation with a symbolic variable that can be used to easily spot a taint
            unicode_str_view.Buffer = claripy.BVS(f'{TAINTED_BUFFER_ALLOC}_{ret_addr}', state.arch.bits)

            # We now need to check if a subsequent EntryContext can be controlled
            for subsequentIndex in range(index + 1, len(directTableEntries)):
                subsequent_entry_context_index = directTableEntries[subsequentIndex]["Index"]
                subsequent_entry_context_name = directTableEntries[subsequentIndex]["Name"]
                subsequent_entry_context_view = HookRtlQueryRegistryValues.get_entry_context(state, start_of_table_addr, subsequent_entry_context_index)
                if TAINTED_BUFFER_ALLOC not in str(subsequent_entry_context_view.deref.uint32_t.resolved):
                    continue

                vuln_title = f"buffer overflow"
                vuln_description = f"RtlQueryRegistryValues - Controllable first 4 bytes of EntryContext"
                vuln_parameters = {
                    "Vulnerable entry index" : entry_context_index,
                    "Vulnerable entry name" : entry_context_name, 
                    "Vulnerable EntryContext" : str(entry_context_view.resolved), 
                    "Controllable entry index" : subsequent_entry_context_index,
                    "Controllable entry name" : subsequent_entry_context_name, 
                    "Controllable EntryContext" : str(subsequent_entry_context_view.deref.uint32_t._addr), 
                }
                vuln_others = {"return address": ret_addr}
                utils.print_vuln(vuln_title, vuln_description, state, vuln_parameters, vuln_others)

                # If the controllable EntryContext is inside the table
                if state.solver.is_true(subsequent_entry_context_view.resolved < end_of_table_addr):
                    vuln_title = f"buffer overflow"
                    vuln_description = f"RtlQueryRegistryValues - Controllable binary EntryContext {subsequent_entry_context_index} before the start of the table or in the middle of it"
                    vuln_parameters = {                        
                        "Vulnerable entry index" : subsequent_entry_context_index,
                        "Vulnerable entry name" : subsequent_entry_context_name, 
                        "EntryContext" : str(subsequent_entry_context_view.resolved), 
                        'Address of the start of the table': str(start_of_table_addr),
                        'Address of the end of the table': str(end_of_table_addr)
                    }
                    vuln_others = {"return address": ret_addr}
                    utils.print_vuln(vuln_title, vuln_description, state, vuln_parameters, vuln_others)

    def run(self, RelativeTo, Path, QueryTable, Context, Environment):
        ret_addr = hex(self.state.callstack.ret_addr)
        ptr_size = self.state.arch.bytes

        directTableEntries = []
        indexWhile = -1
        while True:
            # Each RtlQueryRegistryTable entry is 7 pointers long:
            indexWhile  += 1
            assert(self.state.mem.RTL_QUERY_REGISTRY_TABLE._type.size == (0x38 * 8))
            entry_ptr = QueryTable + indexWhile * (self.state.mem.RTL_QUERY_REGISTRY_TABLE._type.size // 8)
            table_entry = self.state.mem[entry_ptr].RTL_QUERY_REGISTRY_TABLE

            try:
                query_routine = table_entry.QueryRoutine.resolved
                name_ptr = table_entry.Name.uint64_t.resolved
            except:
                break

            # Stop if terminated
            if self.state.solver.is_true(query_routine == 0) and self.state.solver.is_true(name_ptr == 0):
                break

            try:
                flags = table_entry.Flags.uint32_t.resolved
                name = table_entry.Name.deref.wstring.concrete
                entry_context = table_entry.EntryContext
            except:
                break
            
            # Check for vulnerable combination
            # RTL_QUERY_REGISTRY_DIRECT (0x20) and not RTL_QUERY_REGISTRY_TYPECHECK (0x00000100)
            has_direct = self.state.solver.is_true(flags & 0x20 != 0)
            has_typecheck = self.state.solver.is_true(flags & 0x00000100 != 0)
            if (not has_direct) or has_typecheck:
                continue

            if self.state.solver.is_true(entry_context == 0):
                continue

            directTableEntries.append({
                "Index" : indexWhile,
                "Name": name,
                #"EntryContext": entry_context,
            })

            # win32k-like vulnerability
            # If we have an EntryContext that is assumed (by the driver) to have a default value (already in memory) different from zero an attacker might be able
            # to use a REG_BINARY key to overwrite memory that hosts the EntryContext
            # We consider only possible lengths that are greater than 4 bytes
            magnitude = entry_context.deref.int32_t
            valid_positive_magnitude = self.state.solver.is_true((magnitude.resolved & 0x80000000) == 0) and self.state.solver.is_true(magnitude.resolved > 4)
            valid_negative_magnitude = self.state.solver.is_true((magnitude.resolved & 0x80000000) != 0) and self.state.solver.is_true(-magnitude.resolved > 4)
            if valid_positive_magnitude or valid_negative_magnitude:
                vuln_title = f"buffer overflow"
                vuln_description = f"RtlQueryRegistryValues - Potential overflow due to non-zero DWORD on first bytes of entry {indexWhile}"
                vuln_parameters = {
                    "Vulnerable entry index" : indexWhile,
                    "Vulnerable entry name" : name, 
                    "EntryContext" : str(entry_context.resolved),                     
                    'NonStringDataSize': magnitude.concrete,
                }
                vuln_others = {"return address": ret_addr}
                utils.print_vuln(vuln_title, vuln_description, self.state, vuln_parameters, vuln_others)
        
        end_of_table_addr = QueryTable +  indexWhile * (self.state.mem.RTL_QUERY_REGISTRY_TABLE._type.size // 8)
        HookRtlQueryRegistryValues.search_for_termdd_like_vuln(self.state, directTableEntries, QueryTable, end_of_table_addr)
        return 0


# Helper che data un MDL cerca se e' stato allocato da IoAllocateMdl, e se si ritorna le info relative a quell'MDL (indirizzo virtuale e dimensione)
def _allocated_mdl_info(state, MemoryDescriptorList):
    for mdl_info in state.globals.get('allocated_mdls', ()):
        try:
            match = MemoryDescriptorList == mdl_info['Address']
            if isinstance(match, bool):
                is_match = match
            else:
                is_match = state.solver.is_true(match)
        except Exception:
            is_match = False

        if is_match:
            return mdl_info
    return None


# PMDL IoAllocateMdl(
#   [in, optional]      __drv_aliasesMem PVOID VirtualAddress,
#   [in]                ULONG                  Length,
#   [in]                BOOLEAN                SecondaryBuffer,
#   [in]                BOOLEAN                ChargeQuota,
#   [in, out, optional] PIRP                   Irp
# );
class HookIoAllocateMdl(angr.SimProcedure):
    def run(self, VirtualAddress, Length, SecondaryBuffer, ChargeQuota, Irp):
        if utils.tainted_buffer(VirtualAddress):
            if utils.tainted_buffer(Length):
                utils.print_vuln(
                    'MDL Arbitrary virtual address mapping',
                    'IoAllocateMdl - VirtualAddress and Length controllable',
                    self.state,
                    {
                        'VirtualAddress': str(VirtualAddress),
                        'Length': str(Length),
                    },
                    {'return address': hex(self.state.callstack.ret_addr)}
                )
            else:
                utils.print_vuln(
                    'MDL Arbitrary virtual address mapping',
                    'IoAllocateMdl - VirtualAddress controllable',
                    self.state,
                    {
                        'VirtualAddress': str(VirtualAddress),
                        'Length': str(Length),
                    },
                    {'return address': hex(self.state.callstack.ret_addr)}
                )
            pmdl_addr = utils.next_base_addr()
            pmdl = claripy.BVS(f'IoAllocateMdl_pmdl_{hex(self.state.callstack.ret_addr)}', self.state.arch.bits)
            self.state.memory.store(pmdl_addr, pmdl, self.state.arch.bytes, endness=self.state.arch.memory_endness, disable_actions=True, inspect=False)
            self.state.globals['allocated_mdls'] += ({
                'Address': pmdl_addr,
                'Descriptor': pmdl,
                'VirtualAddress': VirtualAddress,
                'Length': Length,
            },)
            return pmdl_addr 
        return utils.next_base_addr()



class HookMmMapLockedPages(angr.SimProcedure):
    def run(self, MemoryDescriptorList, AccessMode):
        mdl_info = _allocated_mdl_info(self.state, MemoryDescriptorList)
        if MemoryDescriptorList.symbolic or mdl_info:
            # Check se controllo accessmode o se e' uguale a 0 (KernelMode)
            if utils.tainted_buffer(AccessMode) or self.state.solver.is_true(AccessMode == 0):
                vuln_parameters = {
                    'MemoryDescriptorList': str(MemoryDescriptorList),
                    'AccessMode': str(AccessMode),
                }
                if mdl_info:
                    vuln_parameters['MdlVirtualAddress'] = str(mdl_info['VirtualAddress'])
                    vuln_parameters['MdlLength'] = str(mdl_info['Length'])

                utils.print_vuln(
                    'MDL Arbitrary virtual address mapping',
                    'MmMapLockedPages - MemoryDescriptorList controllable',
                    self.state,
                    vuln_parameters,
                    {'return address': hex(self.state.callstack.ret_addr)}
                )
        return utils.next_base_addr()

# VOID MmProbeAndLockPages(
#   [in, out] PMDL            MemoryDescriptorList,
#   [in]      KPROCESSOR_MODE AccessMode,
#   [in]      LOCK_OPERATION  Operation
# );
class HookMmProbeAndLockPages(angr.SimProcedure):
    def run(self, MemoryDescriptorList, AccessMode, Operation):
        mdl_info = _allocated_mdl_info(self.state, MemoryDescriptorList)
        if MemoryDescriptorList.symbolic or mdl_info:
            # Check se controllo accessmode o se e' uguale a 0 (KernelMode)
            if utils.tainted_buffer(AccessMode) or self.state.solver.is_true(AccessMode == 0):
                vuln_parameters = {
                    'MemoryDescriptorList': str(MemoryDescriptorList),
                    'AccessMode': str(AccessMode),
                    'Operation': str(Operation),
                }
                if mdl_info:
                    vuln_parameters['MdlVirtualAddress'] = str(mdl_info['VirtualAddress'])
                    vuln_parameters['MdlLength'] = str(mdl_info['Length'])

                utils.print_vuln(
                    'MDL Arbitrary virtual address mapping',
                    'MmProbeAndLockPages - MemoryDescriptorList controllable',
                    self.state,
                    vuln_parameters,
                    {'return address': hex(self.state.callstack.ret_addr)}
                )

# PVOID MmMapLockedPagesSpecifyCache(
#   [in]           PMDL                                                                          MemoryDescriptorList,
#   [in]           __drv_strictType(KPROCESSOR_MODE / enum _MODE,__drv_typeConst)KPROCESSOR_MODE AccessMode,
#   [in]           __drv_strictTypeMatch(__drv_typeCond)MEMORY_CACHING_TYPE                      CacheType,
#   [in, optional] PVOID                                                                         RequestedAddress,
#   [in]           ULONG                                                                         BugCheckOnFailure,
#   [in]           ULONG                                                                         Priority
# );
class HookMmMapLockedPagesSpecifyCache(angr.SimProcedure):
    def run(self, MemoryDescriptorList, AccessMode, CacheType, BaseAddress, BugCheckOnFailure, Priority):
        mdl_info = _allocated_mdl_info(self.state, MemoryDescriptorList)
        if MemoryDescriptorList.symbolic or mdl_info:
            # Check se controllo accessmode o se e' uguale a 0 (KernelMode)
            if utils.tainted_buffer(AccessMode) or self.state.solver.is_true(AccessMode == 0):
                vuln_parameters = {
                    'MemoryDescriptorList': str(MemoryDescriptorList),
                    'AccessMode': str(AccessMode),
                    'CacheType': str(CacheType),
                }
                if mdl_info:
                    vuln_parameters['MdlVirtualAddress'] = str(mdl_info['VirtualAddress'])
                    vuln_parameters['MdlLength'] = str(mdl_info['Length'])

                utils.print_vuln(
                    'MDL Arbitrary virtual address mapping',
                    'MmMapLockedPagesSpecifyCache - MemoryDescriptorList controllable',
                    self.state,
                    vuln_parameters,
                    {'return address': hex(self.state.callstack.ret_addr)}
                )
        return utils.next_base_addr()



class HookIoValidateDeviceIoControlAccess(angr.SimProcedure):
    def run(self, Irp, RequiredAccess):
        if globals.phase == 2:
            ret_addr = hex(self.state.callstack.ret_addr)

            try:
                irsp = self.state.mem[Irp].IRP.Tail.Overlay.s.u.CurrentStackLocation
                ioctl_code = irsp.deref.IO_STACK_LOCATION.Parameters.DeviceIoControl.IoControlCode.resolved
            except Exception:
                ioctl_code = globals.IoControlCode

            try:
                tmp_state = self.state.copy()
                tmp_state.solver.add(RequiredAccess == 0)
                no_access_required = tmp_state.satisfiable()
            except Exception:
                no_access_required = False

            if utils.tainted_buffer(RequiredAccess) or no_access_required:
                utils.print_vuln(
                    'weak ioctl access validation',
                    'IoValidateDeviceIoControlAccess - RequiredAccess controllable or FILE_ANY_ACCESS',
                    self.state,
                    {
                        'Irp': str(Irp),
                        'IoControlCode': str(ioctl_code),
                        'RequiredAccess': str(RequiredAccess),
                    },
                    {'return address': ret_addr}
                )

        return 0


class HookIoCreateDeviceSecure(angr.SimProcedure):
    def run(self, DriverObject, DeviceExtensionSize, DeviceName, DeviceType,
            DeviceCharacteristics, Exclusive, DefaultSDDLString,
            DeviceClassGuid, DeviceObject):

        # Initialize DEVICE_OBJECT, same idea as IoCreateDevice.
        devobjaddr = utils.next_base_addr()
        self.state.globals['device_object_addr'] = devobjaddr

        device_object = claripy.BVS('device_object_secure', 8 * 0x400)
        self.state.memory.store(
            devobjaddr,
            device_object,
            0x400,
            disable_actions=True,
            inspect=False
        )

        self.state.mem[devobjaddr].DEVICE_OBJECT.Flags = 0
        self.state.mem[DeviceObject].PDEVICE_OBJECT = devobjaddr

        # Initialize DeviceExtension.
        new_device_extension_addr = utils.next_base_addr()
        try:
            size = self.state.solver.min(DeviceExtensionSize)
        except Exception:
            size = 0x100

        device_extension = claripy.BVV(0, 8 * size)
        self.state.memory.store(
            new_device_extension_addr,
            device_extension,
            size,
            disable_actions=True,
            inspect=False
        )
        self.state.mem[devobjaddr].DEVICE_OBJECT.DeviceExtension = new_device_extension_addr

        # Store device name for the report/basic info.
        device_name_str = utils.read_buffer_from_unicode_string(self.state, DeviceName)
        if device_name_str:
            if "DeviceName" not in globals.basic_info:
                globals.basic_info["DeviceName"] = []

            if device_name_str not in globals.basic_info["DeviceName"]:
                globals.basic_info["DeviceName"].append(device_name_str)

        # Store SDDL too: useful because IoCreateDeviceSecure is only as good as
        # the security descriptor it receives.
        try:
            sddl_str = utils.read_buffer_from_unicode_string(self.state, DefaultSDDLString)
        except Exception:
            sddl_str = None

        if sddl_str:
            if "DeviceSDDL" not in globals.basic_info:
                globals.basic_info["DeviceSDDL"] = []

            if sddl_str not in globals.basic_info["DeviceSDDL"]:
                globals.basic_info["DeviceSDDL"].append(sddl_str)

            weak_sddl_markers = (
                "WD",      # Everyone / World
                "BU",      # Built-in Users
                "AU",      # Authenticated Users
                "S-1-1-0", # Everyone SID
                "S-1-5-11" # Authenticated Users SID
            )

            dangerous_access_markers = (
                "GA",      # GENERIC_ALL
                "GW",      # GENERIC_WRITE
                "GRGW",
                "GXGW",
                "0x10000000",
                "0x40000000",
            )

            if globals.phase == 2:
                has_weak_principal = any(marker in sddl_str for marker in weak_sddl_markers)
                has_dangerous_access = any(marker in sddl_str for marker in dangerous_access_markers)

                if has_weak_principal and has_dangerous_access:
                    utils.print_vuln(
                        'weak device security descriptor',
                        'IoCreateDeviceSecure - weak SDDL grants broad access',
                        self.state,
                        {
                            'DeviceName': str(device_name_str),
                            'DefaultSDDLString': str(sddl_str),
                            'DeviceType': str(DeviceType),
                            'DeviceCharacteristics': str(DeviceCharacteristics),
                        },
                        {'return address': hex(self.state.callstack.ret_addr)}
                    )

        return 0
