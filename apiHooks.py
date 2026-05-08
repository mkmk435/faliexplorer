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
            ret_addr = hex(self.state.callstack.ret_addr)
            allocated_ptr = claripy.BVS(f"ExAllocatePool_{ret_addr}", self.state.arch.bits)
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
            print("Dentro ExAllocatePoolWithTag Function hook")
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
            globals.active_buffers[str(allocated_ptr)] = int(self.state.solver.eval(NumberOfBytes))
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
            globals.active_buffers[str(allocated_ptr)] = int(self.state.solver.eval(NumberOfBytes))
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
            
            # 1. Check for Pool Buffer Overflow
            for pool in globals.pools:
                if pool in str(dest):
                    is_pool_buffer = True  # Mark that it belongs to a pool
                    buf_size = globals.active_buffers[str(dest)]
                    # print("Buffer size: ", buf_size)

                    tmp_state = self.state.copy()
                    tmp_state.add_constraints(size > buf_size)

                    if tmp_state.solver.satisfiable():
                        utils.print_vuln('Pool buffer overflow', 'memcpy - size controllable and larger than buffer', self.state, {'dest': str(dest), 'src': str(src), 'size': str(size)}, {'return address': hex(self.state.callstack.ret_addr)})
                    
                    break  # We found the matching pool, no need to check other pools

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
                globals.proj.hook(addr, proc(cc=globals.mycc))
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
            utils.analyze_ObjectAttributes('ZwDeleteFile', self.state, ObjectAttributes)

        return 0

# COnsidera che il FileHandle in tutti queste funzioni
# E' popolato, non e' un parametro di input vero
class HookZwOpenFile(angr.SimProcedure):
    def run(self, FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, OpenOptions):
        if globals.phase == 2:
            # Check if we can control the parameters of ZwOpenFile.
            utils.analyze_ObjectAttributes('ZwOpenFile', self.state, ObjectAttributes)

        return 0

class HookZwCreateFile(angr.SimProcedure):
    def run(self, FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength):
        if globals.phase == 2:
            # Check if we can control the parameters of ZwCreateFile.
            utils.analyze_ObjectAttributes('ZwCreateFile', self.state, ObjectAttributes)

        return 0
    
# Check if we can control the parameters of ZwWriteFile
class HookZwWriteFile(angr.SimProcedure):
    def run(self, FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key):
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