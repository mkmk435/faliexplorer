import angr
import claripy
import utils
import globals



# NTSTATUS IoCreateSymbolicLink(
#   [in] PUNICODE_STRING SymbolicLinkName,
#   [in] PUNICODE_STRING DeviceName
# );
# printa e basta il symbolic link name e il device namex``
class HookIoCreateSymbolicLink(angr.SimProcedure):
    def run(self, SymbolicLinkName, DeviceName):

        device_name = utils.read_buffer_from_unicode_string(self.state, DeviceName)
        print("device_name: ", device_name)
        symbolic_link_name = utils.read_buffer_from_unicode_string(self.state, SymbolicLinkName)
        print("symbolic_link_name: ", symbolic_link_name)
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


# NTSTATUS PsLookupProcessByProcessId(
#   [in]  HANDLE    ProcessId,
#   [out] PEPROCESS *Process
# );
class HookPsLookupProcessByProcessId(angr.SimProcedure):
    def run(self, ProcessId, Process):
        if utils.tainted_buffer(ProcessId):
            utils.print_vuln('lookup process', 'PsLookupProcessByProcessId - ProcessId tainted', self.state, {'ProcessId': str(ProcessId), 'Process': str(Process)}, {'return address': hex(self.state.callstack.ret_addr)})
        ret_addr = hex(self.state.callstack.ret_addr)
        eprocess_bvs = claripy.BVS(f'PsLookupProcessByProcessId_{ret_addr}', self.state.arch.bits)
        self.state.memory.store(Process, eprocess_bvs, self.state.arch.bytes, endness=self.state.arch.memory_endness, disable_actions=True, inspect=False)
        self.state.globals['tainted_eprocess'] += (str(eprocess_bvs), )

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
            string_orig = claripy.concat(claripy.BVS(f"RtlInitUnicodeString_{ret_addr}", 8 * 10), claripy.BVV(0, 16))

        # inizializza la dest String, alloca in indirizzo nuovo una stringa unicode
        byte_length = string_orig.length // 8
        new_buffer = utils.next_base_addr()

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


# Scrivi in translated address il valore di BusNumber + BusAddress 
# Serve perche' per 'propagare' il valore di BusNumber e BusAddress al di fuori della funzione, 
# Es. serve per la funzione MmMapIoSpace per controllare se il buffer e' controllabile
class HookHalTranslateBusAddress(angr.SimProcedure):
    def run(self, InterfaceType, BusNumber, BusAddress, AddressSpace, TranslatedAddress):
        self.state.memory.store(TranslatedAddress, BusNumber + BusAddress, self.state.arch.bytes, endness=self.state.arch.memory_endness, disable_actions=True, inspect=False)
        return 1
# class HookHalTranslateBusAddress(angr.SimProcedure):
#     def run(self, InterfaceType, BusNumber, BusAddress, AddressSpace, TranslatedAddress):
#         ret_addr = hex(self.state.callstack.ret_addr)
#         if utils.tainted_buffer(BusNumber) or utils.tainted_buffer(BusAddress):
#             # Create a single symbolic value for the translated address
#             # to avoid accumulating offsets on repeated calls
#             trans_addr = claripy.BVS(f'HalTranslateBusAddress_{ret_addr}', self.state.arch.bits)
#             self.state.memory.store(TranslatedAddress, trans_addr, self.state.arch.bytes, 
#                                     endness=self.state.arch.memory_endness, disable_actions=True, inspect=False)
#             self.state.globals['tainted_translated_addresses'] += (str(trans_addr),)
#         else:
#             self.state.memory.store(TranslatedAddress, BusNumber + BusAddress, 
#                                     self.state.arch.bytes, endness=self.state.arch.memory_endness, 
#                                     disable_actions=True, inspect=False)
#         return 1

class HookIoStartPacket(angr.SimProcedure):
    # Call DriverStartIo when IoStartPacket is called.
    def run(self, DeviceObject, Irp, Key, CancelFunction):
        if globals.DriverStartIo:
            new_state = self.state.project.factory.call_state(addr=globals.DriverStartIo, args=(DeviceObject, Irp), base_state=self.state)
            globals.simgr.deferred.append(new_state)


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
            globals.active_buffers[str(allocated_ptr)] = int(self.state.solver.eval(NumberOfBytes))
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

# VOID ExFreePoolWithTag(
#   [in] PVOID P,
#   [in] ULONG Tag
# );
class HookExFreePoolWithTag(angr.SimProcedure):
    def run(self, P, Tag):
        # Controllo se il buffer liberato da ExFreePoolWithTag e' controllabile
        if globals.phase == 2:
            print("Dentro ExFreePoolWithTagP: ", P)
            if utils.tainted_buffer(P):
                utils.print_vuln('free pool', 'ExFreePoolWithTag - buffer controllable', self.state, {'P': str(P), 'Tag': str(Tag)}, {'return address': hex(self.state.callstack.ret_addr)})

            # if P in globals.freed_set:
                
            if str(P) in self.state.globals['freed_buffers']:
                utils.print_vuln('double free', 'ExFreePoolWithTag - buffer already freed', self.state, {'P': str(P), 'Tag': str(Tag)}, {'return address': hex(self.state.callstack.ret_addr)})
            else:
                # Add to freed set
                self.state.globals['freed_buffers'] += (str(P), )
                # globals.freed_set.add(P)
                # Remove from active buffers

                if P in globals.active_buffers:
                    print("Freeing buffer: ", P)
                    del globals.active_buffers[P]
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
                utils.print_vuln('free pool', 'ExFreePool - buffer controllable', self.state, {'P': str(P), 'Tag': str(Tag)}, {'return address': hex(self.state.callstack.ret_addr)})

            if P in globals.freed_set:
                utils.print_vuln('double free', 'ExFreePool - buffer already freed', self.state, {'P': str(P), 'Tag': str(Tag)}, {'return address': hex(self.state.callstack.ret_addr)})
            else:
                # Add to freed set
                globals.freed_set.add(P)
                # Remove from active buffers

                if P in globals.active_buffers:
                    print("Freeing buffer: ", P)
                    del globals.active_buffers[P]
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

            if P in globals.freed_set:
                utils.print_vuln('double free', 'ExFreePool2 - buffer already freed', self.state, {'P': str(P), 'Tag': str(Tag)}, {'return address': hex(self.state.callstack.ret_addr)})
            else:
                # Add to freed set
                globals.freed_set.add(P)
                # Remove from active buffers

                if P in globals.active_buffers:
                    print("Freeing buffer: ", P)
                    del globals.active_buffers[P]
                    return
                


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
                
        # 3. Execute the actual memcpy behavior
        angr.procedures.SIM_PROCEDURES['libc']['memcpy'](cc=self.cc).execute(self.state, arguments=(dest, src, size))

        return 0
# VOID ProbeForRead(
#   [in] const volatile VOID *Address,
#   [in] SIZE_T              Length,
#   [in] ULONG               Alignment
# );
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
class HookProbeForWrite(angr.SimProcedure):
    def run(self, Address, Length, Alignment):
        if globals.phase == 2:
            if utils.tainted_buffer(Address):
                asts = [i for i in Address.recursive_children_asts]
                target_base = asts[0] if len(asts) > 1 else Address
                # ret_addr = hex(self.state.callstack.ret_addr)
                self.state.globals['tainted_ProbeForWrite'] += (str(target_base), )


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