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
# controlla se oggetto e' stato simbolizzato e tainted, e simbolizza handle come bvs
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
            if utils.tainted_buffer(NumberOfBytes):
                utils.print_vuln('allocate pool', 'ExAllocatePoolWithTag - NumberOfBytes controllable', self.state, {'PoolType': str(PoolType), 'NumberOfBytes': str(NumberOfBytes), 'Tag': str(Tag)})

            ret_addr = hex(self.state.callstack.ret_addr)
            allocated_ptr = claripy.BVS(f'ExAllocatePoolWithTag_{ret_addr}', self.state.arch.bits)
            return allocated_ptr    
        else:
            return utils.next_base_addr()



# Per ora semplice hook che esegue la funzione memcpy originale
class HookMemcpy(angr.SimProcedure):
    def run(self, dest, src, size):
        angr.procedures.SIM_PROCEDURES['libc']['memcpy'](cc=self.cc).execute(self.state, arguments=(dest, src, size))

        return 0