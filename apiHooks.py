import angr
import claripy
import utils
import globals


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
            else:
                handles = dict(self.state.globals['open_section_handles'])
                if SectionHandle not in handles:
                    utils.print_vuln('map physical memory', 'ZwMapViewOfSection - unknown handle', self.state, {'SectionHandle': str(SectionHandle), 'ProcessHandle': str(ProcessHandle), 'BaseAddress': str(BaseAddress), 'CommitSize': str(CommitSize), 'ViewSize': str(ViewSize)}, {'return address': ret_addr})
                elif handles[SectionHandle] == '\\Device\\PhysicalMemory':
                    utils.print_vuln('map physical memory', 'ZwMapViewOfSection - map \\Device\\PhysicalMemory', self.state, {'SectionHandle': str(SectionHandle), 'ProcessHandle': str(ProcessHandle), 'BaseAddress': str(BaseAddress), 'CommitSize': str(CommitSize), 'ViewSize': str(ViewSize)}, {'return address': ret_addr})
        return 0


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