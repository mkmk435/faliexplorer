
import pefile
import capstone as Cs
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
import globals
import cle
from cle.backends.pe.relocation.generic import DllImport
from typing import Optional



#function that return list of instructions of .text
def disasm_file(file_path):

    instruction_list = []
    text_list = []
    print(f"[*] Analisi del file: {file_path}")
    
    try:
        # 1. Carica il file PE
        pe = pefile.PE(file_path)
    except Exception as e:
        print(f"[-] Errore nel caricamento del file PE: {e}")
        return

    # 2. Determina l'architettura per configurare Capstone
    # 0x014c è IMAGE_FILE_MACHINE_I386 (32-bit)
    # 0x8664 è IMAGE_FILE_MACHINE_AMD64 (64-bit)

    if pe.FILE_HEADER.Machine == 0x014c:
        md = Cs(CS_ARCH_X86, CS_MODE_32)
        print("[*] Architettura: x86 (32-bit)")
    elif pe.FILE_HEADER.Machine == 0x8664:
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        print("[*] Architettura: x64 (64-bit)")
    else:
        print("[-] Architettura non supportata da questo script base.")
        return

    md.skipdata = True


    # 3. Cerca le sezioni eseguibili
    # Non diamo per scontato che si chiami ".text", controlliamo i permessi
    IMAGE_SCN_MEM_EXECUTE = 0x20000000

    for section in pe.sections:
        # Operazione bit-a-bit per verificare se la sezione ha il flag di esecuzione
        if section.Characteristics & IMAGE_SCN_MEM_EXECUTE:
            # Pulisce il nome della sezione dai byte nulli
            sec_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
            
            print(f"\n[+] Trovata sezione eseguibile: {sec_name}")
            
            # 4. Estrai i byte grezzi (raw bytes) dalla sezione
            code_bytes = section.get_data()
            
            # 5. Calcola l'indirizzo di memoria reale (ImageBase + VirtualAddress)
            base_address = pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress
            print(f"[+] Indirizzo base per la disassemblatura: {hex(base_address)}")
            print("-" * 50)
            
            # 6. Disassembla con Capstone
            count = 0
            for instruction in md.disasm(code_bytes, base_address):
                if 'text' in sec_name:
                    text_list.append(instruction)
                    # Stampa l'indirizzo, il mnemonico (es. MOV, JMP) e gli operandi
                    print(f"0x{instruction.address:x}:\t{instruction.mnemonic}\t{instruction.op_str}")

                instruction_list.append(instruction)
            print("-" * 50)

    return instruction_list, text_list


def print_debug(msg):
    if globals.args.debug:
        print(f'[Debug] {msg}\n')


def print_vuln(title, description, state, parameters, others):
    # Validate the address.
    if state.addr < 0x1337:
        return

    data = {}
    data['title'] = f'{title}'
    data['description'] = f'{description}'
    data['state'] = str(state)
    data['parameters'] = parameters

    IoControlCode = None 
    vuln_nnuple = None
    if (globals.IoControlCode is None):
        vuln_nnuple = (title, state.addr)
    else:
        IoControlCode = hex(state.solver.eval(globals.IoControlCode))
        vuln_nnuple = (title, state.addr, str(IoControlCode))
        # Evaluate the target buffers.
        SystemBuffer = hex(state.solver.eval(globals.SystemBuffer))
        Type3InputBuffer = hex(state.solver.eval(globals.Type3InputBuffer))
        UserBuffer = hex(state.solver.eval(globals.UserBuffer))
        InputBufferLength = hex(state.solver.eval(globals.InputBufferLength))
        OutputBufferLength = hex(state.solver.eval(globals.OutputBufferLength))
    
        # Set the information of the vulnerability.
        data['eval'] = {'IoControlCode': IoControlCode, 'SystemBuffer': SystemBuffer, 'Type3InputBuffer': Type3InputBuffer, 'UserBuffer': UserBuffer, 'InputBufferLength': InputBufferLength, 'OutputBufferLength': OutputBufferLength}
    
    
    if vuln_nnuple in globals.vulns_unique:
        return
    
    globals.vulns_unique.add((title, state.addr))
   
    data['others'] = others
    if 'tainted_ProbeForRead' in state.globals and len(state.globals['tainted_ProbeForRead']) > 0:
        data['others']['ProbeForRead'] = state.globals['tainted_ProbeForRead']
    if 'tainted_ProbeForWrite' in state.globals and len(state.globals['tainted_ProbeForWrite']) > 0:
        data['others']['ProbeForWrite'] = state.globals['tainted_ProbeForWrite']
    if 'tainted_MmIsAddressValid' in state.globals and len(state.globals['tainted_MmIsAddressValid']) > 0:
        data['others']['MmIsAddressValid'] = state.globals['tainted_MmIsAddressValid']
    
    print(json.dumps(data, indent=4), '\n')
    globals.vulns_info.append(data)


# Function that takes in input a symbolic expression object (ex. an expression). it basically takes an expr as input (for example i pass a register) and checks 
# if the value of that register is also contained inside 
def tainted_buffer(s):
    # The tainted buffer contains only one symbolic variable.
    if len(s.variables) != 1:
        return ''
    
    # Check the tainted symbolic variable. si perche' se creo
    s = str(s)
    if 'SystemBuffer' in s:
        return 'SystemBuffer'
    elif 'Type3InputBuffer' in s:
        return 'Type3InputBuffer'
    elif 'UserBuffer' in s:
        return 'UserBuffer'
    elif 'InputBufferLength' in s:
        return 'InputBufferLength'
    elif 'OutputBufferLength' in s:
        return 'OutputBufferLength'
    else:
        return ''


# genera degli indirizzi virtuali non sovrapposti
def next_base_addr(size=0x10000):
    v = globals.FIRST_ADDR
    globals.FIRST_ADDR += size
    return v


def resolve_import_symbol_in_object(pe_object: cle.backends.pe.pe.PE, symbol_name: str) -> Optional[int]:
    if symbol_name not in pe_object.imports:
        return None
    
    sym_import: DllImport = pe_object.imports[symbol_name]
    return pe_object.min_addr + sym_import.relative_addr

def resolve_import_symbol(loader: cle.loader.Loader, symbol_name: str) -> Optional[int]:
    for obj in loader.all_objects:
       result = resolve_import_symbol_in_object(obj, symbol_name)
       if result:
            return result
    
    return None