import argparse


import pefile
import capstone as Cs
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
import angr
import archinfo

project = None
cfg = None

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
                    print(f"0x{instruction.address:x}:\t{instruction.mnemonic:<8}\t{instruction.op_str}")

                instruction_list.append(instruction)
            print("-" * 50)

    return instruction_list, text_list


def analyze_driver(file_path):
    cfg = project.analyses.CFGFast()
    


    # Customize calling convention for the SimProcs.
    if project.arch.name == archinfo.ArchX86.name:
        mycc = angr.calling_conventions.SimCCStdcall(project.arch)
    else:
        mycc = angr.calling_conventions.SimCCMicrosoftAMD64(project.arch)

    print("This is the graph:", cfg.model.graph)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('path', type=str, help='dir (including subdirectory) or file path to the driver(s) to analyze')

    args = parser.parse_args()

    driver = args.path

    print(f"ANALYZING DRIVER: {driver}")
    instrs = disasm_file(driver)

    project = angr.Project(driver, auto_load_libs=False)

    analyze_driver(driver)