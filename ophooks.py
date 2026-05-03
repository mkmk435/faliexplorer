import globals
import utils
import claripy

# hook per wrmsr The assembly instruction wrmsr uses registers ECX, EDX, and EAX to supply its parameters. 
# ECX MSR Index, EDX:EAX (valore 64 bit), EDX upper 32 bits e EAX lower 32 bits 
# It checks whether the three registers used by wrmsr are "tainted" – meaning each contains a symbolic expression derived from user input (e.g., a buffer from SystemBuffer)
def wrmsr_hook(state):
    # Check if we can control the parameters of wrmsr.

    # print("REGISTRI IN WRMSR Hook",state.regs.eax,state.regs.ecx,state.regs.edx)
    if utils.tainted_buffer(state.regs.eax) and utils.tainted_buffer(state.regs.ecx) and utils.tainted_buffer(state.regs.edx):
        # Check whether the regsiter is constrained.
        utils.print_vuln('WRMSR registers are tainted', '', state, {}, {})

        tmp_state = state.copy()
        # controlla se ecx e' scrivibile con alcuni registri msr utili 
        tmp_state.solver.add(claripy.Or(tmp_state.regs.ecx == 0x00000174, tmp_state.regs.ecx == 0x00000175, tmp_state.regs.ecx == 0x00000176, tmp_state.regs.ecx == 0xC0000081, tmp_state.regs.ecx == 0xC0000082, tmp_state.regs.ecx == 0xC0000083))

        if tmp_state.satisfiable():
            # utils.print_vuln('arbitrary wrmsr', '', state, {'Register': str(state.regs.ecx), 'Value': (str(state.regs.edx), str(state.regs.eax))}, {})    
            utils.print_vuln('arbitrary wrmsr', '', state, {'Register': str(state.regs.ecx), 'Value': (str(state.regs.edx), str(state.regs.eax))}, {})

#Read MSR specified by ECX into EDX:EAX.
def rdmsr_hook(state):
    # Check if we can control the parameters of rdmsr.
    if utils.tainted_buffer(state.regs.ecx):
        # Check whether the regsiter is constrained.
        utils.print_vuln('RDMSR registers are tainted', '', state, {}, {})

        tmp_state = state.copy()
        # controlla se ecx e' scrivibile con alcuni registri msr utili 
        tmp_state.solver.add(claripy.Or(tmp_state.regs.ecx == 0x00000174, tmp_state.regs.ecx == 0x00000175, tmp_state.regs.ecx == 0x00000176, tmp_state.regs.ecx == 0xC0000081, tmp_state.regs.ecx == 0xC0000082, tmp_state.regs.ecx == 0xC0000083))

        if tmp_state.satisfiable():
            # utils.print_vuln('arbitrary rdmsr', '', state, {'Register': str(state.regs.ecx)}, {})    
            utils.print_vuln('arbitrary rdmsr', '', state, {'Register': str(state.regs.ecx)}, {})

# Output byte from memory location specified in DS:(E)SI or RSI to I/O port specified in DX2.
def outs_hook(state):
    # print("REGISTRI IN OUTS Hook",state.regs.esi,state.regs.edx)
    if utils.tainted_buffer(state.regs.edx) and utils.tainted_buffer(state.regs.esi):
        tmp_state = state.copy()
        tmp_state.solver.add(tmp_state.regs.edx == 0xcf9)
        tmp_state.solver.add(tmp_state.regs.esi == 0xe)
        if tmp_state.satisfiable():
            utils.print_vuln('arbitrary outs vuln', '', state, {'I/O Port': str(state.regs.edx), 'Value': str(state.regs.esi)}, {})


# Instruction	Op/En	64-Bit Mode	Compat/Leg Mode	Description
# E6 ib	OUT imm8, AL	I	Valid	Valid	Output byte in AL to I/O port address imm8.
# E7 ib	OUT imm8, AX	I	Valid	Valid	Output word in AX to I/O port address imm8.
# E7 ib	OUT imm8, EAX	I	Valid	Valid	Output doubleword in EAX to I/O port address imm8.
# EE	OUT DX, AL	ZO	Valid	Valid	Output byte in AL to I/O port address in DX.
# EF	OUT DX, AX	ZO	Valid	Valid	Output word in AX to I/O port address in DX.
def out_hook(state):
    # print("REGISTRI IN OUT Hook",state.regs.dx)
    if utils.tainted_buffer(state.regs.edx) and utils.tainted_buffer(state.regs.eax):
        # check semplice se c'e' qualche limite sui valori di outb, 0xcf9 - 0xe fa riavviare il sistema
        tmp_state = state.copy()
        tmp_state.solver.add(tmp_state.regs.edx == 0xcf9)
        tmp_state.solver.add(tmp_state.regs.eax == 0xe)
        if tmp_state.satisfiable():
            utils.print_vuln('arbitrary out vuln', '', state, {'I/O Port': str(state.regs.edx), 'Value': str(state.regs.eax)}, {})