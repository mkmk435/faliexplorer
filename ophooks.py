import globals
import utils
import claripy

# hook per wrmsr The assembly instruction wrmsr uses registers ECX, EDX, and EAX to supply its parameters. 
# ECX MSR Index, EDX:EAX (valore 64 bit), EDX upper 32 bits e EAX lower 32 bits 
# It checks whether the three registers used by wrmsr are "tainted" – meaning each contains a symbolic expression derived from user input (e.g., a buffer from SystemBuffer)
def wrmsr_hook(state):
    # Check if we can control the parameters of wrmsr.

    # print(f"Dentro wrmsr hook, ioctl: {hex(state.solver.eval(globals.IoControlCode))}")

    # print("Dentro wrmsr hook")

    # print("REGISTRI IN WRMSR Hook",state.regs.eax,state.regs.ecx,state.regs.edx)
    if utils.tainted_buffer(state.regs.eax) and utils.tainted_buffer(state.regs.ecx) and utils.tainted_buffer(state.regs.edx):
        # Check whether the regsiter is constrained.
        utils.print_vuln('WRMSR registers are tainted', '', state, {}, {})

        tmp_state = state.copy()
        # controlla se ecx e' scrivibile con alcuni registri msr utili 
        tmp_state.solver.add(claripy.Or(tmp_state.regs.ecx == 0x00000174, tmp_state.regs.ecx == 0x00000175, tmp_state.regs.ecx == 0x00000176, tmp_state.regs.ecx == 0xC0000081, tmp_state.regs.ecx == 0xC0000082, tmp_state.regs.ecx == 0xC0000083))

        if tmp_state.satisfiable():
            # utils.print_vuln('arbitrary wrmsr', '', state, {'Register': str(state.regs.ecx), 'Value': (str(state.regs.edx), str(state.regs.eax))}, {})    
            utils.print_vuln('arbitrary wrmsr', '', state, {}, {})