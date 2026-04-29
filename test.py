import angr, claripy
proj = angr.Project('/bin/true')
state = proj.factory.entry_state()

# copy rsp to rbp
state.regs.rbp = state.regs.rsp

print(state.regs.rbp)

# store rdx to memory at 0x1000
state.mem[0x1000].uint64_t = state.regs.rdx

# dereference rbp
state.regs.rbp = state.mem[state.regs.rbp].uint64_t.resolved

# add rax, qword ptr [rsp + 8]
state.regs.rax += state.mem[state.regs.rsp + 8].uint64_t.resolved