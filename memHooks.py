import claripy
import globals
import utils

def b_mem_read(state):
    # utils.print_debug(f'mem_read {state}, {state.inspect.mem_read_address}, {state.inspect.mem_read_expr}, {state.inspect.mem_read_length}, {state.inspect.mem_read_condition}')
    
    try:
        # Iterate all target buffers.
        for target in globals.NPD_TARGETS:
            if target in str(state.inspect.mem_read_address):
                asts = [i for i in state.inspect.mem_read_address.children_asts()]
                target_base = asts[0] if len(asts) > 1 else state.inspect.mem_read_address
                vars = state.inspect.mem_read_address.variables

                tainted_ProbeForRead = state.globals.get('tainted_ProbeForRead', set())
                tainted_ProbeForWrite = state.globals.get('tainted_ProbeForWrite', set())
                tainted_MmIsAddressValid = state.globals.get('tainted_MmIsAddressValid', set())

                if str(target_base) not in tainted_ProbeForRead and str(target_base) not in tainted_ProbeForWrite and len(vars) == 1:
                    # Add constraints to test whether the pointer is null or not.
                    tmp_state = state.copy()
                    if target == 'SystemBuffer':
                        if '*' in str(state.inspect.mem_read_address):
                            # If SystemBuffer is a pointer, check whether it is controllable.
                            tmp_state.solver.add(tmp_state.inspect.mem_read_address == 0x87)
                            if tmp_state.satisfiable() and str(target_base) not in tainted_MmIsAddressValid:
                                utils.print_vuln('read/write controllable address', 'read', state, {}, {'read from': str(state.inspect.mem_read_address)})
                        else:
                            # If SystemBuffer is not a pointer, check whether it can be null.
                            tmp_state.solver.add(globals.SystemBuffer == 0)
                            tmp_state.solver.add(globals.InputBufferLength == 0)
                            tmp_state.solver.add(globals.OutputBufferLength == 0)
                            if tmp_state.satisfiable() and str(target_base) not in tainted_MmIsAddressValid:
                                utils.print_vuln('null pointer dereference - input buffer', 'read input buffer', state, {}, {'read from': str(state.inspect.mem_read_address)})
                    elif target == 'Type3InputBuffer' or target == 'UserBuffer':
                        # If Type3InputBuffer or UserBuffer is a pointer, check whether it is controllable.
                        if target == 'Type3InputBuffer':
                            tmp_state.solver.add(globals.Type3InputBuffer == 0x87)
                        elif target == 'UserBuffer':
                            tmp_state.solver.add(globals.UserBuffer == 0x87)

                        if tmp_state.satisfiable() and str(target_base) not in tainted_MmIsAddressValid:
                            utils.print_vuln('read/write controllable address', 'read', state, {}, {'read from': str(state.inspect.mem_read_address)})
                    else:
                        # Only detect the allocated memory in case of false positive.
                        if '+' in str(tmp_state.inspect.mem_read_address):
                            return
                        tmp_state.solver.add(tmp_state.inspect.mem_read_address == 0)
                        if tmp_state.satisfiable():
                            utils.print_vuln('null pointer dereference - allocated memory', 'read allocated memory', state, {}, {'read from': str(state.inspect.mem_read_address)})

                # We symbolize the address of the tainted buffer because we want to detect the vulnerability when the driver reads/writes to/from the buffer.
                if utils.tainted_buffer(target_base) and str(target_base) not in state.globals:
                    tmp_state = state.copy()
                    tmp_state.solver.add(target_base == globals.FIRST_ADDR)
                    if not tmp_state.satisfiable():
                        break

                    state.globals[str(target_base)] = True
                    mem = claripy.BVS(f'*{str(target_base)}', 8 * 0x200).reversed
                    addr = utils.next_base_addr()
                    state.solver.add(target_base == addr)
                    state.memory.store(addr, mem, 0x200, disable_actions=True, inspect=False)
    except Exception:
        pass

def b_mem_write(state):
    # utils.print_debug(f'mem_write {state}, {state.inspect.mem_write_address}, {state.inspect.mem_write_expr}, {state.inspect.mem_write_length}, {state.inspect.mem_write_condition}')

    try:
        # Iterate all target buffers.
        for target in globals.NPD_TARGETS:
            if target in str(state.inspect.mem_write_address):
                asts = [i for i in state.inspect.mem_write_address.children_asts()]
                # indirizzo base del buffer, preso dalla espressione
                target_base = asts[0] if len(asts) > 1 else state.inspect.mem_write_address
                vars = state.inspect.mem_write_address.variables

                tainted_ProbeForRead = state.globals.get('tainted_ProbeForRead', set())
                tainted_ProbeForWrite = state.globals.get('tainted_ProbeForWrite', set())
                tainted_MmIsAddressValid = state.globals.get('tainted_MmIsAddressValid', set())

                # controllo se indirizzo e' gia' tainted o controllabile
                if str(target_base) not in tainted_ProbeForRead and str(target_base) not in tainted_ProbeForWrite and len(vars) == 1:
                    # Add constraints to test whether the pointer is null or not.
                    tmp_state = state.copy()
                    
                    if target == 'SystemBuffer':
                        # check se si sta accedendo a qualcosa dereferenziato da system buffer
                        if '*' in str(state.inspect.mem_write_address):
                            # se scrivibile (controllo con semplice constraint a 0x87 se valida)
                            tmp_state.solver.add(tmp_state.inspect.mem_write_address == 0x87)
                            if tmp_state.satisfiable():
                                utils.print_vuln('read/write controllable address', 'write', state, {}, {'write to': str(state.inspect.mem_write_address)})
                        else:
                            # If SystemBuffer is not a pointer, check whether it can be null.
                            tmp_state.solver.add(globals.SystemBuffer == 0)
                            tmp_state.solver.add(globals.InputBufferLength == 0)
                            tmp_state.solver.add(globals.OutputBufferLength == 0)
                            if tmp_state.satisfiable() and str(target_base) not in tainted_MmIsAddressValid:
                                utils.print_vuln('null pointer dereference - input buffer', 'write input buffer', state, {}, {'write to': str(state.inspect.mem_write_address)})
                    elif target == 'Type3InputBuffer' or target == 'UserBuffer':
                        # If Type3InputBuffer or UserBuffer is a pointer, check whether it is controllable.
                        if target == 'Type3InputBuffer':
                            tmp_state.solver.add(globals.Type3InputBuffer == 0x87)
                        elif target == 'UserBuffer':
                            tmp_state.solver.add(globals.UserBuffer == 0x87)

                        if tmp_state.satisfiable():
                            utils.print_vuln('read/write controllable address', 'write', state, {}, {'write to': str(state.inspect.mem_write_address)})
                    else:
                        # Only detect the allocated memory in case of false positive.
                        if '+' in str(tmp_state.inspect.mem_write_address):
                            return
                        tmp_state.solver.add(tmp_state.inspect.mem_write_address == 0)
                        if tmp_state.satisfiable():
                            utils.print_vuln('null pointer dereference - allocated memory', 'write allocated memory', state, {}, {'write to': str(state.inspect.mem_write_address)})
                    
# We symbolize the address of the tainted buffer because we want to detect the vulnerability when the driver reads/writes to/from the buffer.
                if utils.tainted_buffer(target_base) and str(target_base) not in state.globals:
                    tmp_state = state.copy()
                    tmp_state.solver.add(target_base == globals.FIRST_ADDR)
                    if not tmp_state.satisfiable():
                        break
                    
                    state.globals[str(target_base)] = True
                    mem = claripy.BVS(f'*{str(target_base)}', 8 * 0x200).reversed
                    addr = utils.next_base_addr()
                    state.solver.add(target_base == addr)
                    state.memory.store(addr, mem, 0x200, disable_actions=True, inspect=False)
    except Exception:
        pass


def b_call(state):
    ret_addr = state.solver.eval(state.memory.load(state.regs.rsp, state.arch.bytes, endness=state.arch.memory_endness))
    # utils.print_debug(f'call: state: {state}, ret_addr: {hex(ret_addr)}, function addr: {state.inspect.function_address})')

    # Check if the function address to call is tainted.
    if utils.tainted_buffer(state.inspect.function_address):
        state.regs.rip = 0x1337
        # utils.print_vuln('arbitrary shellcode execution', '', state, {}, {'function address': str(state.inspect.function_address), 'return address': hex(ret_addr)})
        
    # If the number of function address evaluated is more than 1, skip the call.
    if len(state.solver.eval_upto(state.inspect.function_address, 2)) > 1:
        tmp_state = state.copy()
        tmp_state.regs.rip = globals.DO_NOTHING
        globals.simgr.deferred.append(tmp_state)
        return angr.SIM_PROCEDURES['stubs']['ReturnUnconstrained']().execute(state)