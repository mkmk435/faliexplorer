import claripy
import globals
import utils
import angr
import traceback

def b_mem_read(state):
    # utils.print_debug(f'mem_read {state}, {state.inspect.mem_read_address}, {state.inspect.mem_read_expr}, {state.inspect.mem_read_length}, {state.inspect.mem_read_condition}')
    
    try:
        # =====================================================================
        # Use-After-Free Detection
        # =====================================================================
        if globals.phase == 2:
            # check se il read_addr e' simbolico
            if state.inspect.mem_read_address.symbolic:
                read_addr = state.inspect.mem_read_address
                # print('free_buffers: ', state.globals.get('freed_buffers', ()))
                for freed_addr in state.globals.get('freed_buffers', ()):
                    print(f'read_addr: {read_addr} freed_addr: {freed_addr}')
                    if read_addr == freed_addr:
                        utils.print_vuln('use-after-free', 'read from freed memory', state, {}, {'read from': hex(read_addr)})
                        break
            
        # Iterate all target buffers.
        for target in globals.NPD_TARGETS:
            if target in str(state.inspect.mem_read_address):
                asts = [i for i in state.inspect.mem_read_address.children_asts()]
                target_base = asts[0] if len(asts) > 1 else state.inspect.mem_read_address
                vars = state.inspect.mem_read_address.variables

                tainted_ProbeForRead = state.globals.get('tainted_ProbeForRead', set())
                tainted_ProbeForWrite = state.globals.get('tainted_ProbeForWrite', set())
                tainted_MmIsAddressValid = state.globals.get('tainted_MmIsAddressValid', set())

                # Controllo che l'indirizzo non sia già stato validato da una ProbeForRead
                if str(target_base) not in tainted_ProbeForRead and str(target_base) not in tainted_ProbeForWrite and len(vars) == 1:
                    
                    # Creiamo lo stato temporaneo una sola volta per testare i constraint
                    tmp_state = state.copy()
                    
                    if target == 'SystemBuffer':
                        if '*' in str(state.inspect.mem_read_address):
                            # If SystemBuffer is a pointer, check whether the READ ADDRESS is controllable (Arbitrary Read).
                            tmp_state.solver.add(tmp_state.inspect.mem_read_address == 0x87)
                            if tmp_state.satisfiable() and str(target_base) not in tainted_MmIsAddressValid:
                                utils.print_vuln('read/write controllable address', 'read', state, {}, {'read from': str(state.inspect.mem_read_address)})

                        else:
                            # If SystemBuffer is not a pointer, check whether the base pointer can be null (NPD).
                            tmp_state.solver.add(globals.SystemBuffer == 0)
                            tmp_state.solver.add(globals.InputBufferLength == 0)
                            tmp_state.solver.add(globals.OutputBufferLength == 0)
                            if tmp_state.satisfiable() and str(target_base) not in tainted_MmIsAddressValid:
                                utils.print_vuln('null pointer dereference - input buffer', 'read input buffer', state, {}, {'read from': str(state.inspect.mem_read_address)})
                    
                    elif target in ('Type3InputBuffer', 'UserBuffer'):
                        # Arbitrary Read: Controlliamo se L'INDIRIZZO DA CUI SI LEGGE è controllabile (esattamente come nel write)
                        tmp_state.solver.add(tmp_state.inspect.mem_read_address == 0x87)

                        if tmp_state.satisfiable() and str(target_base) not in tainted_MmIsAddressValid:
                            utils.print_vuln('read/write controllable address', 'read', state, {}, {'read from': str(state.inspect.mem_read_address)})
                        
                        else:
                            # Test opzionale ma utile: Null Pointer Dereference per i buffer utente
                            tmp_state2 = state.copy()
                            tmp_state2.solver.add(tmp_state2.inspect.mem_read_address == 0)
                            if tmp_state2.satisfiable() and str(target_base) not in tainted_MmIsAddressValid:
                                utils.print_vuln('null pointer dereference - input buffer', 'read input buffer', state, {}, {'read from': str(state.inspect.mem_read_address)})

                    else:
                        # Only detect the allocated memory in case of false positive.
                        if '+' in str(tmp_state.inspect.mem_read_address):
                            return # Nota: return interrompe l'analisi degli altri target, se vuoi solo saltare usa 'continue'
                        
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
                    
    except Exception as e:
        # print(f"Exception in b_mem_read: {e}") # Decommenta in caso di problemi per vedere l'errore
        pass

# def b_mem_write(state):
#     # utils.print_debug(f'mem_write {state}, {state.inspect.mem_write_address}, {state.inspect.mem_write_expr}, {state.inspect.mem_write_length}, {state.inspect.mem_write_condition}')

#     try:
#         # Iterate all target buffers.
#         for target in globals.NPD_TARGETS:
#             # print(state.inspect.mem_write_address)
#             if target in str(state.inspect.mem_write_address):
#                 asts = [i for i in state.inspect.mem_write_address.children_asts()]
#                 # indirizzo base del buffer, preso dalla espressione
#                 target_base = asts[0] if len(asts) > 1 else state.inspect.mem_write_address
#                 vars = state.inspect.mem_write_address.variables

#                 value_being_written = state.solver.eval(state.inspect.mem_write_expr)
#                 print(value_being_written)
                
#                 tainted_ProbeForRead = state.globals.get('tainted_ProbeForRead', set())
#                 tainted_ProbeForWrite = state.globals.get('tainted_ProbeForWrite', set())
#                 tainted_MmIsAddressValid = state.globals.get('tainted_MmIsAddressValid', set())

#                 # controllo se indirizzo e' gia' tainted o controllabile
#                 #   if str(target_base) not in tainted_ProbeForRead and str(target_base) not in tainted_ProbeForWrite and len(vars) == 1:
#                 if len(vars) == 1:

#                     # Add constraints to test whether the pointer is null or not.
#                     tmp_state = state.copy()
#                     tmp_state2 = state.copy()
#                     if target == 'SystemBuffer':
#                         # check se si sta accedendo a qualcosa dereferenziato da system buffer
#                         if '*' in str(state.inspect.mem_write_address):
                            
#                             # se scrivibile (controllo con semplice constraint a 0x87 se valida)
#                             tmp_state.solver.add(tmp_state.inspect.mem_write_address == 0x87)
#                             tmp_state2.solver.add((tmp_state2.inspect.mem_write_address == 0x87))
#                             if tmp_state.satisfiable():
#                                 tmp_state.solver.add(tmp_state.inspect.mem_write_expr == 0x87)
#                                 if tmp_state.satisfiable():
#                                     utils.print_vuln('read/write controllable address', 'write', state, {}, {'write to': str(state.inspect.mem_write_address)})
#                                 else:
#                                     tmp_state2.solver.add(tmp_state2.inspect.mem_write_expr == 0x00)
#                                     if tmp_state2.satisfiable():
#                                         utils.print_vuln('Write NULL on controllable address', 'write', state, {}, {'write to': str(state.inspect.mem_write_address)})
                        
#                         else:
#                             # If SystemBuffer is not a pointer, check whether it can be null.
#                             tmp_state.solver.add(globals.SystemBuffer == 0)
#                             tmp_state.solver.add(globals.InputBufferLength == 0)
#                             tmp_state.solver.add(globals.OutputBufferLength == 0)
#                             if tmp_state.satisfiable() and str(target_base) not in tainted_MmIsAddressValid:
#                                 utils.print_vuln('null pointer dereference - input buffer', 'write input buffer', state, {}, {'write to': str(state.inspect.mem_write_address)})
#                     # niente check * perche' si usano con METHOD_NEITHER, quindi sono gia' puntatori User Mode
#                         # If Type3InputBuffer or UserBuffer is a pointer, check whether it is controllable.
#                     elif target == 'Type3InputBuffer':
#                         print("Type3InputBuffer - Address : ", target_base)
#                         tmp_state.solver.add(globals.Type3InputBuffer == 0x87)
#                         tmp_state2.solver.add(tmp_state2.inspect.mem_write_expr == 0x00)
#                     elif target == 'UserBuffer':
#                         tmp_state.solver.add(globals.UserBuffer == 0x87)
#                         tmp_state2.solver.add(tmp_state2.inspect.mem_write_expr == 0x00)

#                     if tmp_state.satisfiable():
#                         utils.print_vuln('read/write controllable address', 'write', state, {}, {'write to': str(state.inspect.mem_write_address)})
#                     elif tmp_state2.satisfiable():
#                         utils.print_vuln('Write NULL on controllable address', 'write', state, {}, {'write to': str(state.inspect.mem_write_address)})
#                 else:
#                     # Only detect the allocated memory in case of false positive.
#                     if '+' in str(tmp_state.inspect.mem_write_address):
#                         return
#                     tmp_state.solver.add(tmp_state.inspect.mem_write_address == 0)
#                     if tmp_state.satisfiable():
#                         utils.print_vuln('null pointer dereference - allocated memory', 'write allocated memory', state, {}, {'write to': str(state.inspect.mem_write_address)})
                    
# # We symbolize the address of the tainted buffer because we want to detect the vulnerability when the driver reads/writes to/from the buffer.
#                 if utils.tainted_buffer(target_base) and str(target_base) not in state.globals:
#                     tmp_state = state.copy()
#                     tmp_state.solver.add(target_base == globals.FIRST_ADDR)
#                     if not tmp_state.satisfiable():
#                         break
                    
#                     state.globals[str(target_base)] = True
#                     mem = claripy.BVS(f'*{str(target_base)}', 8 * 0x200).reversed
#                     addr = utils.next_base_addr()
#                     state.solver.add(target_base == addr)
#                     state.memory.store(addr, mem, 0x200, disable_actions=True, inspect=False)
#     except Exception:
#         pass
def b_mem_write(state):
    # utils.print_debug(f'mem_write {state}, {state.inspect.mem_write_address}, {state.inspect.mem_write_expr}, {state.inspect.mem_write_length}, {state.inspect.mem_write_condition}')

    try:
        # Iterate all target buffers.
        for target in globals.NPD_TARGETS:
            if target in str(state.inspect.mem_write_address):
                asts = [i for i in state.inspect.mem_write_address.children_asts()]
                # Indirizzo base del buffer, preso dalla espressione
                target_base = asts[0] if len(asts) > 1 else state.inspect.mem_write_address
                vars = state.inspect.mem_write_address.variables

                # Decommenta se ti serve il debug del valore scritto
                # value_being_written = state.solver.eval(state.inspect.mem_write_expr)
                # print(value_being_written)
                
                tainted_ProbeForRead = state.globals.get('tainted_ProbeForRead', set())
                tainted_ProbeForWrite = state.globals.get('tainted_ProbeForWrite', set())
                tainted_MmIsAddressValid = state.globals.get('tainted_MmIsAddressValid', set())

                # Controllo se indirizzo e' gia' tainted o controllabile
                if str(target_base) not in tainted_ProbeForWrite and len(vars) == 1:
                # if len(vars) == 1:

                    # Add constraints to test whether the pointer is null or not.
                    tmp_state = state.copy()
                    tmp_state2 = state.copy()
                    tmp_state3 = state.copy()
                    if target == 'SystemBuffer':
                        # Check se si sta accedendo a qualcosa dereferenziato da system buffer
                        if '*' in str(state.inspect.mem_write_address):
                            # Se scrivibile (controllo con semplice constraint a 0x87 se valida)
                            tmp_state.solver.add(tmp_state.inspect.mem_write_address == 0x87)
                            tmp_state2.solver.add(tmp_state2.inspect.mem_write_address == 0x87)
                            
                            if tmp_state.satisfiable():
                                tmp_state.solver.add(tmp_state.inspect.mem_write_expr == 0x87)
                                if tmp_state.satisfiable():
                                    utils.print_vuln('read/write controllable address', 'write', state, {}, {'write to': str(state.inspect.mem_write_address)})
                                else:
                                    tmp_state2.solver.add(tmp_state2.inspect.mem_write_expr == 0x00)
                                    if tmp_state2.satisfiable():
                                        utils.print_vuln('Write NULL on controllable address', 'write', state, {}, {'write to': str(state.inspect.mem_write_address)})

                        else:
                            # If SystemBuffer is not a pointer, check whether it can be null.
                            tmp_state.solver.add(globals.SystemBuffer == 0)
                            tmp_state.solver.add(globals.InputBufferLength == 0)
                            tmp_state.solver.add(globals.OutputBufferLength == 0)
                            if tmp_state.satisfiable() and str(target_base) not in tainted_MmIsAddressValid:
                                utils.print_vuln('null pointer dereference - input buffer', 'write input buffer', state, {}, {'write to': str(state.inspect.mem_write_address)})
                    
                    # Niente check '*' perche' si usano con METHOD_NEITHER, quindi sono gia' puntatori User Mode
                    elif target in ('Type3InputBuffer', 'UserBuffer'):
                        # if target == 'Type3InputBuffer':
                        #     # print("Type3InputBuffer - Address : ", target_base)
                        #     target_global = globals.Type3InputBuffer
                        # else:
                        #     target_global = globals.UserBuffer

                        # # 1. Controlliamo se l'indirizzo è controllabile (Arbitrary Write)
                        # tmp_state.solver.add(target_global == 0x87)
                        # tmp_state2.solver.add(target_global == 0x87)

                        if tmp_state.satisfiable():
                            # Se l'indirizzo è controllabile, testiamo se il VALORE è controllabile (WWW)
                            tmp_state.solver.add(tmp_state.inspect.mem_write_expr == 0x87)
                            
                            if tmp_state.satisfiable():
                                utils.print_vuln('read/write controllable address', 'write', state, {}, {'write to': str(state.inspect.mem_write_address)})
                            else:
                                # Se il valore non è arbitrario, testiamo se almeno possiamo scriverci NULL
                                tmp_state2.solver.add(tmp_state2.inspect.mem_write_expr == 0x00)
                                if tmp_state2.satisfiable():
                                    utils.print_vuln('Write NULL on controllable address', 'write', state, {}, {'write to': str(state.inspect.mem_write_address)})

                else:
                    # Only detect the allocated memory in case of false positive.
                    tmp_state = state.copy() # Definiamo lo stato qui per evitare crash in questo ramo
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
                    
    except Exception as e:
        # È buona norma printare l'eccezione in debug, decommentala se si rompe qualcosa silenziosamente
        # print(f"Exception in b_mem_write: {e}")
        pass



def b_call(state):
    ret_addr = state.solver.eval(state.memory.load(state.regs.rsp, state.arch.bytes, endness=state.arch.memory_endness))
    # utils.print_debug(f'call: state: {state}, ret_addr: {hex(ret_addr)}, function addr: {state.inspect.function_address})')

    # Check if the function address to call is tainted.
    if utils.tainted_buffer(state.inspect.function_address):
        state.regs.rip = 0x1337
        utils.print_vuln('arbitrary shellcode execution', '', state, {}, {'function address': str(state.inspect.function_address), 'return address': hex(ret_addr)})
    
    # If the number of function address evaluated is more than 1, skip the call.
    if len(state.solver.eval_upto(state.inspect.function_address, 2)) > 1:
        tmp_state = state.copy()
        tmp_state.regs.rip = globals.DO_NOTHING
        globals.simgr.deferred.append(tmp_state)
        return angr.SIM_PROCEDURES['stubs']['ReturnUnconstrained']().execute(state)

def inspect_args_hook(state):
    # # 1. Get the default calling convention for the binary's architecture
    # # cc = state.project.factory.cc()
    
    # # print(f"\n--- Intercepted Call at {hex(state.addr)} ---")
    
    # # ---------------------------------------------------------
    # # PART A: Read Register-Based Arguments (x86_64, ARM, MIPS)
    # # ---------------------------------------------------------
    # # cc.ARG_REGS contains the ordered list of registers used for arguments.
    # # We dump them all since we don't know the exact function signature.
    # if hasattr(globals.cc, 'ARG_REGS') and globals.cc.ARG_REGS:
    #     for i, reg_name in enumerate(globals.cc.ARG_REGS):
    #         # getattr dynamically fetches state.regs.rdi, state.regs.r0, etc.
    #         val = getattr(state.regs, reg_name)
    #         print(f"Reg Arg {i} ({reg_name}): {val}")
            
    # # ---------------------------------------------------------
    # # PART B: Read Stack-Based Arguments (x86 cdecl, or spillover)
    # # ---------------------------------------------------------
    # # Because the 'call' hasn't executed, the stack pointer (SP) 
    # # points EXACTLY to the first stack argument (no return address offset).
    # word_size = state.arch.bytes
    # sp = state.regs.sp
    
    # # Read the first 4 words from the stack as a fallback
    # for i in range(4):
    #     # Calculate address: sp + 0, sp + 4, sp + 8, etc.
    #     arg_addr = sp + (i * word_size)
        
    #     # Load the value respecting the architecture's endianness
    #     val = state.memory.load(arg_addr, word_size, endness=state.arch.memory_endness)
    #     print(f"Stack Arg {i} [@ {arg_addr}]: {val}")
    pass


def b_write_ioctl_handler(state):
        # Store the address of ioctl handler when writing into the memory.
    ioctl_handler_addr = state.solver.eval(state.inspect.mem_write_expr)
    globals.ioctl_handler = ioctl_handler_addr
    state.globals['ioctl_handler'] = ioctl_handler_addr
    globals.simgr.move(from_stash='deadended', to_stash='_Drop')

def b_mem_write_DriverStartIo(state):
    # Store the address of DriverStartIo when writing into the memory.
    DriverStartIo_addr = state.solver.eval(state.inspect.mem_write_expr)
    globals.DriverStartIo = int(DriverStartIo_addr)
    globals.basic_info['DriverStartIo'] = hex(globals.DriverStartIo)
    print(f'DriverStartIo: {hex(globals.DriverStartIo)}')