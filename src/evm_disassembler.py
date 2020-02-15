#!/usr/bin/python3
import sys
import queue
import evm

if __name__ == '__main__':
    data = bytes.fromhex(input('>> '))

    vm = evm.evm(data)
    vm.recursive_run()
    vm.linear_run()
    vm.label_jumpdest()

    instructions = sorted(vm.visited.items())
    with open('output', 'w') as output:
        output.write('Functions:\n')
        func_list = sorted(vm.func_list.items())
        for func, func_info in func_list:
            output.write(
                '  func_{:04x}: num_args = {}, num_retval = {}\n'.format(func, func_info[0], func_info[1]))
            for ret in func_info[2]:
                if ret is None:
                    if func_info[1] == 0:
                        output.write('    NO RETURN(entry function)\n')
                    else:
                        output.write('    RETURN(contract function)\n')
                else:
                    output.write('    returns to 0x{:04x}\n'.format(ret))

            output.write('\n')

        output.write('----------------------\n')
        output.write('Disassembly:\n')
        output.write('LABEL_0000:\n')
        for addr, inst in instructions:
            if addr in vm.blocks:
                output.write('\nLABEL_{:04X}:\n'.format(addr))
                for incoming in vm.blocks[addr]:
                    if incoming[0] is not None:
                        output.write(
                            '// Incoming from 0x{:04x}'.format(incoming[0]))
                        if incoming[1] is not None:
                            output.write(', If {}'.format(incoming[1]))
                        output.write('\n')

                if addr in vm.func_input:
                    output.write(
                        '// Inputs[{}]\n'.format(len(vm.func_input[addr])))
                    for i, arg in enumerate(reversed(vm.func_input[addr])):
                        if type(arg) == int:
                            output.write(
                                '//   stack[{}] = {}\n'.format(-(i+1), hex(arg)))
                        else:
                            output.write(
                                '//   stack[{}] = {}\n'.format(-(i+1), arg))

            output.write('  0x{:04x}: {}\n'.format(addr, inst))
