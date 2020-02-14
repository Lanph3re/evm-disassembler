#!/usr/bin/python3
import sys
import queue
import evm

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print('usage: python {} <data>'.format(sys.argv[0]))
        exit(1)

    data = open(sys.argv[1], 'rb').read()
    vm = evm.evm(data)
    vm.queue.put(0)

    while not vm.queue.empty():
        vm.recursive_run(vm.queue.get())
    vm.linear_run()
    vm.label_jumpdest()

    result = sorted(vm.visited.items())
    with open('output', 'w') as output:
        output.write('Functions:\n')
        func_list = sorted(vm.func_list.items())
        for func, func_info in func_list:
            output.write(
                '\t0x{:04x}, num_args = {}, num_retval = {}\n'.format(func, func_info[0], func_info[1]))
            for ret in func_info[2]:
                if ret is None:
                    if func_info[1] == 0:
                        output.write('\t\tno returns(entry function)\n')
                    else:
                        output.write('\t\tRETURN(contract function)\n')
                else:
                    output.write('\t\treturns to 0x{:04x}\n'.format(ret))
            output.write('\n')

        output.write('----------------------\n')
        output.write('Disassembly:')
        output.write('\nlabel_0000:\n')
        for addr, inst in result:
            if addr in vm.blocks:
                output.write('\nlabel_{:04X}:\n'.format(addr))
                if addr in vm.func_input:
                    output.write(
                        "// Inputs[{}]\n".format(len(vm.func_input[addr])))
                    for i, arg in enumerate(vm.func_input[addr]):
                        output.write("//\t stack[{}] = {}\n".format(i, arg))
                for incoming in vm.blocks[addr]:
                    if incoming[0] is not None:
                        output.write(
                            '// Incoming from 0x{:04x}'.format(incoming[0]))
                    if incoming[1] is not None:
                        output.write(', If {}\n'.format(incoming[1]))
            output.write('\t0x{:04x}: {}\n'.format(addr, inst))