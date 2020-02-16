import evm

if __name__ == '__main__':
    vm = evm.evm(bytes.fromhex(input('>> ')))
    vm.recursive_run()
    vm.linear_run()

    with open('output', 'w') as output:
        output.write('FUNCTIONS:\n\n')
        for func, func_info in sorted(vm.func_list.items()):
            output.write(
                '  FUNC_{:04X}: NUM_ARGS = {}, NUM_RETVAL = {}\n'
                .format(func, func_info[0], func_info[1]))

        output.write(
            '----------------------\n'
            'DISASSEMBLED RESULT:'
        )
        for addr, inst in sorted(vm.visited.items()):
            if addr in vm.blocks:
                output.write('\n\nLABEL_{:04X}:'.format(addr))
                for xref in vm.blocks[addr]:
                    if xref[0] is not None:
                        output.write('\n  {}'.format(xref[0]))
                        if xref[1] is not None:
                            output.write(', if {}'.format(xref[1]))

            output.write('\n  0x{:04X}: {}'.format(addr, inst))
