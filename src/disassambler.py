from evm import Evm


def get_list_with_prefix(prefix, len):
    return ['{}{}'.format(prefix, i) for i in range(len)]


if __name__ == '__main__':
    vm = Evm(bytes.fromhex(input('>> ')))
    vm.recursive_run()
    vm.linear_run()

    with open('output', 'w') as output:
        output.write('FUNCTIONS:\n\n')
        for addr, info in sorted(vm.func_list.items()):
            output.write(
                '  FUNC_{:04X}({}) -> ({})\n'
                .format(
                    addr,
                    ', '.join(get_list_with_prefix('arg', info[0])),
                    ', '.join(get_list_with_prefix('r', info[1])),
                )
            )

        output.write(
            '\n---\n'
            'DISASSEMBLED RESULT:'
        )
        for addr, visited in sorted(vm.visited.items()):
            if addr in vm.blocks:
                output.write('\n\nLABEL_{:04X}:'.format(addr))
                for xref in vm.blocks[addr]:
                    if xref[0] is not None:
                        output.write('\n  {}'.format(xref[0]))
                        if xref[1] is not None:
                            output.write(', if {}'.format(xref[1]))

            output.write('\n  0x{:04X}: {}'.format(addr, visited[0]))
