import queue
import struct
import copy


class evm:
    # opcode mnemonics
    table = {
        0: '*STOP', 1: 'ADD', 2: 'MUL', 3: 'SUB', 4: 'DIV', 5: 'SDIV', 6: 'MOD', 7: 'SMOD', 8: 'ADDMOD',
        9: 'MULMOD', 10: 'EXP', 11: 'SIGNEXTEND', 16: 'LT', 17: 'GT', 18: 'SLT', 19: 'SGT', 20: 'EQ',
        21: 'ISZERO', 22: 'AND', 23: 'OR', 24: 'XOR', 25: 'NOT', 26: 'BYTE', 27: 'SHL', 28: 'SHR',
        29: 'SAR', 32: 'SHA3', 48: 'ADDRESS', 49: 'BALANCE', 50: 'ORIGIN', 51: 'CALLER', 52: 'CALLVALUE',
        53: 'CALLDATALOAD', 54: 'CALLDATASIZE', 55: 'CALLDATACOPY', 56: 'CODESIZE', 57: 'CODECOPY',
        58: 'GASPRICE', 59: 'EXTCODESIZE', 60: 'EXTCODECOPY', 61: 'RETURNDATASIZE', 62: 'RETURNDATACOPY',
        63: 'EXTCODEHASH', 64: 'BLOCKHASH', 65: 'COINBASE', 66: 'TIMESTAMP', 67: 'NUMBER', 68: 'DIFFICULTY',
        69: 'GASLIMIT', 80: 'POP', 81: 'MLOAD', 82: 'MSTORE', 83: 'MSTORE8', 84: 'SLOAD', 85: 'SSTORE',
        86: '*JUMP', 87: '*JUMPI', 88: 'PC', 89: 'MSIZE', 90: 'GAS', 91: 'JUMPDEST', 96: 'PUSH1', 97: 'PUSH2',
        98: 'PUSH3', 99: 'PUSH4', 100: 'PUSH5', 101: 'PUSH6', 102: 'PUSH7', 103: 'PUSH8', 104: 'PUSH9',
        105: 'PUSH10', 106: 'PUSH11', 107: 'PUSH12', 108: 'PUSH13', 109: 'PUSH14', 110: 'PUSH15', 111: 'PUSH16',
        112: 'PUSH17', 113: 'PUSH18', 114: 'PUSH19', 115: 'PUSH20', 116: 'PUSH21', 117: 'PUSH22', 118: 'PUSH23',
        119: 'PUSH24', 120: 'PUSH25', 121: 'PUSH26', 122: 'PUSH27', 123: 'PUSH28', 124: 'PUSH29', 125: 'PUSH30',
        126: 'PUSH31', 127: 'PUSH32', 128: 'DUP1', 129: 'DUP2', 130: 'DUP3', 131: 'DUP4', 132: 'DUP5', 133: 'DUP6',
        134: 'DUP7', 135: 'DUP8', 136: 'DUP9', 137: 'DUP10', 138: 'DUP11', 139: 'DUP12', 140: 'DUP13', 141: 'DUP14',
        142: 'DUP15', 143: 'DUP16', 144: 'SWAP1', 145: 'SWAP2', 146: 'SWAP3', 147: 'SWAP4', 148: 'SWAP5', 149: 'SWAP6',
        150: 'SWAP7', 151: 'SWAP8', 152: 'SWAP9', 153: 'SWAP10', 154: 'SWAP11', 155: 'SWAP12', 156: 'SWAP13',
        157: 'SWAP14', 158: 'SWAP15', 159: 'SWAP16', 160: 'LOG0', 161: 'LOG1', 162: 'LOG2', 163: 'LOG3', 164: 'LOG4',
        176: 'PUSH', 177: 'DUP', 178: 'SWAP', 240: 'CREATE', 241: 'CALL', 242: 'CALLCODE', 243: '*RETURN',
        244: 'DELEGATECALL', 245: 'CREATE2', 250: 'STATICCALL', 253: '*REVERT', 254: '*ASSERT', 255: '*SELFDESTRUCT'
    }
    terminal = ['*STOP', '*RETURN', '*REVERT']
    jump_ops = ['*JUMP', '*JUMPI']

    def __init__(self, data):
        self.stack = []
        self.stack_idx = 0
        self.data = data
        self.pc = 0
        self.memory = {}
        self.queue = queue.Queue(maxsize=0)
        # key: start address of block
        # value: (from_address, cond)
        self.blocks = {}
        # key: disassembled address
        # value: disassembled instruction
        self.visited = {}
        # address that will be disassembled in linear disassemble algorithm
        self.fin_addrs = []
        self.func_input = {}
        self.func_memory_input = {}
        # key: address of function
        # value: [num_args, num_retval, [return_addr, ...]]
        self.func_list = {0x0: [0, 0, [None]]}
        self.opcodes_func = {
            0: self.stop, 1: self.add, 2: self.mul, 3: self.sub, 4: self.div, 5: self.sdiv, 6: self.mod, 7: self.smod, 8: self.addmod,
            9: self.mulmod, 10: self.exp, 11: self.signextend, 16: self.lt, 17: self.gt, 18: self.slt, 19: self.sgt, 20: self.eq,
            21: self.iszero, 22: self.evm_and, 23: self.evm_or, 24: self.xor, 25: self.evm_not, 26: self.byte, 27: self.shl, 28: self.shr,
            29: self.sar, 32: self.sha3, 48: self.address, 49: self.balance, 50: self.origin, 51: self.caller, 52: self.callvalue,
            53: self.calldataload, 54: self.calldatasize, 55: self.calldatacopy, 56: self.codesize, 57: self.codecopy,
            58: self.gasprice, 59: self.extcodesize, 60: self.extcodecopy, 61: self.returndatasize, 62: self.returndatacopy,
            63: self.extcodehash, 64: self.blockhash, 65: self.coinbase, 66: self.timestamp, 67: self.number, 68: self.difficulty,
            69: self.gaslimit, 80: self.pop, 81: self.mload, 82: self.mstore, 83: self.mstore8, 84: self.sload, 85: self.sstore,
            86: self.jump, 87: self.jumpi, 88: self.evm_pc, 89: self.msize, 90: self.gas, 91: self.jumpdest, 96: self.push, 97: self.push,
            98: self.push, 99: self.push, 100: self.push, 101: self.push, 102: self.push, 103: self.push, 104: self.push,
            105: self.push, 106: self.push, 107: self.push, 108: self.push, 109: self.push, 110: self.push, 111: self.push,
            112: self.push, 113: self.push, 114: self.push, 115: self.push, 116: self.push, 117: self.push, 118: self.push,
            119: self.push, 120: self.push, 121: self.push, 122: self.push, 123: self.push, 124: self.push, 125: self.push,
            126: self.push, 127: self.push, 128: self.dup, 129: self.dup, 130: self.dup, 131: self.dup, 132: self.dup, 133: self.dup,
            134: self.dup, 135: self.dup, 136: self.dup, 137: self.dup, 138: self.dup, 139: self.dup, 140: self.dup, 141: self.dup,
            142: self.dup, 143: self.dup, 144: self.swap, 145: self.swap, 146: self.swap, 147: self.swap, 148: self.swap, 149: self.swap,
            150: self.swap, 151: self.swap, 152: self.swap, 153: self.swap, 154: self.swap, 155: self.swap, 156: self.swap,
            157: self.swap, 158: self.swap, 159: self.swap, 160: self.log, 161: self.log, 162: self.log, 163: self.log, 164: self.log,
            176: self.push, 177: self.dup, 178: self.swap, 240: self.create, 241: self.call, 242: self.callcode, 243: self.evm_return,
            244: self.delegatecall, 245: self.create2, 250: self.staticcall, 253: self.revert, 254: self.evm_assert, 255: self.selfdestruct
        }

    # recursive traversal disassemble
    def recursive_run(self, pc):
        self.pc = pc
        self.stack_idx = 0
        self.stack = []

        while True:
            cur_op = self.data[self.pc]
            if self.pc in self.visited:
                return

            # skip invalid opcode
            if cur_op not in self.table:
                self.visited[self.pc] = '{:02x}'.format(cur_op)
                self.pc += 1
                continue

            # mark current address as visited
            inst = self.table[cur_op]
            self.visited[self.pc] = inst
            self.pc += 1

            # terminal instructions(stop, revert, return)
            if inst in self.terminal:
                self.stack_func(cur_op)
                # store instructions following terminal insts for future instrument
                self.fin_addrs.append(self.pc)
                return

            # execute current operation
            if inst.startswith('PUSH'):
                imm_width = int(inst[4:])
                imm_val = self.data[self.pc:self.pc + imm_width].hex()
                self.visited[self.pc - 1] += ' 0x{}'.format(imm_val)
                self.push(int(imm_val, 16))
                self.pc += imm_width
            elif inst not in self.jump_ops:
                self.stack_func(cur_op)
            else:
                pass

            if inst in self.jump_ops:
                if inst == '*JUMPI':
                    self.queue.put(self.pc)
                    jump_addr, condi = self.jumpi()
                    self.func_input[self.pc] = copy.deepcopy(self.stack)

                    # heuristic
                    # find entry point of each contract function
                    # using pattern 'PUSH4, ..., JUMPI'
                    if self.data[self.pc - 0xb] == 0x63 or self.data[self.pc - 0xa] == 0x63:
                        self.func_list[jump_addr] = [0, 1, [None]]

                    # mark instruction following 'JUMPI' as new block
                    if self.pc not in self.blocks:
                        self.blocks[self.pc] = [
                            ((self.pc - 1), " not " + condi)]
                    else:
                        self.blocks[self.pc].append(
                            ((self.pc - 1),  " not " + condi))

                    self.queue.put(jump_addr)
                    self.func_input[jump_addr] = copy.deepcopy(self.stack)

                    # mark destination of 'JUMPI' as new block
                    if jump_addr not in self.blocks:
                        self.blocks[jump_addr] = [((self.pc - 1), condi)]
                    else:
                        self.blocks[jump_addr].append(
                            ((self.pc - 1), condi))
                    self.stack = []
                else:
                    # 'JUMP'
                    jump_addr = self.jump()
                    self.func_input[self.pc] = copy.deepcopy(self.stack)
                    self.fin_addrs.append(self.pc)

                    # check if destination of 'JUMP' is address of function
                    if self.pc in self.stack:
                        ret_idx = self.stack.index(self.pc)
                        num_args = len(self.stack) - ret_idx - 1
                        if jump_addr not in self.func_list:
                            self.func_list[jump_addr] = [
                                num_args, 0, [self.pc]]
                        else:
                            self.func_list[jump_addr][2].append(self.pc)

                    # check if destination of 'JUMP' is return address
                    # and get number of return values.
                    # stack gets cleaned every 'JUMP' is executed,
                    # so assume size of stack when function return
                    # is the number of return values
                    for func_info in self.func_list.values():
                        if jump_addr in func_info[2]:
                            func_info[1] = len(self.stack)
                            if jump_addr not in self.blocks:
                                self.blocks[jump_addr] = [
                                    ((self.pc - 1), None)]
                            else:
                                self.blocks[jump_addr].append(
                                    ((self.pc - 1), None))

                    if type(jump_addr) != int:
                        self.stack = []
                        continue

                    self.queue.put(jump_addr)
                    self.func_input[jump_addr] = copy.deepcopy(self.stack)

                    # mark destination of 'JUMP' as new block
                    if jump_addr not in self.blocks:
                        self.blocks[jump_addr] = [((self.pc - 1), None)]
                    else:
                        self.blocks[jump_addr].append(
                            ((self.pc - 1), None))
                    self.stack = []

            if self.pc > len(self.data):
                return

    # do linear disassemble to find dead blocks
    def linear_run(self):
        for fin_addr in self.fin_addrs:
            self.pc = fin_addr
            while self.pc not in self.visited:
                cur_op = self.data[self.pc]

                # skip invalid opcode
                if cur_op not in self.table:
                    self.visited[self.pc] = '{:02x}'.format(cur_op)
                    self.pc += 1
                    continue

                inst = self.table[self.data[self.pc]]
                self.visited[self.pc] = inst
                self.pc += 1

                if inst.startswith('PUSH'):
                    imm_width = int(inst[4:])
                    imm_val = self.data[self.pc:self.pc + imm_width].hex()
                    self.visited[self.pc - 1] += ' 0x{}'.format(imm_val)
                    self.pc += imm_width

                if self.pc > len(self.data):
                    return

    # find unlabeled 'JUMPDEST' instructions
    def label_jumpdest(self):
        for i in range(len(self.data)):
            if self.data[i] not in self.table:
                continue
            if self.table[self.data[i]] == 'JUMPDEST' and i not in self.blocks:
                self.blocks[i] = [(None, None)]

    def stack_pop(self):
        if len(self.stack) == 0:
            self.stack_idx += 1
            return "stack[{}]".format(-self.stack_idx)
        return self.stack.pop()

    # stack related
    def stack_func(self, op):
        self.opcodes_func[op]()

    def stop(self):
        return

    def add(self):
        operand_1 = self.stack_pop()
        operand_2 = self.stack_pop()
        self.stack.append("{} + {}".format(operand_1, operand_2))

    def mul(self):
        operand_1 = self.stack_pop()
        operand_2 = self.stack_pop()
        self.stack.append("{} * {}".format(operand_1, operand_2))

    def sub(self):
        operand_1 = self.stack_pop()
        operand_2 = self.stack_pop()
        self.stack.append("{} - {}".format(operand_1, operand_2))

    def div(self):
        operand_1 = self.stack_pop()
        operand_2 = self.stack_pop()
        self.stack.append("{} / {}".format(operand_1, operand_2))

    def sdiv(self):
        operand_1 = self.stack_pop()
        operand_2 = self.stack_pop()
        self.stack.append("{} / {}".format(operand_1, operand_2))

    def mod(self):
        operand_1 = self.stack_pop()
        operand_2 = self.stack_pop()
        self.stack.append("{} % {}".format(operand_1, operand_2))

    def smod(self):
        operand_1 = self.stack_pop()
        operand_2 = self.stack_pop()
        self.stack.append("{} % {}".format(operand_1, operand_2))

    def addmod(self):
        operand_1 = self.stack_pop()
        operand_2 = self.stack_pop()
        operand_3 = self.stack_pop()
        self.stack.append(
            "({} + {}) % {}".format(operand_1, operand_2, operand_3))

    def mulmod(self):
        operand_1 = self.stack_pop()
        operand_2 = self.stack_pop()
        operand_3 = self.stack_pop()
        self.stack.append(
            "({} * {}) % {}".format(operand_1, operand_2, operand_3))

    def exp(self):
        operand_1 = self.stack_pop()
        operand_2 = self.stack_pop()
        self.stack.append("{} ** {}".format(operand_1, operand_2))

    def signextend(self):
        operand_1 = self.stack_pop()
        operand_2 = self.stack_pop()
        self.stack.append("{} ** {}".format(operand_1, operand_2))

    def lt(self):
        operand_1 = self.stack_pop()
        operand_2 = self.stack_pop()
        self.stack.append("{} < {}".format(operand_1, operand_2))

    def gt(self):
        operand_1 = self.stack_pop()
        operand_2 = self.stack_pop()
        self.stack.append("{} > {}".format(operand_1, operand_2))

    def slt(self):
        operand_1 = self.stack_pop()
        operand_2 = self.stack_pop()
        self.stack.append("{} < {}".format(operand_1, operand_2))

    def sgt(self):
        operand_1 = self.stack_pop()
        operand_2 = self.stack_pop()
        self.stack.append("{} > {}".format(operand_1, operand_2))

    def eq(self):
        operand_1 = self.stack_pop()
        operand_2 = self.stack_pop()
        self.stack.append("{} == {}".format(operand_1, operand_2))

    def iszero(self):
        operand_1 = self.stack_pop()
        self.stack.append("{} == 0".format(operand_1))

    def evm_and(self):
        operand_1 = self.stack_pop()
        operand_2 = self.stack_pop()
        self.stack.append("{} & {}".format(operand_1, operand_2))

    def evm_or(self):
        operand_1 = self.stack_pop()
        operand_2 = self.stack_pop()
        self.stack.append("{} | {}".format(operand_1, operand_2))

    def xor(self):
        operand_1 = self.stack_pop()
        operand_2 = self.stack_pop()
        self.stack.append("{} ^ {}".format(operand_1, operand_2))

    def evm_not(self):
        operand_1 = self.stack_pop()
        self.stack.append("~{}".format(operand_1))

    def byte(self):
        operand_1 = self.stack_pop()
        operand_2 = self.stack_pop()
        self.stack.append(
            "({} >> (248 - {} * 8)) & 0xFF)".format(operand_2, operand_1))

    def shl(self):
        operand_1 = self.stack_pop()
        operand_2 = self.stack_pop()
        self.stack.append("{} << {}".format(operand_1, operand_2))

    def shr(self):
        operand_1 = self.stack_pop()
        operand_2 = self.stack_pop()
        self.stack.append("{} >> {}".format(operand_1, operand_2))

    def sar(self):
        operand_1 = self.stack_pop()
        operand_2 = self.stack_pop()
        self.stack.append("{} >> {}".format(operand_1, operand_2))

    def sha3(self):
        operand_1 = self.stack_pop()
        operand_2 = self.stack_pop()
        self.stack.append("hash")

    def address(self):
        self.stack.append("address("+str(self.pc)+")")

    def balance(self):
        operand_1 = self.stack_pop()
        self.stack.append("address("+str(operand_1)+").balance")

    def origin(self):
        self.stack.append("tx.origin")

    def caller(self):
        self.stack.append("msg.caller")

    def callvalue(self):
        self.stack.append("msg.value")

    def calldataload(self):
        operand_1 = self.stack_pop()
        if(type(operand_1) == int):
            self.stack.append("msg.data[{}:{}]".format(
                hex(operand_1), hex(operand_1+32)))
        else:
            self.stack.append("msg.data[{}:{}]".format(
                operand_1, operand_1+"+32"))

    def calldatasize(self):
        self.stack.append("msg.data.size")

    def calldatacopy(self):
        operand_1 = self.stack_pop()
        operand_2 = self.stack_pop()
        operand_3 = self.stack_pop()
        """
        self.stack.append("msg.data[{}:{}]".format(operand_1, operand_1+32))
        memory[destOffset:destOffset+length] = msg.data[offset:offset+length]
        """

    def codesize(self):
        self.stack.append("address(this).code.size")

    def codecopy(self):
        operand_1 = self.stack_pop()
        operand_2 = self.stack_pop()
        operand_3 = self.stack_pop()
        """
        memory[destOffset:destOffset+length] = msg.data[offset:offset+length]
        """

    def gasprice(self):
        self.stack.append("tx.gasprice")

    def extcodesize(self):
        operand_1 = self.stack_pop()
        self.stack.append("address({}).code.size".format(operand_1))

    def extcodecopy(self):
        operand_1 = self.stack_pop()
        operand_2 = self.stack_pop()
        operand_3 = self.stack_pop()
        operand_4 = self.stack_pop()
        """
        memory[destOffset:destOffset+ \
            length] = address(addr).code[offset:offset+length]
        """

    def returndatasize(self):
        self.stack.append("RETURNDATASIZE()")

    def returndatacopy(self):
        operand_1 = self.stack_pop()
        operand_2 = self.stack_pop()
        operand_3 = self.stack_pop()
        """
        memory[destOffset:destOffset+length] = RETURNDATA[offset:offset+length]
        """

    def extcodehash(self):
        operand_1 = self.stack_pop()
        self.stack.append("extcodehash")

    def blockhash(self):
        operand_1 = self.stack_pop()
        self.stack.append("block.blockHash({})".format(operand_1))

    def coinbase(self):
        self.stack.append("block.coinbase")

    def timestamp(self):
        self.stack.append("block.timestamp")

    def number(self):
        self.stack.append("block.number")

    def difficulty(self):
        self.stack.append("block.difficulty")

    def gaslimit(self):
        self.stack.append("block.gaslimit")

    def pop(self):
        operand_1 = self.stack_pop()

    def mload(self):
        operand_1 = self.stack_pop()
        if(type(operand_1) == int):
            self.stack.append("memory[{}:{}]".format(operand_1, operand_1+32))
        else:
            self.stack.append("memory[{}:{}]".format(
                operand_1, operand_1+"+32"))

    def mstore(self):
        operand_1 = self.stack_pop()
        operand_2 = self.stack_pop()
        if type(operand_1) == int:
            self.memory["memory[{}:{}]".format(
                hex(operand_1), hex(operand_1+0x20))] = operand_2
        else:
            self.memory["memory[{}:{}]".format(
                operand_1, operand_1+"+0x20")] = operand_2
        """memory[offset:offset+32] = value"""

    def mstore8(self):
        operand_1 = self.stack_pop()
        operand_2 = self.stack_pop()
        if type(operand_1) == int:
            if type(operand_2) == int:
                self.memory["memory[{}:{}]".format(
                    hex(operand_1), hex(operand_1+0x20))] = operand_2 & 0xFF
            else:
                self.memory["memory[{}:{}]".format(
                    hex(operand_1), hex(operand_1+0x20))] = operand_2 + "+0xFF"
        else:
            if type(operand_2) == int:
                self.memory["memory[{}:{}]".format(
                    operand_1, operand_1+"+0x20")] = operand_2 & 0xFF
            else:
                self.memory["memory[{}:{}]".format(
                    operand_1, operand_1+"+0x20")] = operand_2 + "& 0xFF"
        """	memory[offset] = value & 0xFF"""

    def sload(self):
        operand_1 = self.stack_pop()
        self.stack.append("storage[{}]".format(operand_1))

    def sstore(self):
        operand_1 = self.stack_pop()
        operand_2 = self.stack_pop()
        """
        storage[key] = value
        """

    def jump(self):
        destination = self.stack_pop()
        return destination

    def jumpi(self):
        destination = self.stack_pop()
        condition = self.stack_pop()
        return (destination, condition)

    def evm_pc(self):
        self.stack.append("pc")

    def msize(self):
        self.stack.append("MSIZE()")

    def gas(self):
        self.stack.append("GAS()")

    def jumpdest(self):
        return

    def push(self, value):
        self.stack.append(value)

    def dup(self):
        idx = int(self.table[self.data[self.pc - 1]][3:])
        if idx > len(self.stack):
            self.stack.append("stack[{}]".format(-idx))
        else:
            self.stack.append(self.stack[-idx])

    def swap(self):
        idx = int(self.table[self.data[self.pc - 1]][4:])
        if idx+1 > len(self.stack):
            for i in range(idx+1-len(self.stack)):
                self.stack = [
                    ("stack[{}]".format(idx+1 - (idx+1-len(self.stack)) + i))] + self.stack
        self.stack[-idx-1], self.stack[-1] = self.stack[-1], self.stack[-idx-1]

    def log(self):
        idx = int(self.table[self.data[self.pc - 1]][3:])
        operand_1 = self.stack_pop()
        operand_2 = self.stack_pop()
        for _ in range(idx):
            self.stack_pop()

    def create(self):
        operand_1 = self.stack_pop()
        operand_2 = self.stack_pop()
        operand_3 = self.stack_pop()
        self.stack.append("new memory[{}:{}].value({})".format(
            operand_2, operand_2+operand_3, operand_1))

    def call(self):
        operand_1 = self.stack_pop()
        operand_2 = self.stack_pop()
        operand_3 = self.stack_pop()
        operand_4 = self.stack_pop()
        operand_5 = self.stack_pop()
        operand_6 = self.stack_pop()
        operand_7 = self.stack_pop()
        self.stack.append("success")

    def callcode(self):
        operand_1 = self.stack_pop()
        operand_2 = self.stack_pop()
        operand_3 = self.stack_pop()
        operand_4 = self.stack_pop()
        operand_5 = self.stack_pop()
        operand_6 = self.stack_pop()
        operand_7 = self.stack_pop()
        self.stack.append("success")

    def evm_return(self):
        operand_1 = self.stack_pop()
        operand_2 = self.stack_pop()
        """
        return memory[offset:offset+length]
        """

    def delegatecall(self):
        operand_1 = self.stack_pop()
        operand_2 = self.stack_pop()
        operand_3 = self.stack_pop()
        operand_4 = self.stack_pop()
        operand_5 = self.stack_pop()
        operand_6 = self.stack_pop()
        self.stack.append("success")

    def create2(self):
        operand_1 = self.stack_pop()
        operand_2 = self.stack_pop()
        operand_3 = self.stack_pop()
        operand_4 = self.stack_pop()
        self.stack.append("new memory[{}:{}].value({})".format(
            operand_2, operand_2+operand_3, operand_1))

    def staticcall(self):
        operand_1 = self.stack_pop()
        operand_2 = self.stack_pop()
        operand_3 = self.stack_pop()
        operand_4 = self.stack_pop()
        operand_5 = self.stack_pop()
        operand_6 = self.stack_pop()
        self.stack.append("success")

    def revert(self):
        operand_1 = self.stack_pop()
        operand_2 = self.stack_pop()
        """
        revert(memory[offset:offset+length])
        """

    def evm_assert(self):
        return

    def selfdestruct(self):
        operand_1 = self.stack_pop()