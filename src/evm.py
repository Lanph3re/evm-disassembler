import copy
import json
import queue
import struct


class evm:
    def __init__(self, data):
        self.data = data
        self.stack = []
        self.pc = 0

        # queue used for recursive disassemble
        self.queue = queue.Queue(maxsize=0)

        # self.blocks
        #   @desc basic block information
        #   @key start address of block
        #   @value [(from_address, cond), ...]
        self.blocks = {}

        # self.block_input
        #  @desc stack information when enters a block
        #  @key start address of block
        #  @value stack information
        self.block_input = {}

        # self.visited
        #   @desc visited block information
        #   @key disassembled address
        #   @value disassembled instruction
        self.visited = {}

        # self.fin_adrs
        #   @desc address that will be disassembled in linear disassemble algorithm
        self.fin_addrs = []

        # self.func_list
        #   @desc function information
        #   @key address of function
        #   @value [num_args, num_retval, [return_addr, ...]]
        self.func_list = {0x0: [0, 0, [None]]}

        # opcode table
        with open('../rsrc/opcode.json', 'r') as opcode_json:
            self.table = {int(k): v for k, v in json.load(opcode_json).items()}
        self.terminal = ['*STOP', '*RETURN', '*REVERT']
        self.jump_ops = ['*JUMP', '*JUMPI']

        # function table
        self.opcodes_func = {
            0: self.stop,
            1: self.add,
            2: self.mul,
            3: self.sub,
            4: self.div,
            5: self.sdiv,
            6: self.mod,
            7: self.smod,
            8: self.addmod,
            9: self.mulmod,
            10: self.exp,
            11: self.signextend,
            16: self.lt,
            17: self.gt,
            18: self.slt,
            19: self.sgt,
            20: self.eq,
            21: self.iszero,
            22: self.evm_and,
            23: self.evm_or,
            24: self.xor,
            25: self.evm_not,
            26: self.byte,
            27: self.shl,
            28: self.shr,
            29: self.sar,
            32: self.sha3,
            48: self.address,
            49: self.balance,
            50: self.origin,
            51: self.caller,
            52: self.callvalue,
            53: self.calldataload,
            54: self.calldatasize,
            55: self.calldatacopy,
            56: self.codesize,
            57: self.codecopy,
            58: self.gasprice,
            59: self.extcodesize,
            60: self.extcodecopy,
            61: self.returndatasize,
            62: self.returndatacopy,
            63: self.extcodehash,
            64: self.blockhash,
            65: self.coinbase,
            66: self.timestamp,
            67: self.number,
            68: self.difficulty,
            69: self.gaslimit,
            80: self.pop,
            81: self.mload,
            82: self.mstore,
            83: self.mstore8,
            84: self.sload,
            85: self.sstore,
            86: self.jump,
            87: self.jumpi,
            88: self.evm_pc,
            89: self.msize,
            90: self.gas,
            91: self.jumpdest,
            96: self.push,
            97: self.push,
            98: self.push,
            99: self.push,
            100: self.push,
            101: self.push,
            102: self.push,
            103: self.push,
            104: self.push,
            105: self.push,
            106: self.push,
            107: self.push,
            108: self.push,
            109: self.push,
            110: self.push,
            111: self.push,
            112: self.push,
            113: self.push,
            114: self.push,
            115: self.push,
            116: self.push,
            117: self.push,
            118: self.push,
            119: self.push,
            120: self.push,
            121: self.push,
            122: self.push,
            123: self.push,
            124: self.push,
            125: self.push,
            126: self.push,
            127: self.push,
            128: self.dup,
            129: self.dup,
            130: self.dup,
            131: self.dup,
            132: self.dup,
            133: self.dup,
            134: self.dup,
            135: self.dup,
            136: self.dup,
            137: self.dup,
            138: self.dup,
            139: self.dup,
            140: self.dup,
            141: self.dup,
            142: self.dup,
            143: self.dup,
            144: self.swap,
            145: self.swap,
            146: self.swap,
            147: self.swap,
            148: self.swap,
            149: self.swap,
            150: self.swap,
            151: self.swap,
            152: self.swap,
            153: self.swap,
            154: self.swap,
            155: self.swap,
            156: self.swap,
            157: self.swap,
            158: self.swap,
            159: self.swap,
            160: self.log,
            161: self.log,
            162: self.log,
            163: self.log,
            164: self.log,
            176: self.push,
            177: self.dup,
            178: self.swap,
            240: self.create,
            241: self.call,
            242: self.callcode,
            243: self.evm_return,
            244: self.delegatecall,
            245: self.create2,
            250: self.staticcall,
            253: self.revert,
            255: self.selfdestruct,
        }

    # recursive traversal disassemble
    def recursive_run(self):
        self.queue.put((0, []))
        while not self.queue.empty():
            entry = self.queue.get()
            self.pc = entry[0]
            self.stack = entry[1]
            if self.stack is None:
                continue

            # used for calculate the number of return values
            entry_stack_size = len(self.stack)

            while self.pc <= len(self.data) and self.pc not in self.visited:
                cur_op = self.data[self.pc]

                # skip invalid opcode
                if cur_op not in self.table:
                    self.visited[self.pc] = 'INVALID'
                    self.pc += 1
                    break

                # mark current address as visited
                inst = self.table[cur_op]
                self.visited[self.pc] = inst
                self.pc += 1

                # execute current operation
                if inst not in self.jump_ops:
                    self.stack_func(cur_op)

                    # terminal instructions(stop, revert, return)
                    # store instructions following terminal insts for future instrument
                    if inst in self.terminal:
                        self.fin_addrs.append(self.pc)
                        break
                elif inst == '*JUMPI':
                    jump_addr, cond = self.jumpi()

                    # skip indirect call
                    if type(jump_addr) != int:
                        break

                    # heuristic: contract function detection
                    # find entry point of each contract function
                    # using pattern 'PUSH4, ..., JUMPI'
                    if self.data[self.pc - 0xb] == 0x63 or self.data[self.pc - 0xa] == 0x63:
                        self.func_list[jump_addr] = [0, 1, [None]]

                    # mark instruction following 'JUMPI' as new block
                    self.queue.put((self.pc, copy.deepcopy(self.stack)))
                    self.block_input[self.pc] = copy.deepcopy(self.stack)
                    if self.pc not in self.blocks:
                        self.blocks[self.pc] = []
                    self.blocks[self.pc].append(
                        (self.pc - 1,  'not ' + cond))

                    # mark destination of 'JUMPI' as new block
                    self.queue.put((jump_addr, copy.deepcopy(self.stack)))
                    self.block_input[jump_addr] = copy.deepcopy(self.stack)
                    if jump_addr not in self.blocks:
                        self.blocks[jump_addr] = []
                    self.blocks[jump_addr].append((self.pc - 1, cond))

                    break
                else:
                    # 'JUMP'
                    jump_addr = self.jump()

                    # mark instruction following 'JUMP'
                    self.fin_addrs.append(self.pc)

                    # skip indirect call
                    if type(jump_addr) != int:
                        break

                    # check if destination of 'JUMP' is return address
                    # and get number of return values.
                    for func_info in self.func_list.values():
                        if jump_addr in func_info[2]:
                            func_info[1] = len(self.stack) - entry_stack_size
                            if jump_addr not in self.blocks:
                                self.blocks[jump_addr] = []
                            self.blocks[jump_addr].append(
                                (self.pc - 1, None))

                    # mark destination of 'JUMP' as new block
                    self.queue.put((jump_addr, copy.deepcopy(self.stack)))
                    self.block_input[jump_addr] = copy.deepcopy(self.stack)
                    if jump_addr not in self.blocks:
                        self.blocks[jump_addr] = []
                    self.blocks[jump_addr].append((self.pc - 1, None))

                    # heuristic: function detection
                    # check if address after 'JUMP' exists in stack
                    if self.pc in self.stack:
                        ret_idx = self.stack.index(self.pc)
                        if jump_addr not in self.func_list:
                            num_args = len(self.stack) - ret_idx - 1
                            self.func_list[jump_addr] = [num_args, 0, []]
                            self.queue.put((self.pc, None))
                        else:
                            expected_result = copy.deepcopy(self.stack)
                            for i in range(self.func_list[jump_addr][1]):
                                expected_result.append('func_retval{}'.format(i + 1))
                            self.queue.put((self.pc, expected_result))

                            expected_result = copy.deepcopy(self.stack)
                            for i in range(self.func_list[jump_addr][1]):
                                expected_result.append('func_retval{}'.format(i + 1))
                            self.block_input[self.pc] = expected_result

                        self.func_list[jump_addr][2].append(self.pc)

                    break

    # do linear disassemble to find dead blocks
    def linear_run(self):
        for fin_addr in self.fin_addrs:
            if fin_addr not in self.blocks:
                self.blocks[fin_addr] = []
            if fin_addr not in self.visited:
                self.blocks[fin_addr].append((0xdeadbeef, None))

            self.pc = fin_addr
            while self.pc not in self.visited:
                cur_op = self.data[self.pc]

                # skip invalid opcode
                if cur_op not in self.table:
                    self.visited[self.pc] = 'INVALID'
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
        return self.stack.pop()

    # stack related
    def stack_func(self, op):
        self.opcodes_func[op]()

    def stop(self):
        return

    def add(self):
        operand_1 = self.stack_pop()
        operand_2 = self.stack_pop()
        if type(operand_1) == int:
            operand_1 = hex(operand_1)
        if type(operand_2) == int:
            operand_2 = hex(operand_2)

        self.stack.append('{} + {}'.format(operand_1, operand_2))

    def mul(self):
        operand_1 = self.stack_pop()
        operand_2 = self.stack_pop()
        if type(operand_1) == int:
            operand_1 = hex(operand_1)
        if type(operand_2) == int:
            operand_2 = hex(operand_2)

        self.stack.append('{} * {}'.format(operand_1, operand_2))

    def sub(self):
        operand_1 = self.stack_pop()
        operand_2 = self.stack_pop()
        if type(operand_1) == int:
            operand_1 = hex(operand_1)
        if type(operand_2) == int:
            operand_2 = hex(operand_2)

        self.stack.append('{} - {}'.format(operand_1, operand_2))

    def div(self):
        operand_1 = self.stack_pop()
        operand_2 = self.stack_pop()
        if type(operand_1) == int:
            operand_1 = hex(operand_1)
        if type(operand_2) == int:
            operand_2 = hex(operand_2)

        self.stack.append('{} / {}'.format(operand_1, operand_2))

    def sdiv(self):
        operand_1 = self.stack_pop()
        operand_2 = self.stack_pop()
        if type(operand_1) == int:
            operand_1 = hex(operand_1)
        if type(operand_2) == int:
            operand_2 = hex(operand_2)

        self.stack.append('{} / {}'.format(operand_1, operand_2))

    def mod(self):
        operand_1 = self.stack_pop()
        operand_2 = self.stack_pop()
        if type(operand_1) == int:
            operand_1 = hex(operand_1)
        if type(operand_2) == int:
            operand_2 = hex(operand_2)

        self.stack.append('{} % {}'.format(operand_1, operand_2))

    def smod(self):
        operand_1 = self.stack_pop()
        operand_2 = self.stack_pop()
        if type(operand_1) == int:
            operand_1 = hex(operand_1)
        if type(operand_2) == int:
            operand_2 = hex(operand_2)

        self.stack.append('{} % {}'.format(operand_1, operand_2))

    def addmod(self):
        operand_1 = self.stack_pop()
        operand_2 = self.stack_pop()
        operand_3 = self.stack_pop()
        if type(operand_1) == int:
            operand_1 = hex(operand_1)
        if type(operand_2) == int:
            operand_2 = hex(operand_2)
        if type(operand_3) == int:
            operand_3 = hex(operand_3)

        self.stack.append(
            '({} + {}) % {}'.format(operand_1, operand_2, operand_3))

    def mulmod(self):
        operand_1 = self.stack_pop()
        operand_2 = self.stack_pop()
        operand_3 = self.stack_pop()
        if type(operand_1) == int:
            operand_1 = hex(operand_1)
        if type(operand_2) == int:
            operand_2 = hex(operand_2)
        if type(operand_3) == int:
            operand_3 = hex(operand_3)

        self.stack.append(
            '({} * {}) % {}'.format(operand_1, operand_2, operand_3))

    def exp(self):
        operand_1 = self.stack_pop()
        operand_2 = self.stack_pop()
        if type(operand_1) == int:
            operand_1 = hex(operand_1)
        if type(operand_2) == int:
            operand_2 = hex(operand_2)

        self.stack.append('{} ** {}'.format(operand_1, operand_2))

    def signextend(self):
        operand_1 = self.stack_pop()
        operand_2 = self.stack_pop()
        if type(operand_2) == int:
            operand_2 = hex(operand_2)

        self.stack.append('SIGNEXTEND({}, {})'.format(operand_1, operand_2))

    def lt(self):
        operand_1 = self.stack_pop()
        operand_2 = self.stack_pop()
        if type(operand_1) == int:
            operand_1 = hex(operand_1)
        if type(operand_2) == int:
            operand_2 = hex(operand_2)

        self.stack.append('{} < {}'.format(operand_1, operand_2))

    def gt(self):
        operand_1 = self.stack_pop()
        operand_2 = self.stack_pop()
        if type(operand_1) == int:
            operand_1 = hex(operand_1)
        if type(operand_2) == int:
            operand_2 = hex(operand_2)

        self.stack.append('{} > {}'.format(operand_1, operand_2))

    def slt(self):
        operand_1 = self.stack_pop()
        operand_2 = self.stack_pop()
        if type(operand_1) == int:
            operand_1 = hex(operand_1)
        if type(operand_2) == int:
            operand_2 = hex(operand_2)

        self.stack.append('{} < {}'.format(operand_1, operand_2))

    def sgt(self):
        operand_1 = self.stack_pop()
        operand_2 = self.stack_pop()
        if type(operand_1) == int:
            operand_1 = hex(operand_1)
        if type(operand_2) == int:
            operand_2 = hex(operand_2)

        self.stack.append('{} > {}'.format(operand_1, operand_2))

    def eq(self):
        operand_1 = self.stack_pop()
        operand_2 = self.stack_pop()
        if type(operand_1) == int:
            operand_1 = hex(operand_1)
        if type(operand_2) == int:
            operand_2 = hex(operand_2)

        self.stack.append('{} == {}'.format(operand_1, operand_2))

    def iszero(self):
        operand_1 = self.stack_pop()
        if type(operand_1) == int:
            operand_1 = hex(operand_1)

        self.stack.append('{} == 0'.format(operand_1))

    def evm_and(self):
        operand_1 = self.stack_pop()
        operand_2 = self.stack_pop()
        if type(operand_1) == int:
            operand_1 = hex(operand_1)
        if type(operand_2) == int:
            operand_2 = hex(operand_2)

        self.stack.append('{} & {}'.format(operand_1, operand_2))

    def evm_or(self):
        operand_1 = self.stack_pop()
        operand_2 = self.stack_pop()
        if type(operand_1) == int:
            operand_1 = hex(operand_1)
        if type(operand_2) == int:
            operand_2 = hex(operand_2)

        self.stack.append('{} | {}'.format(operand_1, operand_2))

    def xor(self):
        operand_1 = self.stack_pop()
        operand_2 = self.stack_pop()
        if type(operand_1) == int:
            operand_1 = hex(operand_1)
        if type(operand_2) == int:
            operand_2 = hex(operand_2)

        self.stack.append('{} ^ {}'.format(operand_1, operand_2))

    def evm_not(self):
        operand_1 = self.stack_pop()
        if type(operand_1) == int:
            operand_1 = hex(operand_1)

        self.stack.append('~{}'.format(operand_1))

    def byte(self):
        operand_1 = self.stack_pop()
        operand_2 = self.stack_pop()
        if type(operand_2) == int:
            operand_2 = hex(operand_2)

        self.stack.append(
            '({} >> (248 - {} * 8)) & 0xFF)'.format(operand_2, operand_1))

    def shl(self):
        operand_1 = self.stack_pop()
        operand_2 = self.stack_pop()
        if type(operand_2) == int:
            operand_2 = hex(operand_2)

        self.stack.append('{} << {}'.format(operand_2, operand_1))

    def shr(self):
        operand_1 = self.stack_pop()
        operand_2 = self.stack_pop()
        if type(operand_2) == int:
            operand_2 = hex(operand_2)

        self.stack.append('{} >> {}'.format(operand_2, operand_1))

    def sar(self):
        operand_1 = self.stack_pop()
        operand_2 = self.stack_pop()
        if type(operand_2) == int:
            operand_2 = hex(operand_2)

        self.stack.append('{} >> {}'.format(operand_2, operand_1))

    def sha3(self):
        operand_1 = self.stack_pop()
        operand_2 = self.stack_pop()
        if type(operand_1) == int and type(operand_2) == int:
            operand_2 = hex(operand_1 + operand_2)
            operand_1 = hex(operand_1)
        elif type(operand_1) == int:
            operand_1 = hex(operand_1)
            operand_2 = operand_1 + ' + ' + operand_2
        elif type(operand_2) == int:
            operand_2 = operand_1 + ' + ' + hex(operand_2)
        else:
            pass

        self.stack.append(
            'hash(memory[{}:{}])'.format(operand_1, operand_2))

    def address(self):
        self.stack.append('address(\'this\')')

    def balance(self):
        operand_1 = self.stack_pop()
        if type(operand_1) == int:
            operand_1 = hex(operand_1)

        self.stack.append('address(' + operand_1 + ').balance')

    def origin(self):
        self.stack.append('tx.origin')

    def caller(self):
        self.stack.append('msg.caller')

    def callvalue(self):
        self.stack.append('msg.value')

    def calldataload(self):
        operand_1 = self.stack_pop()
        if type(operand_1) == int:
            operand_2 = hex(operand_1 + 0x20)
            operand_1 = hex(operand_1)
        else:
            operand_2 = operand_1 + ' + 0x20'

        self.stack.append('msg.data[{}:{}]'.format(
            operand_1, operand_2))

    def calldatasize(self):
        self.stack.append('msg.data.size')

    def calldatacopy(self):
        for _ in range(3):
            self.stack_pop()

    def codesize(self):
        self.stack.append('address(this).code.size')

    def codecopy(self):
        for _ in range(3):
            self.stack_pop()

    def gasprice(self):
        self.stack.append('tx.gasprice')

    def extcodesize(self):
        operand_1 = self.stack_pop()
        if type(operand_1) == int:
            operand_1 = hex(operand_1)

        self.stack.append('address({}).code.size'.format(operand_1))

    def extcodecopy(self):
        for _ in range(4):
            self.stack_pop()

    def returndatasize(self):
        self.stack.append('RETURNDATASIZE()')

    def returndatacopy(self):
        for _ in range(3):
            self.stack_pop()

    def extcodehash(self):
        operand_1 = self.stack_pop()
        if type(operand_1) == int:
            operand_1 = hex(operand_1)

        self.stack.append('extcodehash({}'.format(operand_1))

    def blockhash(self):
        operand_1 = self.stack_pop()
        if type(operand_1) == int:
            operand_1 = hex(operand_1)

        self.stack.append('block.blockHash({})'.format(operand_1))

    def coinbase(self):
        self.stack.append('block.coinbase')

    def timestamp(self):
        self.stack.append('block.timestamp')

    def number(self):
        self.stack.append('block.number')

    def difficulty(self):
        self.stack.append('block.difficulty')

    def gaslimit(self):
        self.stack.append('block.gaslimit')

    def pop(self):
        self.stack_pop()

    def mload(self):
        operand_1 = self.stack_pop()
        if type(operand_1) == int:
            operand_2 = hex(operand_1 + 0x20)
            operand_1 = hex(operand_1)
        else:
            operand_2 = operand_1 + ' + 0x20'

        self.stack.append('memory[{}:{}]'.format(
            operand_1, operand_2))

    def mstore(self):
        for _ in range(2):
            self.stack_pop()

    def mstore8(self):
        for _ in range(2):
            self.stack_pop()

    def sload(self):
        operand_1 = self.stack_pop()
        if type(operand_1) == int:
            operand_1 = hex(operand_1)

        self.stack.append('storage[{}]'.format(operand_1))

    def sstore(self):
        for _ in range(2):
            self.stack_pop()

    def jump(self):
        return self.stack_pop()

    def jumpi(self):
        destination = self.stack_pop()
        condition = self.stack_pop()
        return (destination, condition)

    def evm_pc(self):
        self.stack.append('$pc')

    def msize(self):
        self.stack.append('MSIZE()')

    def gas(self):
        self.stack.append('GAS()')

    def jumpdest(self):
        return

    def push(self):
        imm_width = int(self.table[self.data[self.pc - 1]][4:])
        imm_val = self.data[self.pc:self.pc+imm_width].hex()
        self.visited[self.pc - 1] += ' 0x{}'.format(imm_val)
        self.stack.append(int(imm_val, 16))
        self.pc += imm_width

    def dup(self):
        idx = int(self.table[self.data[self.pc - 1]][3:])
        self.stack.append(self.stack[-idx])

    def swap(self):
        idx = int(self.table[self.data[self.pc - 1]][4:])
        self.stack[-idx - 1], self.stack[-1] = self.stack[-1], self.stack[-idx - 1]

    def log(self):
        idx = int(self.table[self.data[self.pc - 1]][3:])
        for _ in range(2 + idx):
            self.stack_pop()

    def create(self):
        operand_1 = self.stack_pop()  # value
        operand_2 = self.stack_pop()  # offset
        operand_3 = self.stack_pop()  # length
        if type(operand_1) == int:
            operand_1 = hex(operand_1)
        if type(operand_2) == int and type(operand_3) == int:
            operand_3 = hex(operand_2 + operand_3)
            operand_2 = hex(operand_2)
        elif type(operand_2) == int:
            operand_2 = hex(operand_2)
            operand_3 = operand_2 + ' + ' + operand_3
        elif type(operand_3) == int:
            operand_3 = operand_2 + ' + ' + hex(operand_3)
        else:
            pass

        self.stack.append('new memory[{}:{}].value({})'.format(
            operand_2, operand_3, operand_1))

    def create2(self):
        operand_1 = self.stack_pop()  # value
        operand_2 = self.stack_pop()  # offset
        operand_3 = self.stack_pop()  # length
        self.stack_pop()  # salt
        if type(operand_1) == int:
            operand_1 = hex(operand_1)
        if type(operand_2) == int and type(operand_3) == int:
            operand_3 = hex(operand_2 + operand_3)
            operand_2 = hex(operand_2)
        elif type(operand_2) == int:
            operand_2 = hex(operand_2)
            operand_3 = operand_2 + ' + ' + operand_3
        elif type(operand_3) == int:
            operand_3 = operand_2 + ' + ' + hex(operand_3)
        else:
            pass

        self.stack.append('new memory[{}:{}].value({})'.format(
            operand_2, operand_3, operand_1))

    def call(self):
        for _ in range(7):
            self.stack_pop()
        self.stack.append('success')

    def callcode(self):
        for _ in range(7):
            self.stack_pop()
        self.stack.append('success')

    def evm_return(self):
        for _ in range(2):
            self.stack_pop()

    def delegatecall(self):
        for _ in range(6):
            self.stack_pop()
        self.stack.append('success')

    def staticcall(self):
        for _ in range(6):
            self.stack_pop()
        self.stack.append('success')

    def revert(self):
        for _ in range(2):
            self.stack_pop()

    def selfdestruct(self):
        self.stack_pop()
