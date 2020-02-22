# EVM Disassembler

Ethereum virtual machine bytecode disassembler written in python, uses recursive descent algorithm.

## Usage
```
$ python disassembler.py
>> [hex-encoded bytecodes]
```

## Example
```
$ python disassembler.py
>> 60606040526004361061006c57

$ cat output
FUNCTIONS:

  FUNC_0000() -> ()

---
DISASSEMBLED RESULT:

LABEL_0000:
  0x0000: PUSH1 0x60
  0x0002: PUSH1 0x40
  0x0004: MSTORE
  0x0005: PUSH1 0x04
  0x0007: CALLDATASIZE
  0x0008: LT
  0x0009: PUSH2 0x006c
  0x000C: *JUMPI
```