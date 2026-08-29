---
tags:
  - arm
---


This is the data types that ARM support

![](Assest/Pasted%20image%2020260829085722.png)

The data types we can load or store can be signed and unisgned.
- Halfword: **-h** for unsigned **-sh**
- Bytes: **-b** for unisogned **-sb**
- Word: no extension

 The difference between siged and unsigned 
```assembly
ldr = Load Word
ldrh = Load unsigned Half Word
ldrsh = Load signed Half Word
ldrb = Load unsigned Byte
ldrsb = Load signed Bytes

str = Store Word
strh = Store unsigned Half Word
strsh = Store signed Half Word
strb = Store unsigned Byte
strsb = Store signed Byte
```

## Registers
In ARM there are  [30 general-purpose 32-bit registers](http://infocenter.arm.com/help/topic/com.arm.doc.dui0473c/Babdfiih.html). The first 16 registers are accesible in user-level mode, the other are available in privileged sofware execution.
![](Assest/Pasted%20image%2020260829093219.png)


- **R0-R12**: can be used during common operation to store temporary values. **R7** is useful while working whit **syscall** as it stores the syscall number. **R11** helps us to keep track of boundaries on the stack serving as the frame pointer.

- **R13: SP (Stack Pointer)**: The Stack Pointer points to the top of the stack. The stack is an area of memory used for function-specific storage, which is reclaimed when the function returns. The SP is therefore used for allocating sapce on the stack, by substacting the value (in bytes) we want to allocate from the stack pointer. For example, if we want to allocate a 32 bit value we subtract 4 from stack pointer.

- **R14: LR (Link Register)**: When a function call is made, the Link Register gets updated with a memory address referencig the next instruction where the function was initated from. Doing this allow to the program return to the "partent" function that initated the "child" function.

- **R15: PC (Program Counter)**: The Program Counter is automatically incremented by the size of the instruction executed. This size is always 4 bytes in ARM state and 2 bytes in THUMB mode. During execution PC stores the address of the current istruction plus 8 (two ARM instruction) in ARM state, and the current instruction plus 4 (two Thumb instrctions) in Thumb(v1).
