#!/bin/sh

chmod +x busybox && cp busybox /bin/busybox
ln -s /bin/busybox /usr/sbin/telnetd 
cp -r * /
/etc/init.d/S98lighttpd start
