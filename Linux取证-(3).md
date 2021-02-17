[TOC]

# 0xA 一些辅助技术

## 1 文件完整性校验

如果使用仓库源（apt/yum）安装的方式或包管理器安装的方式（dpkg/rpm），使用下面方法可以确定归属。

```shell
# Debian:
dpkg -S $filename   #确定所属的包

dpkg -l $package    #获得包版本
apt-cache policy $package #等效于上面的命令

# RHEL:
rpm -qf $filename
```

之后进行包管理自检
```shell
# Debian:
dpkg -V $package   #确定所属的包

# RHEL:
rpm -V $package
```



包管理器不可用的话，需要手工下载对应版本的包并进行散列校验。解包命令如下：

```shell
# Debian系：
dpkg -X ./xxx.deb extract	#解压到extract目录
dpkg -i ./xxx.deb			#安装该deb包

# RHEL系：
rpm2cpio xxx.rpm | cpio -div	#解压到当前目录
rpm -i xxx.rpm			#安装该rpm包

# bin文件：
chmod +x xxx.bin; ./xxx.bin
#这类文件比较特殊，可以在虚拟机里面安装后获得二进制，再算散列值。

#解包之后，将待分析的文件与解包出的文件分别计算散列值进行比较。
```



对于python文件的定位上面比较捉急，可以采用下面的办法。

```shell
#step 1获得目标脚本所在的路径，记为$py_pth

#匹配该路径是否属于pip管理
python -m site |grep $py_pth
python3 -m site |grep $py_pth

#确认所属包
pip3 list|grep ${关键字}
pip3 show xxx

#重新下载一份该版本的包，如
pip3 download robotframework==2.8.7 -i https://pypi.tuna.tsinghua.edu.cn/simple --trusted-host  pypi.tuna.tsinghua.edu.cn
#解压之。如果文件扩展名为whl当成zip解压即可。

#比较新下载的文件与待分析文件散列值
md5sum a.pyc b.pyc
```

当然，也可以考虑pyc逆向，网上有不少文章。如，https://zhuanlan.zhihu.com/p/121054235


## 2 时间戳关联分析

时间戳分析用于在掌握一定攻击线索的情况下找出对应时间范围内的文件操作（文件访问、文件内容修改、文件属性修改）记录。时间戳分析不是可靠的，但是有时能对前后关联事件分析起到意想不到的效果。

时间戳的不可靠在于：

1. 系统的升级、软件的安装可能会改变文件的时间戳；

2. 对重启过的系统分析临时生成的文件无意义。（/sys、/proc、/tmp）；

3. 攻击者具备手工修改3种类型时间戳的能力。

时间戳有至少3种：

1. 最近访问（access）。读写复制文件都会影响该时间戳。

2. 最近更改（modify）。更改文件的内容时会影响该时间戳。

3. 最近改动（change）。更改文件的属性（权限、属主组、硬链接）与内容都会影响该时间戳。

4. 创建时间（crtime）。在ext4系统上文件有该时间戳，全局唯一，难篡改。



使用时间戳分析参考这样的思路，给定一个攻击线索，查看线索上的时间戳（stat命令可以查看文件时间戳），分析是否存在该时间段前后发生变动的文件（使用find命令）。

```shell
find命令支持对三种时间戳的过滤。
find / {-atime/-ctime/-mtime/-amin/-cmin/-mmin} [-/+]num
a:access   c:change   m:modify

time以天为单位，min以分钟为单位，-表示以内，+表示以前。
find 参数间默认时and逻辑，如果想用“或”使用“-or”，否使用“！”。

find的-new参数还支持通过比较找出更新的文件。参考Y的时间找出满足条件的X文件。（Y给出时间的方式有两种，一种是通过指定使用某个文件的某项时间戳，另一个是直接通过t参数指定某个时间参考系）
find / -newer[X:acm][Y:acm] filename
find / -newer[X:acm]t 时间戳`yyyy-MM-dd hh:mm:ss`
```

例子

```shell
#(1) 50分钟前，1天内 权限755文件的访问记录
find / -atime -1 -amin +50 -perm 755

#(2) 1天前，10天内，访问的文件
find / -atime -10 -atime +1 2>/dev/null

#(3) 检查PATH对应的目录内一段时间内发生变动的文件
OLD_IFS="$IFS" 
IFS=":" 
arr=($PATH) 
IFS="$OLD_IFS" 
for s in ${arr[@]} 
do 
find $s -atime -10 -amin +50
find $s -ctime -10 -cmin +50
find $s -mtime -10 -mmin +50
done

#(4)web目录内文件的时间戳排序
for i in `find /var/www/html/ -type f`;do a=`stat $i|sed -n 6p`; echo "$a  $i"; done |sort -nr

#(5)满足modify时间戳在2020-04-27 10:04:36接下来1s内的文件。
find / -newermt '2020-04-27 10:04:36' ! -newermt '2020-04-27 10:04:37' 2>/dev/null

#(6)满足change时间戳在2020-04-27 10:04:31接下来1s内的文件。
find / ! -newerct '2020-12-24 15:27:32' -newerct '2020-12-24 15:27:31' 2>/dev/null
```



## 3 文件删除恢复

### 3.1 日志恢复

查找系统内已打开该文件进行读写的进程，通过访问文件描述符指向的数据空间从而访问已被标记删除的数据。

假设攻击者删除了/var/log/secure日志。可以通过lsof |grep /var/log/secure找到打开该文件进行读写的进程。一般来说，结果中会标记该日志为deleted。查看进程读写该日志文件时申请的文件描述符。通过访问/proc/$pid/fd/$num即可获得被删除的日志文件的数据。

```shell
lsof |grep /var/log/secure|grep deleted  #第2列pid,第4列fd
cat /proc/$pid/fd/$fd >> /tmp/secure.resume

```

### 3.2 有进程的文件恢复

文件虽然被删除，但是由于存在进程，通过/proc/$pid/exe可以恢复已被删除的文件。

```shell
cat /proc/$pid/exe > /tmp/file.resume
```

### 3.3 无进程的文件恢复

系统上某孤立（当前没有进程占用它）的文件被删除，且删除时间较短，可以采用本节的方法有针对性的尝试恢复。

在开始尝试对文件的恢复前要判断文件系统类型。
```shell
df -T /home|grep dev
```
注意：不同文件系统下的文件误删恢复技术还不尽相同，没有银弹。数据恢复是一门专门的技术门类。这里只给出最常见的几种文件系统下的数据恢复手段。

#### 3.3.1 ext2文件系统-使用工具debugfs

ext2是一类比较早的文件系统，Debian与RHEL的早期发行版常被安装在这类文件系统上。网上说debugfs可以对ext2文件系统下误删的文件进行恢复。

debugfs是系统自带的软件，使用起来比较方便。恢复步骤如下:

```shell
df ${被删文件所在目录}|grep dev		#获得被删文件所在的分区

debugfs -w $分区    		#进入文件系统诊断模式 
>ls -d $被删位置			#获得被删文件的inode
>lsdel					#获得所有被删文件的inode
>dump <inode> $恢复位置	#最终恢复

注意：该软件实测在ext4及xfs文件系统上不能进行文件恢复。
```

#### 3.3.2 ext3/ext4系统-使用extundelete

extundelete可以帮助这种文件系统下误删文件的恢复，但是很遗憾该软件并未预装在系统环境内。因此使用该工具时要做一些额外的工作准备。

(1)	准备好一套分析环境，安装好extundelete工具。
```shell
#fix依赖
Debian: sudo apt-get install e2fslibs-dev e2fslibs-dev
CentOS: yum install e2fsprogs e2fsprogs-libs e2fsprogs-devel -y

#源码编译
wget https://jaist.dl.sourceforge.net/project/extundelete/extundelete/0.2.4/extundelete-0.2.4.tar.bz2
tar -jxvf extundelete-0.2.4.tar.bz2 ; cd extundelete-0.2.4
./configure ; make && make install
```

(2)	挂载目标磁盘。

```shell
dd if=/dev/sda of=/dev/sdc #备硬盘sda的内容到硬盘sdc上。后者空间一定要不小于前者
mkdir -p /mnt/sdc
mount /dev/sdc /mnt/sdc
```

(3)	尝试进行恢复

参考下面两篇文章。

https://www.cnblogs.com/fat-girl-spring/p/14030840.html

https://www.lucktang.com/2636.html

#### 3.3.3 xfs文件系统-使用xfsrestore

xfs是当前RHEL下常用的文件系统。xfsdump与xfsrestore可以帮助这种文件系统下数据的恢复。

https://blog.csdn.net/weixin_46202385/article/details/108383197


## 4 常见典型日志位置

### 4.1 登录日志

| 路径                     | 作用                                                  |
| ------------------------ | ----------------------------------------------------- |
| /var/log/audit/audit.log | 审计日志                                              |
| /var/log/messages        | 记录Linux操作系统常见的系统和服务错误信息             |
| /var/log/secure          | 系统安全日志，记录大部分应用输入账户信息后的登陆情况  |
| /var/log/lastlog         | 记录最后一次用户成功登陆的时间、登陆IP等信息。lastlog |
| /var/log/btmp            | 记录Linux登陆失败的用户、时间以及远程IP地址。lastb    |
| /var/log/wtmp            | 永久记录用户登录事件。last                            |

特别地，前三种日志中的登录事件可以在使用systemd的linux下使用journalctl命令进行访问。关于ftp、telnet的登录日志也记录在该文件中。

### 4.2 启动和内核日志

内核相关：/var/log/dmesg（或dmesg命令）、/var/log/kern.log

启动日志：/var/log/boot

### 4.3 web日志

web日志的默认路径如下，如果不存在，则需要查看web配置文件。

```shell
debian-nginx:		/var/log/nginx/access.log
debian-apache:	/var/log/apache2/access.log 
centos-apache:		/var/log/httpd/access_log
centos-nginx:		/var/log/nginx/access.log 
```

nginx配置文件：nginx.conf（一般是/etc/nginx/nginx.conf）

Debian-apache配置文件：httpd.conf（一般是/etc/httpd/conf/httpd.conf）

Centos-httpd配置文件：一般定位下来是在000-default.conf与default-ssl.conf中。

### 4.4 防火墙日志

iptables：

如果开启了日志开关（/etc/syslog.conf内添加 kern.warning /var/log/iptables.log），则根据开关内的配置位置进行输出。开启时默认输出在/var/log/messages。

firewalld：

从dmesg中过滤出相关的信息。

### 4.5 其他/var/log日志

其他日志：

```shell
/var/log/cron ：记录crond计划任务服务执行情况
/var/log/maillog ：邮件系统日志
/var/log/syslog ：记录警告信息
/var/log/xferlog ：记录FTP会话
/var/log/daemon.log 系统进程日志
```

注意：如果有日志转储功能开启，根据/etc/logrotate.conf找到转储后的日志文件进行分析。


