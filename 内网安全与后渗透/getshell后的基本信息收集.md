

## 基本信息收集

### 系统类型判断

使用**whoami**能快速判断系统是Linux还是Windows。

如果是Windows，

使用命令**systeminfo | findstr OS**可得到WIndows版本。

![2021-07-04_222300](https://raw.githubusercontent.com/aplyc1a/blogs_picture/master/2021-07-04_222300.jpg)

使用命令**echo %PROCESSOR_ARCHITECTURE%**可看出系统是基于什么架构的。

![2021-07-04_222229](https://raw.githubusercontent.com/aplyc1a/blogs_picture/master/2021-07-04_222229.jpg)

如果是Linux，

判断系统是**RHEL**系还是**Debian**系，往往需要综合起来看。实际场景下，有时拿到的shell是个docker，包管理器可能还给裁掉了。

```shell
#查看内核版本信息，有时能直接看到操作系统类型。
uname -ar
cat /etc/issue
cat /proc/version
cat /etc/redhat-release

yum/rpm  #RHEL系特有的包管理器
apt/dpkg #Debian系特有的包管理器
```

判断系统CPU指令集。是**armv8/arm64/aarch64**的还是**x64/x86_64**的。这个会影响提权以及上传二进制工具可不可用的问题。

```shell
arch
uname -m
```

### 权限与账户

如果是Linux

```shell
#查看自己身份
whoami
id
w
who

#查看用户列表
cat /etc/passwd
```

需额外留意一下自己有没有被分配可交互的shell

```shell
cat /etc/passwd|grep `whoami`
或，cat ~/*_history
```

如果是Windows

```cmd
whoami
```

需额外留意一下自己是不是域用户。可以参考后面的域信息收集部分。



### 网络与端口

查看网络信息，重点关注地址是不是公网的，是不是多网卡，有没有开放一些有意思的服务端口。由于此时我们已经有个shell了，因此端口信息用处不是特别大，考虑提权的话可能用得上。



如果是Linux

```shell
#IP
ifconfig
ip addr

#端口
netstat -ntalp

#使用下面命令，获得公网IP
curl ifconfig.me
curl cip.cc

#路由及MAC表
route print
arp -a
```



如果是Windows

```shell
#IP
ipconfig

#端口
netstat -ano
```



### 软件与系统补丁

**windows**

```cmd
systeminfo
wmic product get name,version
Get-wmiObject -class Win32_Product | Select-Object -Property name,version
wmic qfe get Caption,Description,HotFixID,InstalledOn
```

![2021-07-07_154933](https://raw.githubusercontent.com/aplyc1a/blogs_picture/master/2021-07-07_154933.jpg)

**linux**

```shell
#debian系
dpkg -l
#RHEL系
yum list installed
```



### 进程与服务信息

windows

```shell
#查看进程信息
tasklist | findstr 360
wmic process list brief
#查看当前服务信息
wmic service list brief
```



linux

```shell
#查看进程信息
ps aux
pstree
ps auxwff
top
#查看当前已启用服务
systemctl list-unit-files|grep enabled
```



## 域基本信息收集

### 判断是否处于域

```shell
net time /domain
```

如果存在域且是域用户，返回如下信息。

![2021-07-07_145117](https://raw.githubusercontent.com/aplyc1a/blogs_picture/master/2021-07-07_145117.jpg)

如果存在域但自身不是域用户，返回如下信息。

![2021-07-07_145718](https://raw.githubusercontent.com/aplyc1a/blogs_picture/master/2021-07-07_145718.jpg)

### 定位域控

**方法一**、定位DNS服务器。一般来说域控同时也是域内的DNS服务器。使用ping或nslookup查找所处域即可知道域控IP。

**方法二、**net命令族

```cmd
net time /domain
```

![2021-07-07_145117](https://raw.githubusercontent.com/aplyc1a/blogs_picture/master/2021-07-07_145117.jpg)

```cmd
net group "Domain Controllers" /domain
```

![2021-07-07_150555](https://raw.githubusercontent.com/aplyc1a/blogs_picture/master/2021-07-07_150555.jpg)

```cmd
net group /domain
```



![2021-07-07_150357](https://raw.githubusercontent.com/aplyc1a/blogs_picture/master/2021-07-07_150357.jpg)

```cmd
nltest /DCLIST:[域地址]
```

![2021-07-07_150357](https://raw.githubusercontent.com/aplyc1a/blogs_picture/master/2021-07-07_151052.jpg)

### 定位域管

![2021-07-07_150522](https://raw.githubusercontent.com/aplyc1a/blogs_picture/master/2021-07-07_150522.jpg)

```cmd
net localgroup administrators /domain
```

![2021-07-07_150647](https://raw.githubusercontent.com/aplyc1a/blogs_picture/master/2021-07-07_150647.jpg)

## 虚拟化设备识别

### 虚拟机

有时需要判断我们拿到的设备是实体设备还是虚拟设备。

**Linux**

下面的命令能很明确的告诉我们设备是kvm、vmware等设备。

```shell
grep -rn "etected virtualization" /var/log


root@walrus:/share# dmesg |grep vmware
[    0.000000] vmware: hypercall mode: 0x00
[    0.000000] vmware: TSC freq read from hypervisor : 2592.004 MHz
[    0.000000] vmware: Host bus clock speed read from hypervisor : 66000000 Hz
[    0.000000] vmware: using clock offset of 19057102439 ns
[    3.906114] systemd[1]: Detected virtualization vmware.
[root@xxx ~]# grep -rn "kvm" /var/log
/var/log/messages-20210704:2609:Jul  1 02:18:35 xxx systemd[1]: Detected virtualization kvm.
```

以及，

```shell
lscpu|grep "Hypervisor vendor"
systemd-detect-virt
dmidecode --string system-manufacturer
dmidecode --string system-product-name
```

**windows**

检查是否存在一些特征文件

```cmd
//vmware
        "C:\\Windows\\System32\\vmGuestLib.dll",
        "C:\\Windows\\System32\\vmGuestLib.dll\\vsocklib.dll",
        "C:\\Program Files\\VMware\\VMware Tools\\rpctool.exe",
        "C:\\Windows\\System32\\drivers\\vmmouse.sys",
//vitualbox
        "C:\\windows\\System32\\Drivers\\VBoxMouse.sys",
        "C:\\windows\\System32\\Drivers\\VBoxGuest.sys",
        "C:\\windows\\System32\\Drivers\\VBoxSF.sys",
        "C:\\windows\\System32\\Drivers\\VBoxVideo.sys",
        "C:\\windows\\System32\\vboxdisp.dll"
```



不过，不论Linux还是Windows最简单粗暴的办法就是查看MAC地址了。获得MAC地址后使用在线MAC地址厂商识别工具进行查找就能判断出网卡类型进而确认设备是实体机还是虚拟机。

以上是相对而言容易进行操作的方案，还有一些更为琐碎专业的方法：

https://www.zhihu.com/question/359121561?sort=created

https://zhuanlan.zhihu.com/p/27823437



### docker

上面用于判断是否虚拟机的技巧常被用于病毒、木马等恶意文件做逃逸及躲避沙箱检测时的要用到的技术，实际场景下用的最多的是判断当前拿到的服务器是不是docker。

如果发现环境缺少很多命令如（yum/rpm/apt/dpkg/wget/curl/ifconfig）或发现系统的进程非常少就要怀疑是不是处于docker环境内了。

![2021-07-07_154251](https://raw.githubusercontent.com/aplyc1a/blogs_picture/master/2021-07-07_154251.jpg)

此外，还可以通过一些特征文件来证实我们猜测的有效性。

```shell
ls -al /.dockerenv 
cat /proc/1/cgroup|grep docker
```

![2021-07-07_152415](https://raw.githubusercontent.com/aplyc1a/blogs_picture/master/2021-07-07_152415.jpg)

## 