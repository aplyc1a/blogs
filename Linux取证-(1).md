[TOC]


# 0x00 简介
攻击溯源场景下的Linux取证分析

# 0x01 历史记录分析
## 1 历史记录残余

history命令用于查看历史输入的命令。实质是对~/.bash_history内容的解析，顾名思义，依赖当前的$SHELL为"/bin/bash"。

| **history 清理方法**             | **特征**                      |
| -------------------------------- | ----------------------------- |
| 退出前，history -c               | 难以发现                      |
| vi ~/.bash_history               | 历史记录中留下该命令          |
| echo > ~/.bash_history           | 历史记录中留下该命令          |
| vim   :set history=0   :!command | 只会留下vim，但很少有人这么搞 |
| 直接删除                         | 会发现文件被清空              |

## 2 历史记录加固

### 2.1 记录数扩展

```shell
sed -i 's/^HISTSIZE=1000/HISTSIZE=10000/g' /etc/profile
```

### 2.2 记录内容扩展

编辑/etc/profile，加入以下内容

```shell
USER_IP=`who -u am i 2>/dev/null | awk '{print $NF}' | sed -e 's/[()]//g'`
if [ "$USER_IP" = "" ]
then
USER_IP=`hostname`
fi
export HISTTIMEFORMAT="%F %T $USER_IP `whoami` "
shopt -s histappend
export PROMPT_COMMAND="history -a"
```

### 2.3 防篡改删除加固

使用root权限对所有history文件进行加固。只有拥有root用户才能直接编辑该文件，一定程度上起到保护作用。

```shell
chattr +a ~root/.bash_history
chattr +a ~{other_user}/.bash_history
```

### 2.4 其他

https://blog.csdn.net/skate6/article/details/66971077

# 0x02 账号排查

## 1 新增用户

```shell
#过滤所有有shell的用户
cat /etc/passwd|grep sh

#分析最近一次/etc/passwd的变动是什么
diff /etc/passwd /etc/passwd-

# 按照uid进行排序，关注uid重复的用户有木有。
cat /etc/passwd|awk -F: '{print $3"\t"$4"\t"$1"\t"$7}'|sort -n|grep sh
```

+ ps:  passwd-时间戳，可以用于时间戳关联分析

```shell
stat /etc/passwd-
```

## 2 sudo用户识别

```shell
#1 识别加入sudo组的用户
#RHEL系:
cat /etc/gshadow|grep wheel
#Debian系：
cat /etc/gshadow|grep admin

#2 识别对sudoers文件内加入的异常配置
cat /etc/sudoers|grep -Ev "^$|#" | grep "=("
```

## 3 弱口令、空口令、未知公钥

登录公钥提取

```shell
USER_LIST=`cat /etc/passwd|grep bash | awk -F: '{print $1}'`
for i in $USER_LIST; do cat ~${USER_LIST}/.ssh/authorized_keys; done
#或者
cat /etc/passwd |cut -d: -f 6 | xargs -I@ /bin/sh -c "cat @/.ssh/authorized_keys 2>/dev/null"| sort| uniq -c
```

对于发现的公钥，可以参考下面办法，识别是否由未知IP的未知登录。（不用管公钥后的用户名信息是否存在）

```shell
grep -rn `sed -n '1p' ~/.ssh/authorized_keys |ssh-keygen -lf -|awk '{print $2}'` /var/log
```

# 0x03 登录记录分析

## 1 成功登录事件

提取成功登录的事件

```shell
grep -rn " Accepted password " /var/log
grep -rn " Accepted publickey " /var/log
```

记录登录事件的日志比较多，大的来说分两类：一类是last日志，记录的很粗糙，这里就不展开了。一类是/var/log下的系统日志（auth，audit，secure，具体是其中的哪一个与系统系统有关）

下面给出一个表格，表格中的命令帮助给出：由低到高的频数登录事件

| **系统派系** | **系统名称** | **日志路径**                   | **提取登录事件的命令**                                       |
| ------------ | ------------ | ------------------------------ | ------------------------------------------------------------ |
| RHEL         | HWEuler      | /var/log/messages              | cat messages* \| grep sshd \| grep "Accepted password"\|awk  '{print $11}'\|sort -nr \|uniq -c\|sort -nr |
| Debian       | Ubuntu20     | /var/log/auth.log              | cat auth.log \|grep sshd\|grep "Accepted  password"\|awk '{print $11}'\|sort -nr \|uniq -c\|sort -nr |
| Debian       | Kali-2020    | /var/log/auth.log              | cat auth.log \|grep sshd\|grep "Accepted  password"\|awk '{print $11}'\|sort -nr \|uniq -c\|sort -nr |
| Debian       | Kali-2020    | /var/log/journal/              | journalctl \|grep sshd\|grep "Accepted  password"\|awk '{print $11}'\|sort -nr \|uniq -c\|sort -nr |
| RHEL         | CentOS8      | /var/log/secure                | cat secure\|grep sshd\|grep "Accepted  password"\|awk '{print $11}'\|sort -nr \|uniq -c\|sort -nr |
| any          | any          | /var/log/btmp(失败)            | lastb\|awk '{print $3}'\|sort \|uniq -c\|sort -nr            |
| any          | any          | /var/log/wtmp(成功)            | last\|grep -v "reboot"\|awk '{print $3}'\|sort  -nr\|uniq -c\|sort -nr |
| any          | any          | /var/log/lastlog(最近一次成功) | 除了发现非正常账户登录以外用处不大                           |



同时，对于部分有转储的日志可以将其解压合并后进行分析，如/var/log/messages：

```shell
mkdir /var/log/msg ;cp -a /var/log/messages* /var/log/msg; cd /var/log/msg; gunzip -d ./*;
```



已经成功登录的未知IP，使用网上的批量查询工具识别IP所在地：

https://ip.tool.chinaz.com/siteip

## 2 登录手段分析

登录事件中指示“Accepted publickey”说明是公钥登录，要及时删掉账户目录下的公钥。

登录事件中指示“Accepted password”说明是口令登录，口令失窃有多种可能，其中一种是暴力破解，这时日志中会伴随大量的登录尝试失败事件。  

| 系统派系 | 系统类型 | 日志位置          | 提取登录尝试事件的命令                                       |
| :------- | :------- | :---------------- | :----------------------------------------------------------- |
| RHEL     | HWEuler  | /var/log/messages | cat messages*\|grep sshd\|grep Failed\|awk '{print  $11}'\|sort\|uniq -c\|sort -nr |
| RHEL     | CentOS8  | /var/log/secure   | cat secure \|grep sshd\|grep Failed\|awk '{print  $11}'\|sort\|uniq -c\|sort -nr |
| Debian   | ubuntu20 | /var/log/auth.log | cat auth.log\|grep sshd\|grep Failed\|awk '{print  $11}'\|sort\|uniq -c\|sort -nr |

嫌麻烦？直接用这条命令粗筛。

```shell
cat /var/log/*.log|grep sshd|grep "Failed"|awk '{print $11" "$9" "$7}'|sort |uniq -c|sort -nr
```

+ ps：登录日志被删的但一定条件下可还原



# 0x04 网络检查

## 1 异常通信进程

netstat与ss命令互为替代。

+ ps:从这开始就要特别关注取证命令有没有可能被篡改了。被篡改的命令可能有针对性的屏蔽关键字或rootkit进程。怎么排除干扰后面会专门拉出来说。

以下两命令给出系统内已有的所有绑定了tcp&udp端口的通信，-a表示all（listen/establish/...）

```shell
/usr/bin/netstat -ntuap
/usr/bin/ss -ntuap
```

隐蔽通信(例如使用icmp隧道)可能使用非tcp/udp的原始套接字（sock_raw）。

```shell
netstat -awp
ss -awp
lsof | grep raw
```



## 2 异常配置检查

用处不太大，有时能帮助识别潜在风险。

### 2.1 dns配置

关注异常的dns服务器地址，dns服务被劫持可用于流量劫持与钓鱼。

```shell
# 本地 主机名=》ip映射表
cat /etc/hosts
# dns服务配置文件
cat /etc/resolv.conf
```

如果自身为dns服务器且安装nscd服务时，可能特别关注缓存有无被篡改。
配置文件地址及日志：/etc/nscd.conf /var/log/nscd.log
缓存地址：/var/db/nscd/（如果有nscd服务，对应于dns缓存）

### 2.2 访问控制配置

```shell
/etc/hosts.allow	白名单
/etc/hosts.deny		黑名单
firewall-cmd --zone=public --list-ports
iptables -L
```

### 2.3 仓库源检查

防止仓库地址被篡改造成潜在风险的供应链攻击风险。

```shell
# Debian系：
/etc/apt/sources.list
/etc/apt/sources.list.d/
# RHEL系：
/etc/yum.repos.d/
```

### 2.4 网卡工作模式

局域网嗅探时，网卡往往被设置为混杂模式。

ifconfig -a|grep "UPBROADCAST RUNNING PROMISC MULTICAST"



# 0x05 定时性任务分析

## 1 定时任务crond

这种定时任务分两部分，一种定义于/var/spool/cron/crontabs/{user}。平时由各用户使用crontab -e 进行配置。

```shell
USER_LIST=`cat /etc/passwd|grep bash | awk -F: '{print $1}'`
for i in $USER_LIST; do echo -ne "\n\n${i}\n";  crontab -u $i -l; done
for i in $USER_LIST; do echo -ne "\n\n${i}\n";  cat -A /var/spool/cron/crontabs/$i; done
```

一种定义于/etc/crontab，用于手动编辑，与上面不同之处在于其中的定时任务项内需要指定好执行用户。"/etc/cron.d/*"和"/etc/cron.\*/\*"也与定时性任务有关，必要的时候也要检查其中是否被插入周期性调用的执行执行命令。

检查过程中可以重点关注：定时通信（下载、外发），启动的程序路径异常

## 2 其他

anacrontab与logrotate也是存在周期调用的定时程序，两者与crond关系很大。在检查/etc/cron*/目录下的文件时顺带可以检查了。

at用于临时定时执行某任务。使用atq命令可以查看当前系统内待执行的任务。

at -c ${编号}可以查看某项具体任务的内容。

# 0x06 自启动服务检查

自启动顾名思义伴随操作系统启动后自动运行的脚本或命令。Linux下关于自启动管理最常见的是使用systemd、init.d，前者是后者的替代，目前已经默认启用于大多数Linux发行版中。

攻击者获得主机root权限后，可以在自启动脚本目录部署自己的自启动服务，达到每次开机就运行的目的。排查的重点主要集中于当前自启动级别下目录文件的排查。



## 1 systemd检查

systemd自启动脚本的位置有以下三处，在实际场景中，攻击者常将自启动脚本部署于第一处：

+ /etc/systemd/system/ 系统管理员安装的自启动单元, 优先级更高

+ /run/system/system: 系统执行过程中所产生的服务脚本，优先级次之，一般可忽略。

+ [/usr]/lib/systemd/system/ 软件安装的自启动单元

给出两种思路。

### 1.1 通过systemctl命令

过滤出系统内默认启动的自启动任务

```shell
systemctl list-unit-files --type service |grep enabled
find / -name rtkit-daemon.service|grep -v "/sys"
#通过检查该service文件内部是否含有通信、启动未知文件的操作初步进行识别。
#最后，通过检查与网上搜索确定了该文件是安全文件，只是名字比较奇葩而已。
```

### 1.2 手工分析

```shell
# 简单过滤出含有疑似特殊字符的service文件
grep "sh\\|nc \\|./\\|nohup\\|cat" -rl /lib/systemd/system/
grep "sh\\|nc \\|./\\|nohup\\|cat" -rl /lib/systemd/system/
# 手工分析service文件中的内容
```



## 2 init检查

早期，init自启动脚本的位置主要集中于/etc/rc.d/*。后来，其中的内容直接放到了/etc目录下。一些系统中二者同时存在（为了兼容性建立了符号连接）。init服务作为过时的服务，有很多问题，目前不少系统已经默认关闭了init管理器。

Linux系统有0~6共7个运行等级，最常见的是3(多用户)，5(图形化)。使用runlevel（或who -r或直接查看/etc/inittab）确定运行等级后有针对性地分析。 

如前所述，如果分析的设备属于老版本的Linux。需要关注以下文件或目录中有无攻击者定义的恶意脚本:

/etc/rc.d/rc{0..6}.d /etc/rc.d/rc.local /etc/rc.d/init.d/* /etc/rc.d/rc.sysinit

/etc/rc{0..6}.d /etc/rc.local /etc/init.d/*

可以从几个方面分析自启动脚本/任务。

1. 分析/etc/rc.d/rc.sysinit。

2. 分析/etc/rc.d/rc${RUN_LEVEL}.d/S*。

3. 分析/etc/rc.d/rc.local。

































 





 





