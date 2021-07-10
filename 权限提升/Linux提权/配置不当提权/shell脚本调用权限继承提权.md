# 环境准备

**1.root账户配置如下命令：**

```shell
root: groupadd aplyc1a
root: useradd -d /home/aplyc1a -m aplyc1a -g aplyc1a -s /bin/bash -p 123456
root: mkdir -p ~aplyc1a/escal
root: chown aplyc1a:aplyc1a ~aplyc1a/escal
root: chmod a+x ~aplyc1a/escal
```

**2.多脚本环境准备**

root目录下有1脚本：

```shell
root: echo '#!/bin/bash' >> /root/.hourly.sh
root: echo 'bash /home/aplyc1a/escal/.hourlychk.sh' >> /root/.hourly.sh
```

root用户将本脚本放到了定时任务或/etc/profile中。

aplyc1a家目录下有1脚本：

```shell
aplyc1a: echo "find ~aplyc1a -user root -type f -exec md5sum {}\;" >> ~aplyc1a/escal/.hourlychk.sh
aplyc1a: chmod +x ~aplyc1a/escal/.hourlychk.sh
```



# 攻击实施

攻击者攻陷aplyc1a账户后直接修改~aplyc1a/escal/.hourlychk.sh脚本，加入反弹shell、改密码、添加uid=0账户等等操作的命令。执行后达到提权。这种攻击的思想是脚本执行权限继承。/home/aplyc1a/escal/.hourlychk.sh的实际运行时权限为root，因此能执行敏感操作。
