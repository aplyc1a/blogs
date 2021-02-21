# 门罗币挖矿研究

[TOC]

## 1 钱包

官方的在线钱包申请地址： https://wallet.mymonero.com/

官方的线下钱包客户端：https://www.getmonero.org/downloads/

在线查询门罗币的钱包地址状态：https://www.supportxmr.com/


## 2 矿池

门罗的各种矿池：https://miningpoolstats.stream/monero

找矿池的好处是无需同步区块数据，挖矿相对容易，但是得给矿主交税。并且，想要提现到余额需要挖够一定的数值门槛。

鱼池（xmr.f2pool.com:13531）和猫池（mine.c3pool.com:13333）是两个比较出名的矿池。

## 3 部署

### 3.1 手工编译—xmr-stak

xmr-stak本身提供了已经编译好的二进制程序，但是其中含有抽税，因此要手动编译更改之。

```shell
git clone https://github.com/fireice-uk/xmr-stak
nano xmrstak/donate-level.hpp #改流水抽成为0
apt-get intall cmake hwloc openssl libjsonrpccpp-server0 libmicrohttpd12
#cmake . -DCUDA_ENABLE=OFF -DOpenCL_ENABLE=OFF -DMICROHTTPD_ENABLE=OFF -DOpenSSL_ENABLE=OFF -DHWLOC_ENABLE=OFF
cmake . -DCUDA_ENABLE=OFF -DOpenCL_ENABLE=OFF 
make install && cd bin
./xmr-stak  首次使用会配置各参数
```

若出现“Error: MEMORY ALLOC FAILED: mmap failed”：

运行命令：sysctl -w vm.nr_hugepages=12

### 3.2 手工编译—xmr

xmr本身提供了已经编译好的二进制程序，但是其中含有抽税，因此要手动编译更改之。

```shell
git clone https://github.com/xmrig/xmrig.git
apt-get install libssl-dev libhwloc-dev
sed -i 's/kDefaultDonateLevel = 1/kDefaultDonateLevel = 0/g' xmrig/src/donate.h
sed -i 's/kMinimumDonateLevel = 1/kMinimumDonateLevel = 0/g' xmrig/src/donate.h
mkdir -p xmrig/build && cd xmrig/build
cmake ..; make
```

### 3.3 运行

以上两软件运行时都会依赖config.json或运行时配置命令行参数。

编辑挖矿软件的config.json，修改其中的如下选项：

url:矿池地址

user:自己钱包地址

pass:随意

### 3.4 无文件型挖矿工具

一些矿池还提供了无文件挖矿脚本脚本，如下：

**powershell 无文件挖矿**

```powershell
powershell -Command "$wc = New-Object System.Net.WebClient; $tempfile = [System.IO.Path]::GetTempFileName(); $tempfile += '.bat'; $wc.DownloadFile('http://download.c3pool.com/xmrig_setup/raw/master/setup_c3pool_miner.bat', $tempfile); & $tempfile AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA; Remove-Item -Force $tempfile"
```

**linux 无文件挖矿**

```shell
curl -s -L http://download.c3pool.com/xmrig_setup/raw/master/setup_c3pool_miner.sh | LC_ALL=en_US.UTF-8 bash -s AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```



## 4 收益

### 4.1 矿池收益查询：

https://c3pool.com/cn/

https://www.f2pool.com/xmr/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

### 4.2 各种币的交易价查询：

https://whattomine.com/		   顶部给出了各币的当前汇率

https://miningpoolstats.stream/   price列给出了当前各币汇率

### 4.3 门罗币收益计算器

https://www.babaofan.com/miner/xmr.html

### 4.4 提现

等你挖到了一定量的 xmr 之后，矿池会自动给你转账到你对应的门罗币钱包地址里面。这个时候你就可以找一个交易所进行提现了，比如：币安网，或者 gate.io 都可以。等你的挖到的xmr 卖出去之后你就可以收到人民币了。也就是提现了。

## 5 其他

### 5.1 黑吃黑

网上的样本：1296062aacb4a313ee0af032d23d72eb  config.json

```powershell
#把别人的换成自己的：
#sed -i "s/old/new/g" config.json
sed -i "s/4AzQYXMowpLSbZsm6ngvg1DhTYjsmp8qDeD7rm6rUY3DK9Hza8DpBTCSjZ2rgrTM3RdqnpUZRP8nqWtf923P7urB4QgQfp7/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/g" config.json
sed -i "s/pool.xmr.pt:9000/xmr.f2pool.com:13531/g" config.json
```
### 5.2 xmr定制研究

开源的xmr挖矿程序有两种运行方式，一种是裸运行（会检索并加载配置文件config.json），一种是指定参数运行。[改了一下代码]: (https://github.com/aplyc1a/xmrig)，让它直接硬编码进去好了。

```shell
find ./ -type f -exec sed -i "s/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/自己的钱包地址/g" {} \;
mkdir -p xmrig/build && cd xmrig/build

#常规编译
cmake ..; make
#带debug的编译
cmake .. -DWITH_DEBUG_LOG=true -DWITH_INTERLEAVE_DEBUG_LOG=true -DHWLOC_DEBUG=true -DCMAKE_BUILD_TYPE=Debug ; make
```
### 5.3 网上资料

[挖矿教程](https://blog.f2pool.com/zh/mining-tutorial/xmr)

[门罗币官网](https://getmonero.org/)

[区块浏览器](https://xmrchain.net/)

[区块浏览器](https://moneroblocks.info/)

自己搭建矿池 https://blog.csdn.net/wab719591157/article/details/79256612

关于门罗  https://www.xmr-zh.com/tech/wallet-tech.html