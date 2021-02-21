[TOC]

# 0x00 简介

Windows攻击取证溯源中的技术学习

# 0x01 日志审计
安全日志是发现入侵痕迹过程中需特别关注的日志，Windows默认开启对账户登录事件的记录，我们可以使用它检查异常的登录事件，除此之外我们也可以手动的在本地安全策略中设置更多的审计项。
Windows使用事件ID区分不同类型的事件，因此日志的审计主要关注提取出异常时间的高风险的事件ID。Windows使用eventvwr.msc可以快速的打开事件管理器。除此之外也可以访问日志目录“C:\Windows\System32\winevt\Logs”，日志的大小是有上限的，默认20M。

## 1 高风险事件ID

可以认为，早期系统（xp,2003）使用基本安全策略定义的事件ID，vista以上的系统使用高级安全策略定义的事件ID。

下面给出了一些取证中应该重点关注的高风险事件ID，其中登录事件是最应重点关注且在组策略中默认开启的。

| **序号** | **事件****ID** | **事件说明**                                             | **域控特有** |
| -------- | -------------- | -------------------------------------------------------- | ------------ |
| 1        | 4624           | 登录成功                                                 | -            |
| 2        | 4625           | 登录失败                                                 | -            |
| 3        | 4648           | 凭据登录尝试                                             | -            |
| 4        | 4672           | 特殊权限登录                                             | -            |
| 5        | 5632           | 接入无线进行认证时                                       | -            |
| 6        | 5633           | 接入有线进行认证时                                       | -            |
| 7        | 4768           | 处理Kerberos (TGT) 请求                                  | 是           |
| 8        | 4769           | 已请求 Kerberos 服务票证                                 | 是           |
| 9        | 4770           | Kerberos服务票被更新                                     | 是           |
| 10       | 4771           | Kerberos 预身份验证失败                                  | 是           |
| 11       | 4776           | 计算机试图验证NTLM 凭据（解锁，域登录）                  | -            |
| 12       | 4703           | 用户权限已调整                                           | -            |
| 13       | 4704           | 已分配用户权限                                           | -            |
| 14       | 4706           | 新建域信任                                               | 是           |
| 15       | 4707           | 删除域信任                                               | 是           |
| 16       | 4713           | 已修改kerberos策略                                       | 是           |
| 17       | 4716           | 已修改受信任域信息                                       | 是           |
| 18       | 4717           | 已向账户授予系统安全访问权限                             | -            |
| 19       | 4865           | 已添加受信任林信息项                                     | 是           |
| 20       | 4867           | 已修改受信任林信息项                                     | 是           |
| 21       | 4720           | 创建用户                                                 | -            |
| 22       | 4722           | 启用账户                                                 | -            |
| 23       | 4723           | 改账户密码                                               | -            |
| 24       | 4732           | 账户添加至本地安全组                                     | -            |
| 25       | 4739           | 已更改域策略                                             | -            |
| 26       | 4741           | 已创建计算机帐户                                         | 是           |
| 27       | 4742           | 已更改计算机账户                                         | 是           |
| 28       | 4743           | 已删除计算机账户                                         | 是           |
| 29       | 4765           | 账户添加SID记录                                          | -            |
| 30       | 4766           | 账户添加SID失败                                          | -            |
| 31       | 4781           | 修改账户名                                               | 是           |
| 32       | 4782           | 已访问账户的密码哈希                                     | -            |
| 33       | 4793           | 已调用密码策略检查 API                                   | -            |
| 34       | 4798           | 枚举用户的本地组成员身份                                 | -            |
| 35       | 4688           | 表示进程创建                                             | -            |
| 36       | 4696           | 主令牌分配给进程                                         | -            |
| 37       | 1102           | 审核日志已清除                                           | -            |
| 38       | 1104           | 安全日志现已满                                           | -            |
| 39       | 4656           | 已发出对象句柄请求                                       | -            |
| 40       | 4657           | 已修改注册表值                                           | -            |
| 41       | 4663           | 已尝试访问对象                                           | -            |
| 42       | 4664           | 试图创建硬链接                                           |              |
| 43       | 4670           | 已尝试更改对象上的权限                                   | -            |
| 44       | 4698           | 创建计划任务                                             | -            |
| 45       | 4699           | 删除计划任务                                             | -            |
| 46       | 5140           | 访问的共享目录                                           | -            |
| 47       | 5142           | 添加了网络共享对象                                       | -            |
| 48       | 5145           | 检查网络共享对象以查看是否可以向客户端授予所需的访问权限 | -            |
| 49       | 5168           | 无法对SMB进行SPN检查                                     | -            |
| 50       | 1074           | 关机事件                                                 | -            |
| 51       | 5025           | 已停止防火墙                                             | -            |

+ ps: 

  \[1] [微软的事件ID在线文档](https://docs.microsoft.com/zh-cn/windows/security/threat-protection/auditing/event-4722)

  \[2] [简单的事件ID功能记录](http://www.wmksj.com/wzty/56.html)

## 2 登录类型

| **登录类型** | **登录标题**            | **描述**                                                     |
| ------------ | ----------------------- | ------------------------------------------------------------ |
| 0            | System                  | 仅由系统帐户使用，例如，在系统启动时使用。                   |
| 2            | Interactive             | 用户登录到此计算机。                                         |
| 3            | Network                 | 从网络登录到此计算机的用户或计算机。                         |
| 4            | Batch                   | 批处理登录类型由批处理服务器使用，其中进程可以代表用户执行，而无需直接干预。 |
| 5            | Service                 | 服务由服务控制管理器启动。                                   |
| 7            | Unlock                  | 登录界面解锁。                                               |
| 8            | NetworkCleartext        | 用户从网络登录到此计算机。 用户的密码已传递到其未加Hashed 形式的身份验证包。 内置身份验证先打包所有哈希凭据，然后再跨网络发送它们。 凭据不以纯文本格式遍历网络 (也称为明文) 。 |
| 9            | NewCredentials          | 调用方克隆其当前令牌，并指定出站连接的新凭据。 新的登录会话具有相同的本地标识，但其他网络连接使用不同的凭据。 |
| 10           | RemoteInteractive       | 用户使用终端服务或远程桌面远程登录到此计算机。               |
| 11           | CachedInteractive       | 用户使用本地存储在该计算机中的网络凭据登录到此计算机。 未联系域控制器来验证凭据。 |
| 12           | CachedRemoteInteractive | 与  RemoteInteractive 相同。 这用于内部审核。                |
| 13           | CachedUnlock            | 工作站登录。                                                 |

## 3 常见事件特点

### 3.1 非域事件

本地口令登录-成功：event={4648，4624:2}

本地口令登录-失败：event={4648，4625:2}

远程登录-成功：event={4648，4624:10，4672:SYSTEM}

远程登录-失败：event={4648，4625:10}

注销动作：event={4647(动作)，4634（结果）}

解锁登录-成功：event={ 4648，4624:7，4672 }

解锁登录-成功：event={ 4648，4625:7 }

远程访问文件共享目录-成功：event={4624:3, 5140}

### 3.2 域事件（待进一步研究）

域账户域登录（域控关机）：event={ 4648，4625:7 }

域账户域登录（域控正常）：krbrgt+owner

域主机的本地登录：

退域重加：

local：event={4733删除,4688登录，4732添加}

DC event={4768,4769,4724,4742,4725,4722}

PTH：

PTK：

PTT：

## 4 事件提取

### 4.1 powershell

简单的事件快速提取。

```powershell
Get-WinEvent -FilterHashtable @{Logname='security';Id='4624','4624','4672'}
Get-EventLog Security -InstanceId 4624,4625,4672
```

也可以具体查看某条记录的信息。

```powershell
$events=Get-EventLog Security -InstanceId 4624,4625,4672
$events[2]|fl *
```

### 4.2 LogPraser

\#审核登录

```powershell
.\LogParser.exe -i:evt -o:datagrid "select TimeGenerated,extract_token(strings,5,'|') as User, message,extract_token(strings,18,'|') as SIP from security where eventid=4624"

.\LogParser.exe -i:evt -o:datagrid "select TimeGenerated,extract_token(strings,5,'|') as User, message,extract_token(strings,18,'|') as SIP from security where eventid=4624 and SIP not in ('-')"
```

\#审核进程创建（信息收集）

```powershell
LogParser.exe -i:EVT "SELECT TimeGenerated,EventID,EXTRACT_TOKEN(Strings,1,'|') as UserName,EXTRACT_TOKEN(Strings,5,'|') as ProcessName FROM c:\11.evtx where EventID=4688"
```



+ ps:

\[1][LogParser快速上手教程](https://www.jianshu.com/p/0f3ec2fb57a4)

### 4.3 登录事件可视化分析

LogonTracer是一款可视化分析windows事件的日志，仓库地址为：

https://github.com/JPCERTCC/LogonTracer

## 5 防火墙日志

以win10为例，在防火墙日志的具体位置在：%systemroot%\system32\LogFiles\Firewall\pfirewall.log

系统一般都默认关闭该日志，可以在“控制面板->windows 防火墙->高级->属性->公共配置文件下开启该选项”

# 0x02 操作记录审计

## 1 Recent记录（访问记录）

Windows默认会存储150个最近打开的文件或文件夹，如果同一文件被访问两次将以最近一次访问的时间加以记录。下面提供多种查看访问记录的方法。

（1）C:\Documents and Settings\%username%\Recent

（2）或winkey+r && recent

（3）%UserProfile%\Recent

（4）%APPDATA%\Microsoft\Windows\Recent

## 2 Prefetch（预存取记录）

用来存放系统已访问过文件的预读信息，能够加快系统的启动速度。记录文件运行次数、上次执行时间、Hash等。

**注意**：使用[PECmd](https://github.com/EricZimmerman/PECmd)可以提取Prefetch文件夹中的信息：

PECmd.exe -d C:\Windows\Prefetch --csv c:\temp

## 3 WinKey+R(运行框执行历史)

打开注册表，查看以下注册表项

```powershell
reg query HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
reg query HKEY_USERS\<sid>\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```

## 4 Powershell 历史记录

```powershell
Get-Content (Get-PSReadLineOption).HistorySavePath
```

```powershell
#带编号的历史记录
#https://www.cnblogs.com/JiangOil/p/12516881.html
function Get-AllHistory
{
    $his = Get-Content (Get-PSReadLineOption).HistorySavePath
    $n = $his.Length
    $out = @()
    for($i=0;$i -lt $n;$i++)
    {
        $out = $out + "$i $($his[$i])"
    }
    return $out
}
```

## 5 执行或访问过的文件历史（其他）

### 5.1 UserAssist

userassist键值包含GUI应用执行的信息，如名称、路径、关联快捷方式、执行次数、上一次执行时间等。

数据来源（注册表）：

```powershell
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count
```



分析工具：https://blog.didierstevens.com/programs/userassist/



### 5.2 Amcache

Amcache.hve记录执应用程序的执行路径、上次执行时间、以及SHA1值。

数据来源（文件）：

 ```cmd
C:\Windows\appcompat\Programs\amcache.hve
 ```

分析工具：https://github.com/EricZimmerman/AmcacheParser

```cmd
AmcacheParser.exe -f C:\Windows\AppCompat\Programs\Amcache.hve --csv d:\temp
#实测时提示Amcache.hve被占用。
```



### 5.3 MUICache

用来记录exe文件的文件名称，在注册表中保存exe文件的绝对路径和对应exe文件的文件名称。

数据来源（注册表）：

```powershell
HKEY_CURRENT_USER\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache

HKEY_USERS\<sid>\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache
```

### 5.4 AppCompatFlag

数据来源（注册表）：

```powershell
HKLM\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers
HKCU\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers
HKCU\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Persisted
HKCU\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store
```

### 5.5 AppCompatCache

ShimCache 又称为AppCompatCache，从 Windows XP开始存在，用来识别应用程序兼容性问题。跟踪文件路径，大小和上次修改时间（LastModifiedTime）和上次更新时间（LastUpdateTime）。

其中在Windows7/8/10系统中最多包含1024条记录，Windows7/8/10系统中不存在“上次更新时间”。

注册表位置：

```powershell
HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache
```

#### 5.5.1 使用AppCompatParser

工具地址：https://github.com/EricZimmerman/AppCompatCacheParser/

基本用法：AppCompatCacheParser.exe --csv d:\temp -t

#### 5.5.2 使用ShimCacheParser

地址：https://github.com/mandiant/ShimCacheParser

基本用法：

```poweshell
reg export "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache" shimcache.reg

python27 ShimCacheParser.py -o out.csv -r D:\shimcache.reg -t
```

# 0x03 进程检查

针对进程的快速检查能初步排查系统内是否存在异常的正在运行的持久化程序。

Windows下可用于进程分析的工具非常多，微软自带的进程管理工具（msinfo、taskmgr、tasklist）足以应付大部分场景，以及SysinternalsSuite套件中的Process Explorer、Procmon，还有专用于安全人员进行主机安全分析的火绒剑。

进程检查的关键在于从大量进程中快速发现存在异常行为的进程。简单的思路如下：

1. 检查有无对外通信的进程；

2. 检查有无文件签名异常的进程；

3. 检查有无路径可疑或资源占用极高的进程；

4. 检查有无对读写可疑未知文件的进程；

5. 检查有无加载异常dll的进程；

6. 检查进程是否在一段时间内存在可疑操作。

下面各小节基本按照该思路进行展开，给出怎么使用对应工具做简单排查。

## 1 常见进程

svhost.exe：windows服务主进程

iexplore.exe 网络相关进程

explorer.exe windows资源管理器

rundll32.exe 在内存中运行32位的DLL文件

ctfmon.exe 输入法相关程序

winlogon.exe 域登录管理器

csrss.exe是微软客户端/服务端运行时子系统

lsass.exe windows本地安全认证服务

services.exe 服务控制器

smss.exe 会话管理子系统

wmiprvse.exe wmi处理器

internat.exe 多语言输入程序

## 2 异常进程特点

**异常进程的定位：**

​    缺少签名信息、描述信息的进程；

​    路径异常、属主异常的进程；

​    高CPU及高内存占用的进程。



 ## 3 进程基本信息概览

taskmgr--(自带)

msinfo--(自带)

Process Explorer--(SysinternalsSuite)

Procmon--(SysinternalsSuite)

ProHacker

## 4 进程与网络

火绒剑

TCPView--(SysinternalsSuite)

TCPvcon--(SysinternalsSuite)

## 5 进程与dll

procmon--(SysinternalsSuite)

listdll--(SysinternalsSuite)

## 6 进程与文件读写

handle--(SysinternalsSuite)

## 7 自启动项审计

```cmd
# windows自带管理工具
msconfig

# 注册表内添加自启动项
HKEY_CURRENT_USER\software\micorsoft\windows\currentversion\run
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Runonce

# 分析系统配置文件
配置文件或目录内添加自启
C:\windows\win.ini
C:\windows\system.ini
win7 开始 所有应用 启动，观察下面是否有新增的项目。

```

# 8 账户排查

常规的账户添加的方式：

```powershell
net user www$ 123456 /add
net localgroup administrators www$ /add
```

账号检查的几种方法：

命令"net user"及管理器"lusrmgr.msc"能列出系统内常规的用户。

然而有时候攻击者比较狡猾，[留下来了隐藏账户](https://www.cnblogs.com/threesoil/p/10777719.html)，这时可以在注册表HKEY_LOCAL_MACHINE\SAM\SAM\Domains\Account\Users\Names中可以看到所有用于登录的用户，包括上面提到的隐藏账户。



# 9 注册表取证

## 1 注册表基础

HKEY_USERS：包含所有加载的用户配置文件

HKEYCURRENT_USER：当前登录用户的配置文件

HKEY_CLASSES_ROOT：包含所有已注册的文件类型、OLE等信息

HKEYCURRENT_CONFIG：启动时系统硬件配置文件

HKEYLOCAL_MACHINE：配置信息，包括硬件和软件设置

## 2 check项

### 2.1 启动项

```powershell
HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
```

### 2.2 检查隐藏账户

```powershell
HKEY_LOCAL_MACHINE\SAM\SAM\Domains\Account\Users\Names
```

### 2.3 软件执行等操作历史记录

```powershell
# Recent
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs

# 运行框执行历史
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKEY_USERS\<sid>\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU

# UserAssist
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count

# MuiCache
HKEY_CURRENT_USER\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache
HKEY_USERS\<sid>\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache

# AppCompatFlag
HKLM\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers
HKCU\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers
HKCU\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Persisted
HKCU\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store

# AppCompatCache
HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache
```



### 2.4 外设挂载记录

```powershell
# USB
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\PnpResources\Registry\HKLM\SYSTEM\CurrentControlSet\Control\usbstor
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Portable Devices\Devices
HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Enum\SWD\WPDBUSENUM
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\SWD\WPDBUSENUM

# 其他硬件设备
HKEY_LOCAL_MACHINE\System\MountedDevices
#  https://github.com/adaminfosec/Get-DriveLetter/blob/master/Get-DriveLetter.ps1
```

### 2.5 几种常见后门位置

```powershell
# 关注这些目录下有没有加载恶意脚本或程序**
HKEY_CURRENT_USER\Environment -> UserInitMprLogonScript
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon -> Userinit
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\
```

