# RainCode

社工字典生成器



## 使用

raincode用来生成针对不同角色用户的高定制化字典。常见的密码都存在一定的规律，通过定制化不同角色的密码模型文件（*.model）及信息元数据文件（config.json）可以极大概率的产生正确的用户密码。

### 1 自然人

**step1**：收集目标的各类信息，填入**human.json**。

**step2**：选择对应的模型文件(**\*.model**)。

**step3**：执行之。

```shell
python3 raincode.py -j *.json -m *.model [-i dicfilename] [-o [result.txt]]
-j/--json *  : 指定需要加载的目标元数据文件。
-m/--model * : 指定需要加载的目标模型文件。
-o/--output [filename]: 指定输出文件名称。
-i/--import *: 导入外置字典

#输出到标准屏幕
python3 raincode.py -j human.json -m model/chinese-password.model
#输出密码到文件
python3 raincode.py -j human.json -m model/chinese-password.model -o result.txt
#导入密码
python3 raincode.py -j human.json -m model/chinese-password.model -i common/chinese-password.txt
```



### 2 后台

**step1**：收集目标的各类信息，填入**backend.json**。

**step2**：选择对应的模型文件(**\*.model**)。

**step3**：执行之。

```shell
python3 raincode.py -j *.json -m *.model [-i dicfilename] [-o [result.txt]]
-j/--json : 指定需要加载的目标元数据文件。
-m/--model: 指定需要加载的目标模型文件。
-o/--output [filename]: 指定输出文件名称。
-i/--import [filename]: 导入外置字典

#输出到标准屏幕
python3 raincode.py -j backend.json -m model/backend.model
#输出密码到文件
python3 raincode.py -j backend.json -m model/backend.model -o result.txt
#导入密码
python3 raincode.py -j backend.json -m model/backend.model -i common/backend-password.txt
```



## 附录-目录说明

### model

存储用于生成字典的核心模型文件。模型描述的是密码的结构。

| 名称                   | 作用             |
| ---------------------- | ---------------- |
| chinese-password.model | 中文密码模型     |
| engish-password.model  | 英语密码模型     |
| backend-password.model | 后台常见密码模型 |

### db

| 名称               | 作用                    |
| ------------------ | ----------------------- |
| %m%d.txt           | 4位月日-数字字典        |
| %Y%m%d.txt         | 6位年月日-数字字典      |
| chinesename-l3.txt | 3位名字-字母字典        |
| sfz_l4.txt         | 某证后4位-字母字典      |
| sfz_l6.txt         | 某证后6位-字母字典      |
| 百家姓.txt         | 百家姓频数排序-字符字典 |

使用**db2json.py**将txt字典转化为可加入json文件中的材料。

python3 db2json.py -i chinesename-l3.txt -n name > 1.json

### common

| 名称                       | 作用                 |
| -------------------------- | -------------------- |
| chinese-password.txt       | 国内高频弱口令       |
| english-password.txt       | 国外高频弱口令(暂缺) |
| linux-account.txt          | linux常见用户        |
| backend-account.txt        | 后台常见用户         |
| backend-password.txt       | 后台常见弱口令       |
| backend-sqlinject-user.txt | 后台常见万能账户     |

