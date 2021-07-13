攻击者拿到权限但不知道密码时，有时会考虑通过劫持su、sudo、passwd命令实现偷取正常用户输入的密码。

虽然这个技术从思想上来说并不高端，但是实际实施起来有很多种姿势与点需要注意。

以下是3款我写的相关小工具：

```shell
https://github.com/aplyc1a/toolkits/blob/master/0x04 持续控制/Linux/fake命令后门/fake_passwd/README.md
https://github.com/aplyc1a/toolkits/blob/master/0x04 持续控制/Linux/fake命令后门/fake_su/README.md
https://github.com/aplyc1a/toolkits/blob/master/0x04 持续控制/Linux/fake命令后门/fake_sudo/README.md
```

**姿势：**

部署fake类后门有两种部署方法：

```shell
1.利用$PATH内定义的优先级顺序，在高优先级目录创建fake命令。这种方法不需要攻击者非得是root用户。（这种后门在取证溯源时抗包管理自检，但熟悉命令位置时就能发现）
2.攻击者拿到root权限后，使用fake命令替换掉正确位置的命令文件，并将fake内指定移动后的命令位置。（这种后门会被包管理器自检发现）
```

**注意点：**必须足够的真。命令交互过程中的语言不能一会汉语一会英语，界面上尽可能地与正常命令保证一致。这是需要不断的对工具脚本进行打磨调整的。

总的来说，这种技术难度不高，但是做真的难度很大。从取证溯源的角度来说，识别这类后门比较容易。可以关注这些后门的内容是二进制还是明文ascii，可以关注系统内的同名文件，也可以使用包管理自检。

