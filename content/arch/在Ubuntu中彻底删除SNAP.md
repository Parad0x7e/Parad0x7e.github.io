---
date: '2026-01-26T16:15:10+08:00'
draft: false
title: '在Ubuntu中彻底删除SNAP'
summary: 'snap是什么？'
---
环境：Ubuntu 24.04 lts

## Snap

### snap是什么？

Ubuntu中的`snap`是一种由Canonical开发的、现代化的容器化软件包管理系统。
Ubuntu是预装了snap的
就是下面这个小玩意
![](imgs/fc5094a79432bfef2109fc0c1705f348.png)
打开后的界面
![](imgs/807a4f50ff3a30f39120d8133256eafd.png)
一个类似于软件商店的东西，那为什么要删除它呢？个人的体验和感受是缺点太多，不好用。

### 缺点

Snap的缺点主要集中在性能、生态系统限制、集中化控制以及用户体验等等方面，它还违背了Linux操作系统的理念与精神。

#### 🐌 性能和资源消耗

- **启动速度慢**： Snap应用通常比传统的`.deb`包或原生的应用启动要慢，尤其是在第一次启动时。
- **占用空间大**： 由于 Snap应用将所有依赖项都打包在内（自包含），因此它们占用的磁盘空间通常比非Snap版本要大得多。
- 内存占用高： 你可以在很多论坛中见到一些用户反映Snap应用会占用更多内存资源。
- 系统资源消耗： 安装和运行多个Snap包可能会使系统启动和关机速度变慢。

#### 🔒 生态系统和集中化

- 单一应用商店： Snap生态系统被Canonical高度集中控制，所有Snap包都必须来自SnapCraft商店。用户无法像使用`apt`或`Flatpak`那样添加第三方仓库（repository）。
- 垄断担忧： 这种集中化的模式引发了关于Canonical垄断和控制Linux软件分发渠道的担忧。
- 私有后端： Snap商店的后端是私有的，而不是像传统 Linux软件包管理那样开放透明。

#### ⚙️ 系统集成和用户体验

- 糟糕的桌面集成： Snap应用可能会遇到无法正确显示系统主题、字体或无法与桌面环境的拖放等功能正常工作的问题。
- 受限的功能： 一些Snap版本的应用功能会受到限制，不如非 Snap 版本完整。
- 权限问题： 由于Snap的沙盒（Sandboxing）机制，用户可能会遇到与文件系统访问或权限相关的小烦人bug。
- 强制自动更新： Snap默认强制自动更新，这对于某些需要特定版本或稳定性的应用（如数据库、开发环境）来说可能是个大问题。
- 命令行错误信息不友好： 某些Snap错误信息可能只显示PID（进程 ID）等技术细节，对普通用户不友好，需要到终端手动解决。

#### 📦 兼容性和限制

- 对 AppArmor 的依赖： Snap的沙盒功能严重依赖于 AppArmor（Linux 内核安全模块）。在没有AppArmor配置或不适用的其他发行版上，其安全性可能无法得到保障。
- 与系统设置不兼容： Snap应用可能不尊重你的系统设置或某些底层配置。

Snap的行为很明显已经违背了Linux操作系统的核心理念与精神，在开源与自由的Linux中，是不太可能受到欢迎的。

## 删除Snap

### 备份

为了安全起见，删除前记得做备份

#### 虚拟机

打个快照即可，以VMware Workstation举例如下图
![](imgs/1d59d1fd74c2fa36f64e91df69ba37ca.png)
![](imgs/8324b8967066883085c57fb382ac9091.png)
可以取一个名称，并写上相应的描述
![](imgs/dc48e83e78bebc76da07a56b65f55967.png)

#### 主机

> 这里我没有电脑是安装了Ubuntu系统的只能用虚拟机来演示了

在自己电脑上安装Ubuntu系统的话，是没有办法像虚拟机一样随时拍快照，随时进行恢复的，这里我们使用Time Shift工具来备份系统。
TimeShift 是一款 Linux 上的系统快照工具，用于备份系统文件和设置，以便在系统崩溃或更新失败时，快速将系统恢复到先前的工作状态。

1. 下载Time Shift

```sh
sudo apt install timeshift -y
```

![](imgs/d58e93759da011623f8ebcb95ffe6c70.png)

2. 打开timeshift
   ![](imgs/80e6bc20cb3fe223da3f5d3f641d58ad.png)
3. 选择快照类型为RSYNC
   ![](imgs/d716258403366e5b45560a9237734765.png)
4. 备份根目录和用户目录
   ![](imgs/378da5f10f0b844bc2c9828a6b1a4a75.png)
   ![](imgs/ad9a5dda3cdfb3da163cac6d158aa3dd.png)
   ![](imgs/d0fb1743033308712dd6f2af230bd49a.png)
   ![](imgs/041b9d86ff07ed0f09b27ec5cdc4a0c2.png)
5. 创建备份（耐心等待一会）
   ![](imgs/ee79526fe780bb46bc9e39f0bf2f238b.png)
   这样备份就做完了

### 删除

先查看snap都安装了哪些软件

```sh
snap list
```

![](imgs/9dda255164374714f5b3066ee4038ae2.png)
开始删除操作前，请先确保后台没有运行其他程序，这里会删除firefox，可以先安装一个Google浏览器下载地址： https://www.google.com/chrome/

#### 安装Google Chrome（不需要可以跳过）

下载对应的软件包deb格式
![](imgs/ddb8105189ff526d6727a59496a91af3.png)
点击下载后，可以在download目录找到它
![](imgs/b4dff8da5a360f9e5822b5f25de70ad6.png)
使用以下命令进行安装

```sh
chmod a+x google-chrome-stable_current_amd64.deb
sudo dpkg -i ./google-chrome-stable_current_amd64.deb
```

![](imgs/f80b096e96414940ee8ee11ddf6a7584.png)这样就是安装完成了
![](imgs/83ea13e4dcb00e0f5b04a3a3e4a85207.png)
好了接下来，我们可以开始删除软件了

#### 删除软件包

输入并执行以下命令完成删除，注意**包与包之间存在依赖关系，最好是按这个顺序去删除**

```sh
sudo snap remove firefox
sudo snap remove gtk-common-themes
sudo snap remove gnome-42-2204
sudo snap remove snapd-desktop-integration
sudo snap remove snap-store
sudo snap remove firmware-updater
sudo snap remove bare
sudo snap remove thunderbird
sudo snap remove core22
# 最后删除snapd
sudo snap remove snapd
```

![](imgs/dd033ffc7be1bbbb0915167a920ef0de.png)
这里能够发现有一个错误，原因是：thunderbird正在使用core22，先删除thunderbird，再删除core22就好了。
删除完所有软件后，再次使用snap list查看
![](imgs/1f4eff73b764ee18892ae446327d1cdb.png)
这样就是删完了

#### 停止snapd服务

```sh
sudo systemctl stop snapd
# 禁止开机自启动snapd
sudo systemctl disable snapd
# 彻底禁用并阻止snapd服务启动
sudo systemctl mask snapd
```

![](imgs/213f27fae3fe55c4a10eb270b50c2426.png)

#### apt卸载snapd

```sh
# 不仅会删除snapd软件包本身，还会删除其相关的所有配置文件
sudo apt purge snapd -y
# 阻止snapd软件包被APT软件包管理器升级、安装(锁定版本)
sudo apt-mark hold snapd
```

#### 删除残留文件

```sh
sudo rm -rf ~/snap
sudo rm -rf /snap
sudo rm -rf /var/snap
sudo rm -rf /var/lib/snapd
```

![](imgs/68823be940f59ab4f21d61d17055222e.png)

#### 阻止snap重新安装

编辑配置文件/etc/apt/preferences.d/nosnap.pref

```sh
sudo nano /etc/apt/preferences.d/nosnap.pref
```

将以下内容写入这个配置文件：

```pref
Package: snapd
Pin: release a=*
Pin-Priority: -10
```

按住Ctrl + O保存，Ctrl + X退出
![](imgs/51f8b3f3b39bf8cfa183854e4a37bd07.png)
这个配置文件，作用是利用APT的优先级机制，强制将snapd软件包的安装和升级优先级设置为极低，从而有效地阻止APT自动安装或推荐安装snapd。
配置完成后，输入`sudo apt update`更新apt源列表
![](imgs/ce34efe6e626315fcbfa0081dd140ed4.png)
做到这里，我们已经成功的在Ubuntu系统中删除了所有的snap软件包。删除snap后，Ubuntu就没有图形界面的软件商店了，如果需要使用图形界面化来安装软件，可以选择安装GNOME软件商店

```sh
sudo apt install --install-suggests gnome-software
```

![](imgs/825f33c840748ed76b7820c15303a824.png)
安装完成后，可以找到它（中文为：软件，英文为：software）如下图所示：
![](imgs/b3c0d6dfbf0c988c9b5dfec4d98447fd.png)
![](imgs/56ef0b44bfbf3f2bb166b5823900b568.png)
最后的最后重启电脑

```sh
sudo reboot now
```

## 恢复Snap

打开timeshfit，点击恢复，默认下一步即可
![](imgs/572195d88bb005f09c5e20b20f1e0f73.png)