# 利用meltdown漏洞，读取内存内容
## 实验平台
+ 虚拟机：VMware Workstation Pro
+ 系统：ubuntu 14.04
+ 内核版本：4.4.0-31-generic
## 实验准备
1. 关于系统的选择，之前一直使用的是ubuntu 16.04，内核版本是4.13.0-45-generic,但是经过了好长时间的调研都始终无法将meltdown的补丁关闭，所以最终选择了安装一个低版本的虚拟机，果然取得了成功。
2. 关于实验环境的检测，我在这个[网站](https://linuxhint.com/check-patch-spectre-meltdown-ubuntu/)上找到了相关的工具，如图显示，meltdown的漏洞为v，即为可以攻击。
## 实验原理
## 实验效果
## 参考资料