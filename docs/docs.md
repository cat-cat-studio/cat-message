# cat-message项目使用文档
## 1. 项目介绍
本项目是一个基于socket的即时通讯软件，使用Python编写。它支持多用户聊天、聊天信息传输加密等功能。项目分为客户端和服务器端两部分，客户端使用PyQt6进行界面设计，服务器端使用socket库进行网络通信。产品界面简洁功能齐全，可进行简易通讯。
## 2. 项目结构
项目结构如下：
```
docs
├── docs.md
src
├── server.py
├── user.py
.gitignore
LICENSE
README.md
requirements.txt
```
注：src目录下是项目的源代码，docs目录下是项目的使用文档。README.md文件是项目的说明文件，LICENSE文件是项目的许可证文件requirements.txt文件是项目的依赖库文件。  
main分支为稳定版本，dev分支为开发版本。
## 3. 开发环境要求
- Python 3.X（我使用Python 3.12.8开发 低版本也能用）
- PyQt6（用于客户端界面设计）
- git（用于版本控制）
## 4. 使用说明
### 4.1 基础使用
如果你是windows用户，你可以在[这里](https://github.com/xhdndmm/cat-message/releases)下载最新版本的exe文件，解压后直接运行exe文件即可。  
如果你是其他系统用户，请阅读下方源码部署部分。
### 4.2 源码部署
首先克隆存储库：
```
git clone https://github.com/xhdndmm/cat-message.git
cd cat-message/
```
然后安装依赖
```
pip install -r requirements.txt
```
如果你需要守护进程，请手动配置systemd服务文件。
```
sudo vi /etc/systemd/system/cat-message.service
```
将以下内容复制到文件中：
```
[Unit]
# 服务名称，可自定义
Description = cat-message
After = network.target
Wants = network.target

[Service]
Type = simple
#文件路径请自行更改
ExecStart = /path/to/python3 /path/to/cat-message/src/server.py

[Install]
WantedBy = multi-user.target
```
