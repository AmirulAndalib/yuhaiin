#

## SsrMicroClient

[![license](https://img.shields.io/github/license/asutorufa/ssrmicroclient.svg)](https://raw.githubusercontent.com/Asutorufa/SsrMicroClient/master/LICENSE)
[![releases](https://img.shields.io/github/release-pre/asutorufa/ssrmicroclient.svg)](https://github.com/Asutorufa/SsrMicroClient/releases)
[![Go Report Card](https://goreportcard.com/badge/github.com/Asutorufa/SsrMicroClient)](https://goreportcard.com/report/github.com/Asutorufa/SsrMicroClient)
![languages](https://img.shields.io/github/languages/top/asutorufa/ssrmicroclient.svg)  
<!-- [![codebeat badge](https://codebeat.co/badges/ce94a347-64b1-4ee3-9b18-b95858e1c6b4)](https://codebeat.co/projects/github-com-asutorufa-ssrmicroclient-master) -->
How to use:

- download the [releases](https://github.com/Asutorufa/SsrMicroClient/releases) binary file.if not have your platform ,please build it by yourself.
- if you use windows,you need to read [how to install libsodium to windows](https://github.com/Asutorufa/SsrMicroClient/blob/master/windows_use_ssr_python.md).
- build

```shell script
git clone https://github.com/Asutorufa/SsrMicroClient.git
cd SsrMicroClient
go build SSRSub.go
./SSRSub
```
gui:  
install [therecipe/qt](https://github.com/therecipe/qt)
```shell script
git clone https://github.com/Asutorufa/SsrMicroClient.git
cd gui
go build qt.go
./qt
```

- config file  
  it will auto create at first run,path at `~/.config/SSRSub`,windows at Documents/SSRSub.

<!--
```
#config path at ~/.config/SSRSub
#config file,first run auto create,# to note
#python_path /usr/bin/python3
#ssr_path /shadowsocksr-python/shadowsocks/local.py
#local_port 1080
#local_address 127.0.0.1
#connect-verbose-info
workers 8
fast-open
daemon
#pid-file /home/xxx/.config/SSRSub/shadowsocksr.pid
#log-file /dev/null
```
-->
gui version(by qt):  
![image](https://raw.githubusercontent.com/Asutorufa/SsrMicroClient/master/img/gui_by_qt_dev1.png)  
no gui version:
![image](https://raw.githubusercontent.com/Asutorufa/SsrMicroClient/master/img/SSRSubV0.2.3beta.png)

<!-- [日本語](https://github.com/Asutorufa/SSRSubscriptionDecode/blob/master/readme_jp.md) [中文](https://github.com/Asutorufa/SSRSubscriptionDecode/blob/master/readme_cn.md) [other progrmammer language vision](https://github.com/Asutorufa/SSRSubscriptionDecode/blob/master/readme_others.md)    -->

## Thanks

[Golang](https://golang.org)  
[therecipe/qt](https://github.com/therecipe/qt)  
[mattn/go-sqlite3](https://github.com/mattn/go-sqlite3)(now change to json)  
[breakwa11/shadowsokcsr](https://github.com/shadowsocksr-backup/shadowsocksr)  
[akkariiin/shadowsocksrr](https://github.com/shadowsocksrr/shadowsocksr/tree/akkariiin/dev)  

<!--
## already know issue

ssr python version at mac may be not support,please test by yourself.
-->
## Others
<!--
Make a simple gui([Now Dev](https://github.com/Asutorufa/SsrMicroClient/tree/dev)):
![gui](https://raw.githubusercontent.com/Asutorufa/SsrMicroClient/dev/img/gui_dev.png) 
--> 
Todo:

- [x] (give up)use shadowsocksr write by golang(sun8911879/shadowsocksR),or use ssr_libev share libraries.  
      write a half of [http proxy](https://github.com/Asutorufa/SsrMicroClient/blob/OtherLanguage/Old/SSR_http_client/client.go) find sun8911879/shadowsocksR is not support auth_chain*...oof.  
      when i use ssr_libev i cant run it in the golang that has so many error,i fix a little but more and more error appear.

<!-- ```error
      # command-line-arguments
    /tmp/go-build379176400/b001/_x002.o：在函数‘main’中：
    ./local.c:1478: `main'被多次定义
    # command-line-arguments
    .........
    .........
    .........
    ./local.c:438:36: warning: comparison between pointer and       integer
                         if (perror == EINPROGRESS) {
                                    ^~
``` -->

- [x] add bypass
  - add bypass by socks5 to socks5 and socks5 to http.I need more information about iptables redirection and ss-redir.
- [x] ss link compatible.  
  - [ ] need more ss link template.
- [x] support http proxy.  
  - already know bug: telegram cant use,the server repose "request URI to long",I don't know how to fix.
- [ ] create shortcut at first run,auto move or copy file to config path.
- [ ] add `-h` argument to show help.
<!--
fixed issue:

- process android is not linux.
- sh should use which to get.  
- support windows.
- can setting timeout.
-->
