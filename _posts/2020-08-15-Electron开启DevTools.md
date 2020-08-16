---
title: Electron程序开启DevTools
author: Admin
date: 2020-08-15 20:49:00 +0800
categories: [逆向]
tags: [Electron, 逆向]
---

# 开宗明义

某些Electron程序在发布时会关闭DevTools功能，而Electron打包时会把网站打包到`asar`文件下，包括配置文件`main.js`。通过[asar](https://github.com/electron/asar)工具可以将其重打包，开启DevTools，以便进一步逆向。

# 安装

```shell
npm install asar -g
```

# 解压asar至任意目录

```shell
asar extract <asar文件路径> <目录路径>
```

> `extract`可简写为`e`

# 修改`main.js`

找到`new BrowserWindow()`的变量

例如`mainWindow = new BrowserWindow`

在下方添加一行

```javascript
mainWindow.webContents.openDevTools();
```

# 打包目录至asar

```shell
asar pack <目录路径> <asar文件路径> 
```

> `pack `可简写为`p`

---

> 💡tips: More than just modifying devtools! 
