# dfir-win



## 简介

本项目用途为收集数据，帮助蓝队同学分析、研判、应急Windows安全事件。

目前收集的信息有：

- ✅进程
- ✅网络

- ✅注册表
- ✅DNS缓存

- ✅服务
- ✅计划任务

- ✅Powershell历史记录
- ✅WMI

- ✅安装软件
- ✅日志

- ✅命名管道



## 使用方式

1. 下载本项目
2. Win + X 选择“命令提示符（管理员）”
3. 输入powershell，进入powershell终端，并cd到本项目目录
4. powershell -ep Bypass .\dfir.ps1 
5. 对项目文件夹生成的日志进行分析