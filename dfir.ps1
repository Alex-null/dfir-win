#########################################
# Author  : Alex-null
# Tool    : Windows应急响应收集脚本
# Version : 0.0.1
# Github : https://github.com/Alex-null/dfir-win
# Tips ：对于不熟悉的文件可以在https://winbindex.m417z.com/进行查询；由于调用了大量命令，所以有可能被杀毒软件误报
#########################################
#===============================
#       V A R I A B L E S       |
#===============================
$UserName = [System.Environment]::UserName
$CurrentPath = pwd | Select-Object | %{$_.ProviderPath}
$TheDate = Get-Date
#===============================
#          B A N N E R          |
#===============================
cls
#===============================
#        S T A R T I N G        |
#===============================
Write-Host "[+]  Hi, $UserName,推荐使用管理员权限运行，大部分命令依赖管理员权限"
Write-Host -ForegroundColor Green "[+] 日志应急脚本即将在1s后启动"
Start-Sleep -s 1 
#===============================
#       E X E C U T I O N       |
#===============================
echo "========================================================`r`nDFIR Report`r`n$TheDate`r`n========================================================`r`n`r`n" > $CurrentPath\report.txt
$host.UI.RawUI.BufferSize = New-Object System.Management.Automation.Host.Size(500,5000)
$host.UI.RawUI.BufferSize
####################################################################
# 主机名
####################################################################
Write-Host -ForegroundColor Yellow "[+]  Collecting computer name"
if (Test-Path -Path HKLM:"\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName") {
  $ThePCName = Get-ItemPropertyValue  HKLM:"\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName" -Name "ComputerName"
  Add-Content -Path $CurrentPath\report.txt -Value "`r`nComputer Name: $ThePCName"
} else {
    Write-Host -ForegroundColor Red "[-]  Could not find the Registry key!"
    Add-Content -Path $CurrentPath\report.txt -Value "`r`nComputer Name: Could not find the Registry key!"
  }
Remove-Item $CurrentPath\TEMP.txt 2>&1>$null
Remove-Item $CurrentPath\TEMP1.txt 2>&1>$null

####################################################################
# 检查域
####################################################################
Write-Host -ForegroundColor Yellow "[+]  Checking if the computer is in domain or workgroup"
$domain = (Get-WmiObject Win32_ComputerSystem).Domain
if ((gwmi win32_computersystem).partofdomain -eq $true) {
    Add-Content -Path $CurrentPath\report.txt -Value "`r`nDomain: Part of a domain"
    Add-Content -Path $CurrentPath\report.txt -Value "`r`nDomain: $domain"
} else {
    Add-Content -Path $CurrentPath\report.txt -Value "`r`nDomain: WORKGROUP"
}
####################################################################
# IP信息
####################################################################
Write-Host -ForegroundColor Yellow "[+]  get IP"
ipconfig /all >> $CurrentPath\report.txt
####################################################################
# 通过SID列出账户
####################################################################
Write-Host -ForegroundColor Yellow "[+]  Collecting user accounts list from SID"
if (Test-Path -Path HKLM:"\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList") {
  Get-ChildItem -Path HKLM:"\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList" | select pschildname > $CurrentPath\TEMP.txt
  $FileContent = [System.IO.File]::ReadAllText("$CurrentPath\TEMP.txt")
  $FileContent.Trim() > $CurrentPath\TEMP.txt
  $TrimmedContent = Get-Content $CurrentPath\TEMP.txt | Select-Object -Skip 2
  $TrimmedContent > $CurrentPath\TEMP.txt
  $Namex = ""
  Get-Content $CurrentPath\TEMP.txt | ForEach-Object {
    if ($_ -match "s") {
    $_ = $_ -replace '\s',''
    $ProfImgPath = Get-ItemPropertyValue  HKLM:"\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$_\" -Name "ProfileImagePath"
    $UserN = $ProfImgPath.split("\")[-1]
    $Namex = $Namex + "$UserN"+ " "
    }
  }
  Add-Content -Path $CurrentPath\TEMP1.txt -Value $Namex
  $TEMPone = Get-Content $CurrentPath\TEMP1.txt
  Add-Content -Path $CurrentPath\report.txt -Value "`r`nUser List: $TEMPone"
} else {
    Write-Host -ForegroundColor Red "[-]  Could not find the Registry key!"
    Add-Content -Path $CurrentPath\report.txt -Value "`r`nUser List: Could not find the Registry key!"
  }

####################################################################
# 检测网络连通性
####################################################################
Write-Host -ForegroundColor Yellow "[+]  Collecting Internet connectivity information"
$NetStatus = [bool](Test-Connection baidu.com -Count 1 -ErrorAction SilentlyContinue)
if ($NetStatus -eq $true) {
  Add-Content -Path $CurrentPath\report.txt -Value "`r`nNetwork Status             : Connected to Internet"
} else {
    Add-Content -Path $CurrentPath\report.txt -Value "`r`nNetwork Status             : Not connected to Internet"
  }
$PrivIP = Test-Connection -ComputerName (hostname) -Count 1 | select -ExpandProperty IPV4Address 2>$null
$OnlyIP = $PrivIP.IPAddressToString 2>$null
if ($OnlyIP -match "[0-9]") {
  Add-Content -Path $CurrentPath\report.txt -Value "`r`nPrivate IP Address         : $OnlyIP"
} else {
    Add-Content -Path $CurrentPath\report.txt -Value "`r`nPrivate IP Address         : No IP address found!"
  }
####################################################################
# 通过WMIC获取用户
####################################################################
Write-Host -ForegroundColor Yellow "[+]  Collecting user accounts list from wmic"
wmic UserAccount get | ft -Property * -AutoSize > $CurrentPath\Users.txt
####################################################################
# 获取Tcp连接
####################################################################
Write-Host -ForegroundColor Yellow "[+]  Collecting Network TCP "
Get-NetTCPConnection | select LocalAddress,localport,remoteaddress,remoteport,state,@{name="process";Expression={(get-process -id $_.OwningProcess).ProcessName}}, @{Name="cmdline";Expression={(Get-WmiObject Win32_Process -filter "ProcessId = $($_.OwningProcess)").commandline}} |  sort Remoteaddress -Descending | ft -wrap -autosize > $CurrentPath\NetworkTcp.txt
####################################################################
# 获取进程
####################################################################
#System Idle Process、 System进程以外出现没有命令行的进程可能是当前执行权限不够
#Write-Host -ForegroundColor Yellow "[+]  Collecting running process"
gwmi win32_process | Select Name, ProcessID, @{n='Owner';e={$_.GetOwner().User}},CommandLine | ft -wrap -autosize > $CurrentPath\process.txt
####################################################################
# 获取命名管道
####################################################################
Write-Host -ForegroundColor Yellow "[+]  Collecting pipe"
 [System.IO.Directory]::GetFiles("\\.\\pipe\\") |ft -wrap -autosize > $CurrentPath\pipe.txt
####################################################################
# 获取服务 
####################################################################
Write-Host -ForegroundColor Yellow "[+]  Collecting service"
gwmi win32_service | ft -Property  Name, DisplayName, PathName, User, State > $CurrentPath\Service.txt
####################################################################
# 获取计划任务
####################################################################
Write-Host -ForegroundColor Yellow "[+]  Collecting scheduled tasks"
schtasks /query /fo LIST /v |ft > $CurrentPath\task.txt
####################################################################
# 获取注册表（当前用户）
####################################################################
Write-Host -ForegroundColor Yellow "[+]  Collecting Registry For Current User"
(Gci -Path HKCU:\ -recurse) |ft -wrap -autosize > $CurrentPath\Registry.txt
####################################################################
# 获取WMI信息
####################################################################
Write-Host -ForegroundColor Yellow "[+]  Collecting WMI"
Get-CimInstance -Namespace root\Subscription -Class __FilterToConsumerBinding > $CurrentPath\WMIFilterToConsumerBinding.txt
Get-CimInstance -Namespace root\Subscription -Class __EventFilter > $CurrentPath\WMIEventFilter.txt
Get-CimInstance -Namespace root\Subscription -Class __EventConsumer > $CurrentPath\WMIEventConsumer.txt
####################################################################
# 获取DNS缓存
####################################################################
Write-Host -ForegroundColor Yellow "[+]  Collecting DnsClientCache"
Get-DnsClientCache |ft -wrap -autosize > $CurrentPath\DnsClientCache.txt
####################################################################
# 获取安装的软件
####################################################################
Write-Host -ForegroundColor Yellow "[+]  Collecting Software"
gwmi win32_product |ft -wrap -autosize > $CurrentPath\Software.txt

####################################################################
# 获取日志
####################################################################
wevtutil epl System  $CurrentPath\system.evtx
wevtutil epl Application $CurrentPath\Application.evtx
wevtutil epl Security  $CurrentPath\Security.evtx
wevtutil epl "Windows PowerShell" $CurrentPath\PowerShell.evtx
wevtutil epl Microsoft-Windows-WMI-Activity/Operational $CurrentPath\wmi.evtx

####################################################################
# 获取powershell历史记录
####################################################################
$Users = (Gci C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt).FullName
$Pasts = @($Users);

foreach ($Past in $Pasts) {
	write-host "`n----User Pwsh History Path $Past---`n" -ForegroundColor Magenta; 
	get-content $Past
  copy $Past $CurrentPath\
  Add-Content -Path $CurrentPath\ConsoleHost_history.txt  -value "`r`n$Past"
}

####################################################################
# 最近打开的文件Top10文件名
####################################################################
Write-Host -ForegroundColor Yellow "[+]  Checking recently used files"
$a = 1
$UsrProfile = $ENV:USERPROFILE
if (Test-Path -Path "$UsrProfile\AppData\Roaming\Microsoft\Windows\Recent") {
  cd "$UsrProfile\AppData\Roaming\Microsoft\Windows\Recent"
  $RecentFiles = (Get-ChildItem .\ -file).FullName
  $RFLength = $RecentFiles.length
  if ($RFLength -gt 0) {
    if ($RFLength -gt 10) {
      Write-Host -ForegroundColor Green "[+]  Found Recent Files!"
      Add-Content -Path $CurrentPath\report.txt -Value "`r`nRecent Files : Found more than 10 files in $UsrProfile\AppData\Roaming\Microsoft\Windows\Recent`r`n        Here is the list of 10 files-"
      $RecentFiles | ForEach-Object {
        if ($a -lt 11) {
          $LinkFileName = Get-ChildItem -Path $_ -Name
          Add-Content -Path $CurrentPath\report.txt -Value "`r`n        $LinkFileName"
          $a++
        }
      }
    } elseif ($RFLength -eq 10) {
        Write-Host -ForegroundColor Green "[+]  Found Recent Files!"
        Add-Content -Path $CurrentPath\report.txt -Value "`r`nRecent Files               : Found more than 10 files in $UsrProfile\AppData\Roaming\Microsoft\Windows\Recent`r`n        Here is the list of 10 files-"
        $RecentFiles | ForEach-Object {
          if ($a -lt 11) {
            $LinkFileName = Get-ChildItem -Path $_ -Name
            Add-Content -Path $CurrentPath\report.txt -Value "`r`n        $LinkFileName"
            $a++
          }
        }
      } else {
         Write-Host -ForegroundColor Green "[+]  Found Recent Files!"
         Add-Content -Path $CurrentPath\report.txt -Value "`r`nRecent Files               : Found less than 10 files in $UsrProfile\AppData\Roaming\Microsoft\Windows\Recent`r`n        Here is the list-"
         $RecentFiles | ForEach-Object {
          if ($a -lt 11) {
            $LinkFileName = Get-ChildItem -Path $_ -Name
            Add-Content -Path $CurrentPath\report.txt -Value "`r`n        $LinkFileName"
            $a++
          }
         }
        }
  } else {
      Write-Host -ForegroundColor Red "[+]  Found Nothing!"
      Add-Content -Path $CurrentPath\report.txt -Value "`r`nRecent Files               : Nothing found"
    }
  cd $CurrentPath
}
Remove-Item $CurrentPath\TEMP.txt 2>&1>$null
Remove-Item $CurrentPath\TEMP1.txt 2>&1>$null

####################################################################
# 敏感目录痕迹
####################################################################
tree c:\Users /F > file.txt
gci "C:\Users\*" -Recurse  | ft >> file.txt
gci -path "C:\Users\*" -Recurse | Get-FileHash | ft hash, path -autosize > users_hash.txt
gci -path "C:\windows\temp" -Recurse  | ft >> file.txt
gci -path "C:\windows\temp" -Recurse | Get-FileHash | ft hash, path -autosize > temp_hash.txt
#仅win10
reg query "HKLM\SYSTEM\CurrentControlSet\Services\bam\state\UserSettings" /s > bam.txt