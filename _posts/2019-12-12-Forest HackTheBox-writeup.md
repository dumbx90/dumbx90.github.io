---
title: 2019-12-12-Forest HackTheBox writeup by a dumb
author: dumb
date: 2019-12-12 14:10:00 +0800
categories: [Blogging, Tutorial]
tags: [htb,pentest,windows,ad]
---

# Forest HackTheBox writeup by a dumb

## Sumary 

Forest is easy machine. The goal is pwned a Windows Domain Controller where is installed a Exchange Server too. The DC allow anonymous bind in LDAP. After that you use this information to gain access becase there is a user with pre authentication disabled in kerberos. In the initial shell we enumerate and discovery that particular user is member of Account Operator wich is special group  that can be used to add users in Exchange group. After that, you can use this path to grab DCSync privileges and dump the hashes of entire Active Direcory. 


## Recon 

A simple scan with nmap reveal a lot of opne ports:

