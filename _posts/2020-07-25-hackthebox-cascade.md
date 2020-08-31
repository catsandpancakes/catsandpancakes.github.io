---
title: HackTheBox - Cascade
layout: post
date: 2020-07-25 23:00:00 +0800
---

![d8a90d700d09a8613c4328e97130aa3b.png](/images/htb-cascade/360e040bbff842178a561345324bdc0e.png)

### 0. Preface

Lots of enumeration in this one. Not a lot of exploitation to go on here, but I found the most interesting part to be the reverse engineering of the .NET application.

In this box, we will be tackling:

1. Active Directory enumeration... lots of it. 
2. Decrypting VNC passwords
3. Reverse Engineering a .NET application using DNSpy
4. Decrypting AES encoded passwords with CyberChef
5. Digging through the Active Directory Recycle Bin

<!--excerpt-->

---

### 1. Preliminary NMAP Scan

```bash
sudo nmap -sC -sV -O -oN nmap.txt 10.10.10.182 -p- -v
```

![0fb123451b1079a91747b7d14222031c.png](/images/htb-cascade/8dc1d6792d6e498d9870e8082b260c29.png)

This seems to be a domain controller. LDAP, Kerberos and high ports running MSRPC are pretty much dead giveaways. Let's start off with LDAP enumeration. 

### 2. LDAP RootDSE

```bash
sudo nmap --script ldap-rootdse -p389 10.10.10.182 -v
```

![1fead680a4e20fc3a5b9a9d4d5015a5a.png](/images/htb-cascade/87986ae6d60646d9bab783e56dc69f95.png)

![b0b51adeb5bf7ae1847bc9f8e7832667.png](/images/htb-cascade/b8d817979aaa492e99f7d925d5304bfe.png)

This tells us that the domain/forest functional level is on Windows 2008 R2, which supports AD Recycle Bin. Domain controller's hostname is CASC-DC1, domain name is `cascade.local`. Adding this to the hosts file to make our lives easier.

### 3. Anonymous LDAP Search for All Users

Next, let's see if we can grab all the users and their attributes from LDAP.

```bash
sudo nmap --script ldap-search --script-args ldap.qfilter='users' -p389 10.10.10.182 -v
```

![c2d7907bb0294cfd741a15a4aa5cb291.png](/images/htb-cascade/8452fb8492d745a891cbb2cc779a9d13.png)

Notice that Ryan Thompson has an attribute called cascadeLegacyPwd, which seems to be a Base64 encoded string clk0bjVldmE=. Let's run that through CyberChef, and we got the first set of credetials - `r.thompson:rY4n5eva`

Also notice that Steve Smith seems to have slightly different rights than everyone else.

![8064cc3f58b6cfcbc16defee46bfa181.png](/images/htb-cascade/d92b179a730f403f990d41a645262681.png)

Also, there's an account called ArkSvc that is able to access the AD Recycle Bin.

![05bade35665fb9fb0486ad05629d8b6a.png](/images/htb-cascade/a1bdb84d5672480f8f8df95fd152ad85.png)

### 4. Accessing Shares With R.Thompson<br/>

Let's see what shares r.thompson can access with SMBMap.

```bash
smbmap -u "r.thompson" -p "rY4n5eva" -d "CASCADE.LOCAL" -H "10.10.10.182"
```
![5fbbd547581b6d48f07c8e6e26ef406f.png](/images/htb-cascade/ea6be8f88014465dace802a935ad9c17.png)

### 5. SMB Exfiltration Using R.Thompson

Let's download everything and analyse them offline using SMBClient.

```bash
smbclient -U "CASCADE.LOCAL/r.thompson" \\\\10.10.10.182\\$SHARE
```

Once inside smbclient, use recurse and prompt to *turn on* recurse and *turn off* prompt. Then use *mget \** to download everything that r.thompson can access.

### 6. SMB Exfil - Data Share

![3c9f5c8f7f1a1a8bb6a8d8c926f4a269.png](/images/htb-cascade/8116ee51e0b84e5db7a98ea0a58076d2.png)

Couple of interesting things here, let's take a look at VNC Install.reg first

Found a password reg key in here: "Password"=hex:6b,cf,2a,4b,6e,5a,ca,0f

Also found this Github Repo that contains a python script to decrypt VNC passwords - [VNCPasswd.py](https://github.com/trinitronx/vncpasswd.py).  

```bash
./vncpasswd.py -d -H 6bcf2a4b6e5aca0f
```

And we have our next password - sT333ve2, but no username. 

Moving on, let's take a look at ArkAdRecycleBin.log. There seems to be a custom script that uses CASCADE\ArkSvc to delete users automatically. There seems to be a deleted user called TempAdmin, according to the logs.

Taking a look at Meeting_Notes_June_2018.html, TempAdmin seems to have been used for some migration jobs. The password for TempAdmin is the same as the "normal admin account password". 

### 7. SMB Exfil - NETLOGON Share

Nothing too interesting in the .vbs files, so skipping. 

### 8. SMB Exfil - SYSVOL Share

Nothing too interesting in SYSVOL either. Skipping this too. 

### 9. Using CrackMapExec to Password Spray
Right. Let's find out who uses that password we found earlier.

Here's the list of users we got from the nmap ldap-search earlier:

![531e82311bea124458c4bcdb4506ee32.png](/images/htb-cascade/df4174971f88469c9db2d257042ac0bc.png)
	
Let's run crackmapexec to password spray: 

```bash
crackmapexec smb 10.10.10.182 -u userlist.txt -p sT333ve2 --continue-on-success
```

Got a hit and our next set of credentials - `s.smith:sT333ve2`

### 10. Enter-PSSession using S.Smith's credentials and user flag

```powershell
Enter-PSSession 10.10.10.182 -Credential 'CASCADE.LOCAL\s.smith' -Authentication Negotiate
```

Get the user flag in c:\users\s.smith\desktop\

### 11. SMB Enumeration for S.Smith
Let's go back a bit to SMB. S.Smith has slightly different permissions from the rest of the users, so it's also likely that he has different shares too. 

Let's run smbmap again:

```bash
smbmap -u 's.smith' -p 'sT333ve2' -d 'cascade.local' -H 10.10.10.182
```

![ab7ba362b45ea12f2440910b0e8bede1.png](/images/htb-cascade/7c90fef5f011434b8a7faec9a287c90d.png)

Notice that his account has access to the Audit share. Let's exfiltrate that one too. 

### 12. SMB Exfil - Audit Share (Reading SQLite Database)
Whatever's inside here seems to be a Windows program. Let's take a look at the DB first. This DB can be viewed with SQLiteBrowser using either Windows/Linux. We will be using Windows because of the next part.

Opening up the DB, we can see these tables: 

![5a13e36b1646dd28bed3726b9024f251.png](/images/htb-cascade/9e705ad9d12a42759162d8f6433cbbed.png)

The DeletedUserAudit table seems to hold the list of users deleted by ArkSvc:

![59ef58e46a8eff5636ff98d4770a3834.png](/images/htb-cascade/1611f38d02814a7ab868f0ce3ec88829.png)

Moving on, the Ldap table seems to store the credentials for ArkSvc.

![ce962a6ec15d96ca3af955c94f1fb5c8.png](/images/htb-cascade/ec27644aaa174092bc82e585aef45c66.png)

Trying to decode the pwd value with CyberChef's Base64 module or Magic module turns up nothing useful. 

### 13. SMB Exfil - Audit Share (Reversing .exe)
Next, let's take a look at the executable found in the Audit share. Since running an unknown executable is risky, let's use DNSpy to reverse engineer it and see what it does. 

Opening up the executable with DNSpy, let's go to the Main() function first:

![ee161b2c49b88e2080b96014ac34381f.png](/images/htb-cascade/a202d137e812440a83d487fb3d9f7fbc.png)

![0606368ebf13cf5d1178d7e55e85d8cc.png](/images/htb-cascade/6d5eec5cb88643388e25323b23700a1f.png)

Breaking this down: 
1. When the program is run, it demands for an argument, which needs to point to the database file (```Audit.db```)
2. Next, it will read all values from the Ldap table (SELECT * FROM LDAP)
3. Using the Pwd value in the Ldap table, it will pass it to a function called Crypto.DecryptString() with the Pwd value and a string - c4scadek3y654321 - as arguments. 

The Crypto.DecryptString() function is defined in the CascCrypto.dll:

![ff8971afb1c77e4f54a4b98f92b43222.png](/images/htb-cascade/c8d4d02f10f749c1bb6e4df5da5cb8ac.png)

![1278f5507552fd2c23f4e7d52253f4ae.png](/images/htb-cascade/46a7ea853b4c42259eceb00f7ef6d8c1.png)

Breaking this down again: 
1. It will first convert the Pwd value from Base64. 
2. Next, it will decrypt the Base64 string using AES-CBC, with the following parameters: 
	- KeySize = 128
	- BlockSize = 128
	- IV = 1tdyjCbY1Ix49842
	- Key = c4scadek3y654321 (the hardcoded key passed into the Crypto.DecryptString() function earlier in Main())

Awesome. Using these parameters, let's decrypt the Pwd value for ArkSvc using CyberChef. 

![97060c0f6b9251d6b14cd869c722bb91.png](/images/htb-cascade/fdc58c1186a04ae39f603d967e2f1741.png)

Note that the Key/IV values in the code are provided in UTF8. Do change the Key/IV formats to the appropriate ones. Do also note that the Input format is Raw after conversion from Base64.

This yields us yet another set of credentials: `CASCADE.LOCAL\ArkSvc:w3lc0meFr31nd`

### 14. Enter-PSSession with ArkSvc

Now that we have the password for ArkSvc, let's go back to Kali and Enter-PSSession with ArkSvc. Now, recall that ArkSvc has access to the AD Recycle Bin, so let's check that out.

```powershell
Get-ADObject -IncludeDeletedObjects -Properties * -Filter * | where deleted -match "true"
```
![eb68373638d0cee3545485c07c3ef468.png](/images/htb-cascade/fff81f57488e4d0d9179a5403b6cea42.png)

Notice that the TempAdmin user also has a cascadeLegacyPwd custom attribute as well. Let's run it through CyberChef again.
	
This yields us the password `baCT3r1aN00dles`. 

Recall that email about TempAdmin having the same password as the normal admin? This potentially yields us our last set of credentials: `administrator:baCT3r1aN00dles`.

### 15. Enter-PSSession with Administrator

Using `Enter-PSSession` again, we manage to login with Administrator.

![e8e48ed0f0a4b5b2ba8d58082d24020b.png](/images/htb-cascade/8cc73b2399f243b18bd6d9efaf89c5a8.png)

![43c1be67538b5078b8ca48a019a25e34.png](/images/htb-cascade/8e7b8a683fbf43c3be06fe93c6fd4ba4.png)