---
title: VulnHub - Photographer 1
layout: post
date: 2020-08-09 15:00:00 +0800
---

![c964c59d0d3aa473b6b4b450f8e9fdf6.png](/images/vh-photographer1/ccdff3c9b9a74cd98eafe3b085a4a13f.png)

### 0. Preface

This box is a pretty straightforward one. Just gotta sift through the LinPEAS output and you're pretty much golden for privilege escalation. 

In this box, we will be tackling: 

1. Koken CMS exploit
2. Careful reading through LinPEAS output

<!--excerpt-->

---

### 1. Preliminary NMAP Scan

```bash
sudo nmap -sC -sV -oN nmap.txt 192.168.32.7 -v
```

![ef928a49bb248f003031a1dc907cfeb0.png](/images/vh-photographer1/118716b6dd7d405a952525d8daa00aa3.png)

This is a Ubuntu box running Apache. A couple of ports we can look through - 445, 80 and 8000. 

### 2. SMB Share

Let's start off with anonymous SMBMap. 

```text
smbmap -u "" -p "" -H 192.168.32.7
```

![c132c71c1a2d540b6a1bd8b03fb4aae9.png](/images/vh-photographer1/078e575bafeb4b64a0eda843d1aebc5d.png)

Looks like we have read access to `sambashare`. Let's download everything from there. 

```text
smbclient -N \\\\192.168.32.7\\sambashare
```

![fa2120e21423e30ce450109c68017a62.png](/images/vh-photographer1/9ca34d5434b74f7282367efa46ee1def.png)

![94ca1eb631a3a9d652e0c4faabd4da5e.png](/images/vh-photographer1/64c16828de9f47a5adf77a3fc8faf623.png)

Taking a look at `mailsent.txt` gives us two potential usernames - `daisa` and `agi`, as well as two potential email addresses - `daisa@photographer.com` and `agi@photographer.com`. 

Next, move on to extracting and looking inside `wordpress.bkp.zip`.

![2ea30280fd7abc103e5d021d81557360.png](/images/vh-photographer1/391bf3838de1425f81a44b0cd440ff22.png)

Nothing much of interest here. 

### 3. Web Server Enumeration, Hydra Brute Force

Let's move on to the web server. 

![433ea947ed3483851e6659f6438fcbf0.png](/images/vh-photographer1/bc6dc0cfd30b49068f9e73ad675fd529.png)

This seems to be a photography site running on html. We can start off by running `gobuster` to brute force directories. 

```text
gobuster dir -u http://192.168.32.7 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x html
```

![9474ea5345f868a3ca7f77b3bc71f860.png](/images/vh-photographer1/28e47b9a9a3d48dca658d2d273383a64.png)

There's nothing much of use here, so let's move on to the web server on `:8000`.

![9f3375a854a2b5a7ca8a71c4ec60fbec.png](/images/vh-photographer1/9ef9e11c10524ef99a6c83eb112fd382.png)

Navigating to timeline gives us this `shell.php`.

![6650300ba3e5c9cf72465e9394fcad4a.png](/images/vh-photographer1/7c3bba6eeba34c90be47e0491bf3476d.png)

Clicking on this bring us to a pretty familiar php reverse shell message. Interesting. 

![caeb9c49737436f54ecf47ccf8e540d3.png](/images/vh-photographer1/db5c4066623e4078b43dda68a92ea666.png)

Moving on to look at the page source, there appears to be a `/admin` directory. Let's try accessing it.

![8c29ead2bb79187216b82fca58f3f526.png](/images/vh-photographer1/f6156a06795640099273011d385347a0.png)

![f9c3267eaf06763fe66f19f204112c3f.png](/images/vh-photographer1/d8ab50338b254e6e8f7feefd44ef2bd8.png)

So we got a login page. Let's try to login with `daisa@photographer.com` and proxy the POST request to burpsuite. 

![75476784e93b280d878dba3aa7e957ed.png](/images/vh-photographer1/3b46c95e8d93454fa09ba24ad67a6b84.png)

This seems to be running Koken CMS, based on the HTTP cookie headers. 

Back to the login page, let's first trigger a failed login and try to reset the password for `agi@photographer.com`. 

![e37fbf59d746ddc71c00a99ca5dbdeb8.png](/images/vh-photographer1/7e8cf613e488410b80424d7f403e53f4.png)

This gives us an error message that the email address was not found. Let's try resetting the password for `daisa@photographer.com` instead.

![9ad3fc8c7326746606236844374a7597.png](/images/vh-photographer1/d83fdaf8a410421687de4db15535ae42.png)

Nice, we seem to have a valid email address. Let's use hydra to bruteforce with `rockyou.txt`. 

```text
hydra -l "daisa@photographer.com" -P /usr/share/wordlists/rockyou.txt 192.168.32.7 -s 8000 http-post-form "/api.php?/sessions:email=^USER^&password=^PASS^:User not found"
```

![45d45d29033e9edabd0254423015c159.png](/images/vh-photographer1/84f6c1d2cfc34aff881ca245e779236b.png)

Awesome, we got the credentials `daisa@photographer.com:babygirl`. Let's login with those credentials.  

![03fa869c9153623d9d0c889e7a23a0a2.png](/images/vh-photographer1/56fdcef661bf4bb083e721ddfe8dcf73.png)

### 4. Koken CMS Exploit, Reverse Shell 

Looking at the console page, we see that this is running Koken 0.22.24. 

![9877d44b440cbfd270df19166d850c3a.png](/images/vh-photographer1/254e710c57a64220a9ded5c04e7558f3.png)

There is [an exploit](https://github.com/V1n1v131r4/Bypass-File-Upload-on-Koken-CMS/blob/master/README.md) for this, which is written by the same guy who made this box. 

So, following the POC, we will try to upload an "image" with `phpinfo()`. 

![31983cbfa3ff1ff9e6a2bb5750cbd1b3.png](/images/vh-photographer1/ceadfee53fce4f0eaff176446b50f490.png)

Now that we know it works, we can upload a php reverse shell with the following LHOST IP and LPORT. 

![fba77017b91eb57ccec93c5309599839.png](/images/vh-photographer1/ada7439d73cd4c99825c0a60cfd9d260.png)

After the upload has completed, we setup a netcat listener on port 8000, then navigate to `http://192.168.32.7:8000/storage/originals/02/a9/image.php` to trigger the reverse shell. 

![a9357f7c2b1f50e035daf4865bbd3258.png](/images/vh-photographer1/7abe2a6f98da4b86ac1471c585bb8b01.png)

Let's first grab the user flag on `/home/daisa`. 

![58b539724a1405677b5eae18e928060a.png](/images/vh-photographer1/c40933c668cd40eeb792c4212455c132.png)

### 5. Linpeas Enumeration, Root

Now let's upload and run `linpeas.sh` to enumerate the box automatically. 

![14c771bbed00e1238d5e923b8fbd1e0e.png](/images/vh-photographer1/53ce1da4495f46b89f5c0bf1ea3cbd35.png)

Looking through the linpeas output, we notice that php7.2 has the SUID bit set. Let's take a look at the php7.2 binary. 

![b246ccf5ecda5a13e935e676c4389906.png](/images/vh-photographer1/7a3f280670444140a6fa44017fd112e8.png)

Since php7.2 is owned by `root`, anything we run through this binary will also be run as `root` due to the SUID bit. 

Using [GTFOBins](https://gtfobins.github.io/), we find that we are able to execute `/bin/bash` using `php`. This should give us a root shell. 

![031944984f9873b881def4cbea24ba85.png](/images/vh-photographer1/5e426c26093f4d9d887fa642c97e99ac.png)

```bash
php -r "pcntl_exec('/bin/bash', ['-p']);"
```

![6982ca4e2bfb0a8c6c521cf51a09680e.png](/images/vh-photographer1/237773ed85d044348bc82fb6909a1735.png)