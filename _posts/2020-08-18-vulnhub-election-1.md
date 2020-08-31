---
title: VulnHub - eLection 1
layout: post
date: 2020-08-18 15:00:00 +0800
---

![63ac097bd2b9163f6643bd12b619ab8b.png](/images/vh-election1/b6ca4b19571f4662b6223bc65f8e7f8c.png)

### 0. Preface

Very straightforward machine. To be honest, a very easy machine too. Just requires some enumeration by sifting through the `linpeas.sh` output. Also, please update your Serv-U if it is still below 15.7.

In this box, we will be tackling: 

1. Web server enumeration.
2. More web server enumeration.
3. Translating from binary to text.
4. Abusing Serv-U 15.6 with SUID bit set.

<!--excerpt-->

---

### 1. Preliminary NMAP Scan
```bash
sudo nmap -sC -sV -oN nmap.txt 192.168.32.11 -v
```

![adb39c2d46a4625906d0e1527f0b64b7.png](/images/vh-election1/1420292d54814bfeba15e6184ac76128.png)

Only ports 22 and 80 are open. This box is running Ubuntu, and the web server is running on Apache. 

### 2. Web Server Enumeration (Part 1)

Let's see what's on port 80. 

![aa6b39465bd2290dcb610d19dcb75d34.png](/images/vh-election1/37eea95695594194be192f2a966123f1.png)

Nothing much except the default page. We will run `gobuster` on this to bruteforce directories. 

```text
gobuster dir -u http://192.168.32.11 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o gobuster.txt
```

![0cbcd9b821de7a0d3160337311a5989b.png](/images/vh-election1/4de578f956d845d68eb16516f8876f70.png)

Let's try accessing `/election`.

![32bf705d521795905633a7a643b5d2d5.png](/images/vh-election1/4863393f7ec9425dbf260c1c2738505d.png)

![2dcd67eebef65770e1aa3acab65ed36c.png](/images/vh-election1/784a1e50c98444ec800dab931351ba2d.png)

Looking in the page source, this seems to be running php. We will run another `gobuster` to look for php files. 

```text
gobuster dir -u http://192.168.32.11/election -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php -o gobuster-election.txt
```

![00159dd46b00643506c467c6f4580c34.png](/images/vh-election1/b427b07893b34e46b697d4f8014602f0.png)

Let's access `/election/card.php`. 

![717816722128c3624d37caca94d0e11c.png](/images/vh-election1/717d01f7c97e4fdebb9cd95abe7db68f.png)

We have what looks like binary. Let's put it through CyberChef. 

![e66b5ef2c20014dac7355526ebd558ce.png](/images/vh-election1/effa40d0982f4ecba289c45bf7b6b8e7.png)

Converting it once gives us more binary, which we convert a 2nd time to get our first set of creds - `1234:Zxc123!@#`. 

Let's check out `/election/admin` next and try to login with the credentials we got. 

![95e1da175c69e77117aa25220713b354.png](/images/vh-election1/1ed2c55947b94000bb04b9c865524a7e.png)

![f49e223d2366e53276ce76280cc4cb77.png](/images/vh-election1/66a891fae93c4cfb9020d7d033920565.png)

Awesome. 

### 3. Web Server Enumeration (Part 2)

Let's hop on over to the settings page. 

![dcf1b386e42102df97c56b3a57a10775.png](/images/vh-election1/f3bfc1eda0164e328d36af0bbd15c089.png)

On the bottom, there's a system info box. Pretty useful to have system info. Let's take a look at logging. 

![4274a0e6c3b049f48cbd0411fb2ff6b2.png](/images/vh-election1/9ed18488832d49e78fc77f04990997e4.png)

![b1d6ea984a1bedd9e758b901092e8b64.png](/images/vh-election1/19be96c047da4a8dbdc8fd7872d7537e.png)

Now we got our second set of credentials - `love:P@$$w0rd@123`. We can try to SSH into the box with those. 

![a0d37f4bdef8e6c4866b63bc170011ed.png](/images/vh-election1/a2873b2934704751952412f09fa67de3.png)

Let's grab the user flag from the desktop. 

![a7333fc9e56c865117acbd059e9558fd.png](/images/vh-election1/2c4bd7b8b1354269ab79591ef5825224.png)

### 4. Exploiting Serv-U to Root

Let's start off by uploading and running `linpeas.sh` to enumerate the machine.  

![51c54fa61a34f718e9e3b265ae55ea76.png](/images/vh-election1/4f0dd475916c4b0083e79f846e21ecd5.png)

We see that there is a binary, Serv-U, which has the SUID bit set. Let's take a look in the `/usr/local/Serv-U` directory. 

![19400a656263a5bee60e8373134bbbae.png](/images/vh-election1/edf0fff0722d4a748715df2cbf199e62.png)

![f17d430629dc006c3c4eae94ba9c42ee.png](/images/vh-election1/5187561b37114cb3bff88241fa0373f9.png)

Taking a look at the `Serv-U-StartupLog.txt`, we see that it is running 15.1.6.25. 

```text
searchsploit Serv-U
```

![92b75fb1f7a2b77bc00a040349b0e7b3.png](/images/vh-election1/fe8be4669159403f96224b29839ee3d2.png)

Running `searchsploit` on that gives us two exploits. Let's use the first one - `47009.c`.

We will compile this with `gcc` locally. 

```bash
gcc 47009.c -o exploit
```

![62ee67d943d988bd5da8a83082c078cf.png](/images/vh-election1/c5179d91fe0948ef83e6e583bea998a3.png)

Now, let's upload the exploit to the remote server and run it.

![5b87fdd2eac5dd5f47e9e7ee2206237e.png](/images/vh-election1/aff38dc83bec46c3885eb0abc2408094.png)

And we have root. 