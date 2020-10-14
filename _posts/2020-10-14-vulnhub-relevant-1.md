---

title: VulnHub - Relevant 1
layout: post
date: 2020-10-14 15:30:00 +0800

---

![5e10d90f6fd45ba213a0c99a0785745e.png](/images/vh-relevant1/f7b8d28aaafe4de8a204b20ef31e4d52.png)

### 0. Preface

This is a pretty fun box, which has you enumerating a WordPress site without using the usual `wpscan`. Turns out, `nmap` has some pretty useful scripts that can be used to enumerate certain common services too! 

In this box, we will be tackling: 

1. Enumerating WordPress Plugins with `nmap`.
2. Exploiting RCE with WordPress File Manager.
3. Elevating privileges using Node.js. 

<!--excerpt-->

---

### 1. Preliminary NMAP Scan

```bash
sudo nmap -sC -sV -oN nmap.txt 192.168.32.20 -v
```

![9e69b2edbdc08939cf5d9b0486be46e6.png](/images/vh-relevant1/2ae08ec91f984aee9cce91f1b7b0a43b.png)

This seems to be an Ubuntu box. Only port 22 and 80 are open, and port 80 seems to be running Nginx.

### 2. Web Server Enumeration 

Let's visit the website. 

![2706508bba4519f673d1674b33bb5ef6.png](/images/vh-relevant1/51e69e8b22504209ad4d459e232caf97.png)

Interesting. It's been pwned before. Let's try to visit some of those links.

![dd88812899481681a4071a291a4623bf.png](/images/vh-relevant1/1d9bbbe7b26e4462852fb3243ea73ca8.png)

The first one takes us to an acapella rickroll. Haven't gotten rickroll-ed by a box before. 

![6de21733784bb1204f68c25cbc0c4b6d.png](/images/vh-relevant1/1d2460a636c44a21b412720bf374617b.png)

The second one takes us to a pastebin with some usernames and passwords. This might come in handy later on. 

![e69db158946abd58d8534d545ee745f0.png](/images/vh-relevant1/52e8b7adba9a4052b16bbec3a9ce906d.png)

The third one takes us to an image of a QR code. Let's try to decode it. 

![af9c95394554ec0ebe4242c2260112e2.png](/images/vh-relevant1/e67ac92c1c0c4b41b231f36cc6b8109e.png)

This seems to contain a TOTP secret key for `patsy@relevant` which matches up with one of the users in the pastebin earlier. 

Moving on, let's try to run `gobuster` on the site. 

```
gobuster dir -u http://192.168.32.20 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o gobuster.txt
```

![bc3d4cb320172318a486052769a185cb.png](/images/vh-relevant1/e2df8a3468f1472eadb0a80a004d87aa.png)

Seems to be running WordPress. Let's try to enumerate with `wpscan`. 

![3cac4823af3ca0591003bc5988dc67b1.png](/images/vh-relevant1/f2031e4fa2b642a7aab16d6c891f9104.png)

![d0259d5e657448bef7d1411ce930e4e4.png](/images/vh-relevant1/61aea4511bcb4cd5961f322f27605725.png)

Unfortunately, `wpscan` doesn't detect this as a WordPress site because `/wp-admin` is down. 

Next, let's move on to trying the credentials found in the pastebin. 

![4568d83f3872e82e5a6bcffd2f254aa9.png](/images/vh-relevant1/7feb241f6b0c4a0d8c3a8fd60451f6d2.png)

We eventually find that `patsy` is able to SSH to the box, but the account requires a verification code. This should be that TOTP token we found earlier. 

Let's pop the TOTP secret key into [KeePassXC](https://keepassxc.org/) to generate an OTP for `patsy`. 

*I'm not entirely sure if there's another way to do this without using KeePassXC, but I use it as my password/OTP manager, so that's the only way I know how to generate OTPs.*

![6f9e1d18eb1054e06ab8854e6d50411e.png](/images/vh-relevant1/19c3828b4df24dd0a3396d15c6046854.png)

![c3e856d38aba4a804ece2f26b75071e0.png](/images/vh-relevant1/f5d0045a2f9b46d8847eff347862aae3.png)

Let's generate an OTP and try to login. 

![3722d1eeb4896afefafa5564dfcbb7b0.png](/images/vh-relevant1/9aedd8786c2f43dea5f180ebb021685a.png)

![ce4809407f91836425dd3afdb2735fd7.png](/images/vh-relevant1/ad8d667aea79482d9fc88e5f1bdb6dab.png)

Unfortunately, the `patsy` account is disabled. 

### 3. Exploiting WordPress File Manager 6.7

Next, let's try to scan for WordPress plugins using `nmap`'s `http-wordpress-enum`.  

```
sudo nmap -p80 192.168.32.20 --script http-wordpress-enum --script-args search-limit=10000
```

![a9e2539d2bfd7b12e2f0f8de75fd10ec.png](/images/vh-relevant1/b0676af4f2da48b8a98b8629262cb10a.png)

This site has WordPress File Manager 6.7, which is [vulnerable to RCE](https://github.com/w4fz5uck5/wp-file-manager-0day). Let's try to run the exploit.  

```
python2 elFinder.py http://192.168.32.20
```

![2386e25b8a3c591b190f2b5fe96ccd23.png](/images/vh-relevant1/c0066207e15440da9ae121087f1b984b.png)

Now that we have successfully gotten RCE, let's try to `ping` ourselves to see if we can get a reverse shell. 
 
![efb9bff9a9ceae8a1f1f892f55c88fff.png](/images/vh-relevant1/ce511477fa9047b594f8e3096f10aa24.png)

Great. Let's upload the [PenTestMonkey PHP reverse shell](https://github.com/pentestmonkey/php-reverse-shell) to the box using `wget`. 

![99c62310c0415d890cecc36b8e2d1199.png](/images/vh-relevant1/9c3a17755c564888aa0134143ff2be8d.png)

Now, let's get an `nc` listener going, then move the reverse shell to `/var/www/html`. 

![84a394c9b02c7c205b47768bcf431458.png](/images/vh-relevant1/a8919df535574845853c3b35325c5ff8.png)

![aeb65d9e5d08f8c77d63323200897c68.png](/images/vh-relevant1/d3c8440f61fc4f0dbb010a6ab3130f96.png)

Navigating to `/shell.php` gets us a reverse shell connection. Nice!

### 4. More Enumeration, Exploiting Node.js REPL Compiler

First, let's check out `/etc/passwd`, specifically for users that have a login shell. 

![40ea0f39521cad0ecb4ba8ace72bb1d1.png](/images/vh-relevant1/5db33dcf36b1444a9326bab0d3674e44.png)

We have a couple. Let's take a look at some of their home directories. 

We almost missed this, but we found a note inside `/home/h4x0r/...`. 

![87199ddc5ec42a512132c40bc2ce6fb8.png](/images/vh-relevant1/f1fc19134d1648bf9eb29e51d58dd99d.png)

This seems to contain the password hash for `news`. Let's copy it to our box and crack it with `john`. 

```
sudo john --wordlist:/usr/share/wordlists/rockyou.txt news.hash
sudo john --show news.hash
```

![e9afd72ca8b35c45bfcb5c37a554fd72.png](/images/vh-relevant1/6d8bf4f8125c4defb854a143a7cdc716.png)

Sweet. We have our first proper set of credentials (not counting `patsy` since we can't use it) - `news:backdoorlover`. 

![554a7efcb1387c8ebdb85b1c11f7d350.png](/images/vh-relevant1/d1a4c42f0970455fa4b631276c41dc19.png)

Let's `su` to `news` and see what the account can do using `sudo -l`.

![81bd040006755005b0a5ddd549b5988d.png](/images/vh-relevant1/4f62e1c373f14ad79d82d1fc2a96d358.png)

Interesting. Let's see if GTFOBins have any entries on this. 

![3e7cfc4751ab951b210b2c0196b086d2.png](/images/vh-relevant1/a8b4c18e8d5840d2b225bcf34fc79c82.png)

Great, we find that [we are able to escalate privileges](https://gtfobins.github.io/gtfobins/node/) if we have `sudo` permissions on this. 

```
sudo node -e 'require("child_process").spawn("/bin/bash", {stdio: [0, 1, 2]});'
```

![8b3372626acc117859470e269081daae.png](/images/vh-relevant1/8a04e9e9ca9541c29ab03587c8346a47.png)

And we're done. 

### 5. Extras

We find this inside `mysql`. 

![63ae716dfb599a37b684b53980ee9458.png](/images/vh-relevant1/4110d218a5fb4412864495178f46c1bd.png)

I'm [never gonna let you down](https://www.youtube.com/watch?v=dQw4w9WgXcQ). 