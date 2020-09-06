---

title: Booting Into Writable Filesystem Using Grub
layout: post
date: 2020-09-06 20:30:00 +0800

---

![ffe0dedfae75df5f87bdd716292b51ac.png](/images/meta-goofed/b489e130c20c4ff88f2a6b8c85748865.png)

### 0. Preface

This is a very different post than the usual HackTheBox/VulnHub write-ups on this site. I managed to brick my Kali VM while testing out an exploit locally, which unfortunately, involves manually editing `/etc/sudoers`. 

I realised I done goofed when I couldn't run `sudo`, and I also didn't set a password for the `root` user. 

...and the last snapshot of the VM was taken a month ago.

Note that there will be *some* swearing involved. 

<!--excerpt-->

---

### 1. How to Goof

Simply (and stupidly), editing your `/etc/sudoers` file without testing it out using `visudo` first. 

If you edit `/etc/sudoers` via `visudo`, it will warn you if you made a mistake, and will ask you what to do next. 

![276a40356353d33736977364656a603b.png](/images/meta-goofed/bb5fbc33505b4465b899d9bc69d4304d.png)

Stupidly, I just ran the following: 

```bash
sudo sed -i -e '$akali ALL=[ALL:ALL] NOPASSWD:ALL' /etc/sudoers
```

Notice the mistake? 

It's supposed to be `( )` instead of `[ ]`. 

And this is when you know you've fucked up. 

![c820aa6bbeabc3a2d5b05b327c36fb46.png](/images/meta-goofed/f06d5a3e17c94e598baa53364464e925.png)

Now you can **P A N I C**. 

### 2. The Fix

I desperately tried to `su root` with every password I can think of, but of course, it doesn't work because there's no password set in the first place. 

![c3f578ead4d0195cdba712b07341191f.png](/images/meta-goofed/73baf514d27a495d9529547b03eea5d3.png)

So, I tried to boot into single user mode in the hopes that I can edit `/etc/sudoers` with the root user. 

To do so, I had to edit the bootloader script. 

![f4c6f0613193fc5b794ec9170b463a8e.png](/images/meta-goofed/eafd53c1e1c842d1861d09937c76d0cd.png)

Press `e` to edit. 

Find the following line and add a `1` behind it. 

```bash
linux	/boot/vmlinuz-5.7.0-kali3-amd64 root=UUID=114c498f-de75-44bb-a5ec-6339282d4171 ro quiet splash
```

![3f1324f16c29657d2bfe1bd88d2ae948.png](/images/meta-goofed/f23e7742359142e7aee842c3f88dff61.png)

Press Ctrl+X to boot.

![332dcebeedabe51191cc888591dbfcfa.png](/images/meta-goofed/741e3e39e15b4e57ace90c6658d62b43.png)

**F u c k**.

Cue more **P A N I C**.

After some research, I found that you could append `init=/bin/bash` instead, and change `ro` to `rw` to boot into `bash` directly with a writable filesystem. 

![2fb93f28b97fe222a2db5d5efea61abc.png](/images/meta-goofed/76313cde46e948b482ef65bff4e6b922.png)

Ctrl+X.

![4587e63559bb1922561630211d2f365c.png](/images/meta-goofed/924158fb17b843b98a0f0314e6782f61.png)

![6f7487dbbb1d674405e1c0710f72dc66.png](/images/meta-goofed/a0ad24d214234e2c9dbc6bd9a648ae7f.png)

Now to revert the sudoers file, this time using `visudo`. 

![bcc79fa455492ca5a8f484a4cde93e4f.png](/images/meta-goofed/d24debeb521c4d78affd6affccbc1de9.png)

Next to power off the machine and boot it again normally. 

![42cce469fc2db134949bace2ee2521b4.png](/images/meta-goofed/659b00e6e4b9445db792f4d7cc433387.png)

Lesson learnt.