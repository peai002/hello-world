---
title: "Why learning Operating System with Linux Arch?"
excerpt: "I was thinking why we use Arch for the OS class and here's the answer."
excerpt_separator: "<!--more-->"
categories:
  - Operating System
tags:
  - Arch
  - Linux
  - Learning Diary
mathjax: true
---

# My first attempt of learning Linux and Operating System

This semester at Columbia, I am taking [operating system class](http://www.cs.columbia.edu/~jae/4118/?asof=20170117) with Prof. Jae Woo Lee (I usually call him Jae, as this is also how most students would refer him to).

The class just began and we haven't gone to the most exciting (desperate?) part of implementing parts of the kernel. Since I still have time to take a breathe and make sure I am ready for the following weeks of 'hacking', I decide to sit down, play with the virtual machine we will be using for development, and customize it in a way that will make me very very efficient later on.

# The first big question: why Arch

So I know we are learning operating system, and by saying that in most schools I think it means to learn the operating system theories plus hand-on experience with Linux. Undoubtedly, Linux is a free, open-source masterpiece. However, given all those Linux distributions (a Linux distribution basically means an OS with Linux Kernel + package management software + this and that), with some famous name to beginners like me (Ubuntu, Redhat), what makes Arch a great choice for OS learners -- To be honest, I never knew about Arch back to 30 days before!

I think it is very important to know 'why' behind instead of blindly following the instructions from professor / online. Only after understanding the rationale behind can I fully appreciate the convenience and the greatness of the tool.

It took me some Googling and Googoogling (meaning Google whatever I Googled, a depth-2 search) to find 3 most important reasons. As I am still new to this, this post is mostly a summarization. I will update more later after I get more hands-on experiences and have more say about this.

# The first and foremost: Really good wiki pages

Okay this may not sound like a killer feature of this distribution, but trust me it is. Usually when people don't get into trouble, long, detailed Wiki pages are considered as verbose and boring. But when it comes to a place where you need to hack, break and fix things, you will actually want some guidance, and more, and more. For example, Arch installation is such a pain (comparatively), but it is compensated with a very good installation guide [here](https://wiki.archlinux.org/index.php/Installation_guide). For a learner, nothing is better than good documentation. It is your last resort, after google, stackoverflow and ask people in the dev community.

# Light-weight, yet highly customizable

I read about the principle of Arch, one of them being "Simplicity". As someone who had experience with pirated Windows XP, I understand the feeling when your OS comes with something that you don't need, but you cannot fully uninstall them. So Arch features being small and only contains those must-have, and leaves the rest for users to install based on their needs. Again this is great for OS learners because first-of-all, you don't want your virtual box to take up your entire hard disk, and at the same time, you want to have all the necessary tools for development. It is also a great learning experience to install, configure those tools.

# Pacman + AUR

Speaking of tools, I saw many comments online about the pacman package management system that Arch adopts. I do not have prior experience in shipping packages, but I did use homebrew and apt-get for some time. So one of the general comments I heard about is that pacman, being a binary repository management, is more modern in terms of its software architecture. It allows this C program to achieve its core functionality nicely. Also it is said that pacman's command deign is more user friendly. That means, all the commands are more standardized. They all look like `pacman [Some Main Action] [Flags] target`. Last but not least, `pacman -Syu` is a one-line command that helps you update your system. This sounds pretty cool! In addition, many recommend yaourt as a front-end for pacman. I will definitely have a try!

At the same time, the community-driven Arch User Repository (AUR) seems to be another big reason why people choose Arch. It contains extensive repositories that users uploaded. As mentioned in [Arch Wiki](https://wiki.archlinux.org/index.php/Arch_compared_to_other_distributions):

> Debian is the largest upstream Linux distribution with a bigger community and features stable, testing, and unstable branches, offering over 43,000 packages. The available number of Arch binary packages is more modest. However, when including the AUR, the quantities are comparable.

---
Now Arch seems to be a pretty fun OS to learn and play with. Let me come back later with more personal sharing. Stay tuned!
