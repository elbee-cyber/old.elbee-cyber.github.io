---
layout: post
title: Cracking the DEFCON 30 Badge Firmware
---

Physical firmware extraction and reverse engineering of the DEFCON 30 badge.

## Cracking the DEFCON 30 Badge Firmware - 2022-11-22

Before beginning this post there are some important things to note. At the time of this post, I am very inexperienced in the world of hardware, IoT, firmware extraction and firmware analysis. Because of this, the majority of my process, including the use of the physical equipment used to interact with the flash chip, was done via trial and error. This is a very dirty article by someone who barley knows what they're doing, but I think it is still important to post this to demonstrate the learning process.

### Backstory and Objective
Once upon a time I was very excited to fly to Las Vegas and attend <a href="https://defcon.org/html/defcon-30/dc-30-index.html">DEFCON 30</a> the annual go-to security conference. This was going to be my first conference and I had purchased pre-registration tickets, which was a new system that DEFCON was using to allow attendees to guaranttee a badge and semi-skip LINECON. However, because of a personal emergency that appeared last minute, I was unable to attend and I gifted my pre-registration to my good friend and mentor <a href="https://ctftime.org/user/3509">playoff-rondo</a>. Later on when I was catching up with him he gave me his badge. DEFCON badges usually have some sort of challenge on them and this year's badge was some sort of piano keyboard. <a href="https://github.com/Kybr-git/DC30-Badge-Challenge-Writeup/blob/main/README.md">This is the writeup made by the attendee that solved the badge challenge and won a black badge</a>, as you can see it is meant to be solved in part by interacting with other attendees who have a different variant of the badge. This is obviously not possible for me, so my goal was to reverse engineer the badge and find what key combo needs to be pressed in order to win the first part of the challenge.
