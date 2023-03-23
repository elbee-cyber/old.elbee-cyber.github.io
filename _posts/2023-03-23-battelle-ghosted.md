--- 
layout: post 
title: Ghosted (Battelle)
--- 
 
Published on: **2023-03-23** and last edited on: **2023-03-23** 
 
 
 
 
 
 
## Ghosted (Battelle)
 
The following is a writeup for a easy/introductory binary exploitation challenge made by Battelle as one of their cyber career challenges.

Running checksec on the given binary reveals a 64-bit binary with all memory mitigations enabled. Further viewing of the elf will continue in Binja.
<p align="center"> 
  <img src="/assets/2023-03-23-0/Screenshot_13.png" /> 
</p> 

The main function prints text to the screen and handles the user options. It also allocates `current_itinerary` on the heap and exits with the `fly_home()` function.
<p align="center"> 
  <img src="/assets/2023-03-23-0/Screenshot_14.png" /> 
</p> 

Looking at `fly_home`, the function compares the value at `current_itinerary` to `itinerary` and prints the flag if equal, else `exit` is called. `itinerary` has the value `"|1. MLB|\n|2. TPA|\n|3. CLT|\n|4. IAD|\n|5. CMH|\n"`.
<p align="center"> 
  <img src="/assets/2023-03-23-0/Screenshot_15.png" /> 
</p> 

`schedule_flight` asks for input and copies the flight-specific formatted input to a pointer that is not utilized, after 9 bytes of buffer are copied to `current_itinerary`. Neither the pointer or the buffer are declared with an initial value. There is a buffer overflow as input is only 32 bytes. The overflow corrupts the next variable on the stack, buffer. The 9 bytes copied later in the function are enough for a single flight detail. eg: `""|1. MLB|\n"` is 9 bytes long.
<p align="center"> 
  <img src="/assets/2023-03-23-0/Screenshot_16.png" /> 
</p> 

At the time of this post, BinaryNinja does not assume that variables are character arrays, unlike Ghidra which does this implicitly. I'd rather it did do this in lieu of having to continuously view the stack frame. I wrote a <a href="https://github.com/elbee-cyber/analyze_char_arrays">quick plugin</a> using the BinaryNinja API that will parse void variables and determine if they are a string by analyzing call references and it is currently available on the plugin manager.
My final exploit utilizes the overflow in `schedule_flight` by calling it multiple times to build out the itinerary string in `current_itinerary` and pass the final check in `fly_home`.
```python3
...
itinerary = "|1. MLB|\n|2. TPA|\n|3. CLT|\n|4. IAD|\n|5. CMH|\n".split("\n")[:-1]

# Use overflow to create correct itinerary
for i in itinerary:
    p.sendlineafter("complaint\n\n","2")
    p.sendlineafter("destination.\n","C"*32+i)

# Fly home
p.sendlineafter("complaint\n\n","3")
...
```
