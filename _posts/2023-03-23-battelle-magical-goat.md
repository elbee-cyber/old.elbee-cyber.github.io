--- 
layout: post 
title: Feed the Magical Goat (Battelle)
--- 
 
Published on: **2023-03-23** and last edited on: **2023-03-23** 

# Table of contents 
1. [Reversing](#reversing) 
2. [Angr Solve](#angr) 
 
 
## Feed the Magical Goat (Battelle)
 
The following is a writeup for a reverse engineering challenge made by Battelle as one of their cyber career challenges. This challenge explores the use of <a href="https://angr.io">angr</a> and it's ability to emulate file systems for the use of symbolic data. If you are unfamiliar with Angr and the concept of symbolic execution, I made a <a href="https://youtu.be/QkVzjn3z0iw">YouTube</a> video exploring and explaining this which I (obviously) highly recommend you watch.
<a name="reversing"></a> 
# Part 1: Reversing
A zip file containing a 32-bit, unstripped ELF is provided as part of the challenge. Running the binary outputs a bunch of text and then ends with the binary deleting itself. 
<p align="center"> 
  <img src="/assets/2023-03-23/Screenshot_2.png" /> 
</p> 
Starting a Binja project and looking through the strings reveals the following:
- File operations
- A filename
- A flag format string (Character by character, flag is likely calculater within the binary)
<p align="center"> 
  <img src="/assets/2023-03-23/Screenshot_3.png" /> 
</p> 
<p align="center"> 
  <img src="/assets/2023-03-23/Screenshot_4.png" /> 
</p> 
<p align="center"> 
  <img src="/assets/2023-03-23/Screenshot_5.png" /> 
</p> 

Viewing main a function is called which interacts with what is likely the expected file called `give_offering`.
<p align="center"> 
  <img src="/assets/2023-03-23/Screenshot_6.png" /> 
</p> 
The function first opens "chow.down" and assigns the stream to eax. The following conditional checks if the operation was not successful via checking the file descriptor in eax. If it wasn't, the program closes the file descriptor, unlinks the binary (deletes it), prints the outro and calls exit. From here on I will refer to this blob as the fail block. Assuming this conditional was false, the file is allocated onto the heap at eax_2. The next conditional checks if eax_2 is 0x40, if true a hint is printed, both the elf and chow.down are deleted and the chunk is freed, followed by a fail block. The next conditional returns the pointer to the file contents and is the path I have to follow in order to continue program execution. It checks if the more than 0xf bytes were read.
<p align="center"> 
  <img src="/assets/2023-03-23/Screenshot_7.png" /> 
</p> 
Returning to main, multiple conditions are checked against various offsets of the file content. If code execution continues without a conditional being true, the flag is printed using these file content offsets, of which I assume were operated on by the functions in the conditions.
<p align="center"> 
  <img src="/assets/2023-03-23/Screenshot_8.png" /> 
</p> 
Looking at just one of the functions reveals that it is quite complicated.
<p align="center"> 
  <img src="/assets/2023-03-23/Screenshot_9.png" /> 
</p> 
Manually reversing these functions would be significantly detremental to my mental health, so instead I'll use symbolic execution to find an execution path that leads to the flag print and what the file contents need to be in order for this path to execute. Angr is a symbolic execution engine for python that utilizes microsoft's Z3 solver and a simulation manager to manage execution states. It is also capable of file system emulation. Using this feature will be simpler than alternative methods of symbol placement such as directly in memory.
<a name="angr"></a> 
# Part 2: I'm Angry FS
The following is my solve script:
```python3
import angr,claripy,sys

p = angr.Project("./billygoat")
s = p.factory.blank_state(addr=0x8048f46)

symbol = claripy.BVS('file',8*0xf)
f = angr.storage.SimFile("chow.down", content=symbol)
s.fs.insert("chow.down",f)

def win(state): # Check stdout for "flag{" and print flag
        out = str(state.posix.dumps(sys.stdout.fileno()))
        if "flag{" in out:
                print("Flag: flag"+out.split("flag")[1][:-3])
        return "flag{" in out

simgr = p.factory.simulation_manager(s) # Create simulation manager
simgr.explore(find=win, avoid=0x80490ce) # Find path to flag with win, avoid fail block

print(b"Input: "+simgr.found[0].posix.closed_fds[0][1].concretize()) # Print contents of closed file descriptor from the found state
```

Let's step through it to understand it better.
The first few lines create the Angr project, create the initial state which starts in `give_offering` (0x8048f46) and creates a symbol whose size is based on the constraint within that function.
```python3
p = angr.Project("./billygoat")
s = p.factory.blank_state(addr=0x8048f46)

symbol = claripy.BVS('file',8*0xf)
```
Next a SimFile object is created with the name "chow.down" and whose content is the symbolic data just created. It is then inserted into the simulated file system.
```python3
f = angr.storage.SimFile("chow.down", content=symbol)
s.fs.insert("chow.down",f)
```


