---
title: Recur UTCTF
author: pwndumb
date: 2021-03-15 11:10:00 +0800
categories: [Reverse,Linux]
tags: [reverse,ctf]
---

# The Challenge

The chall gave me a `ELF 64 binary` called `recur` . The objective is clear: **get the flag**.

> [recur binary](https://github.com/pwndumb/pwndumb-docker/tree/main/ctf-solve/utctf-2021/reverse/recur)

## Dinamic Analysis

Running the program I saw the initial words of `flag`.

![image-20210315143806567](https://raw.githubusercontent.com/pwndumb/pwndumb.github.io/master/assets/img/commons/recur/image-1.png)

Try strings not works. Not this time. 😅

## Static Analysis

Using strings and other related tools is a waste of time.  So I put the binary in [rizin](https://rizin.re). This tool is so amazing that turn a job of reverse binary much more easier. 

<img src="https://raw.githubusercontent.com/pwndumb/pwndumb.github.io/master/assets/img/commons/recur/image-2.png" alt="image-20210315144226291" style="zoom:67%;" />

In 1 there is a `cmp` intruction that compare what have in `var_14h` with `0x1b = 27`.  In 2 I the `flag` encoded  is put in `rdx`. After the program puts `var_14h`, in `eax` , multiply and save the result in `eax` and call `recurrence`.The return of function is `xored` with the  `value` in  `flag[index]` array.  The whole picture is a  classical `loop` and `var_14` is a index for the loop. Let me rename that and continue. 



# recurrence function

  

<img src="https://raw.githubusercontent.com/pwndumb/pwndumb.github.io/master/assets/img/commons/recur/image-3.png" alt="image-20210315150224257" style="zoom:67%;" />	



The function compare the `count_loop`  with 0, if it equal return is 3, if not, compare with 1 and if is equal return 5. Otherwise the function call itself with `count_loop - 1` and  `cunt_loop -2` :

```c
recurrence(0) = 3
recuurence(1) = 5
  
recurrence(2) = ?
```

<img src="https://raw.githubusercontent.com/pwndumb/pwndumb.github.io/master/assets/img/commons/recur/image-4.png" alt="image-20210315150814377" style="zoom:67%;" />



After examine this assembly code sometimes I not figure out what was doing so I use the `rizin plugin`   [rz-ghidra](https://github.com/rizinorg/rz-ghidra). Now the things become clear:

<img src="https://raw.githubusercontent.com/pwndumb/pwndumb.github.io/master/assets/img/commons/recur/image-5.png" alt="image-20210315152004517" style="zoom:80%;" />



So,  I now what is `recurrence(2)`:

```c
recurrence(0) = 3
recuurence(1) = 5 
recurrence(2) = recurrence(2-1) * 2 + recurrence(2-2) * 3
  						= recurrence(1) * 2 + recurrence(0) * 3 = 5 * 2 + 3 * 3 = 19
recurrence(3) = recurrence(3-1) * 2 + recurrence(3-2) * 3 
  						=  recurrence(2) * 2 + recurrence(1) * 3 
  							 reccurrence(2) = recurrence(2-1) * 2 + recurrence(2-2) * 3
```



The  program hangs because recursive functions call itself too much times. The function not store previous values because it was written without **memoization**.🤔

> Take me too long time to accept this. My first ideia was transform the recursive function in a iterate one.

<iframe src="https://giphy.com/embed/11ahZZugJHrdLO" width="480" height="428" frameBorder="0" class="giphy-embed" allowFullScreen></iframe><p><a href="https://giphy.com/gifs/what-the-fuck-11ahZZugJHrdLO">via GIPHY</a></p>

# Memoization 



What the hell is that ? In a dumb word is a techinique of optimization that allow run recursive function much more faster than usual way.  How ? Using a simple trick : keep the result of a function saved in some sort of data structure that you can check fast  if the function was already calculate. Python has a nice library to do that or you can do by hand. In this case , just keep the result of `recurrence` in a dictionary . Change the head of function too. It will  check if the  `recurrence[count_loop]` was previous calculate. 

``` python
recurrence_cache={}
def recurrence(n):

    if n in recurrence_cache:
        return recurrence_cache[n]
    if n ==0:
        value = 3
    if n == 1:
        value = 5
    elif n > 1:
        value  = recurrence(n-2) * 3 + recurrence(n -1) * 2
        #print("value = {value")
    
    recurrence_cache[n] = value
return value     
```



We save the value in `recurrence_cache` that is   dictionary. When function is called the first instruction is check is `count_loop` was in `recurrence_cache`. If its jus return the value otherwise caculate the value and save in `recurrence_cache`.

# Get Flag



So I now how solve the problem of hang function, but what the program does with this value ? Come back to `rizin` :



<img src="https://raw.githubusercontent.com/pwndumb/pwndumb.github.io/master/assets/img/commons/recur/image-7.png" alt="Screen Shot 2021-03-15 at 4.53.19 PM" style="zoom:67%;" />

 The program `xor`  the result of `recurrence` with the letter is in `flag[count_loop]`. The result is saved in `eax`. Next the program put the value of `al` that is 8 bits long in `eax` and set this as argument in `edi` for `putchar` function.  

## decode.py

The main  ideia for get the flag is:

1. rewrite `recurrence`  funtion using memoization;
2. iterate over encoded flag and xor with result of recurrence function;
3. get  part that correspond to `al` register and save.
4. print the flag. 
5. get the points.🎉

All steps are in the final script. I have to mention that I use [Cutter](https://cutter.re) tool for get the flag in hexadecimal. I know the `rizin` can do it, but I'am too lazy.  

<img src="https://raw.githubusercontent.com/pwndumb/pwndumb.github.io/master/assets/img/commons/recur/image-6.png" alt="image-20210315154102523" style="zoom:67%;" />



```python
#! /usr/bin/python3
from ctypes import *

# keep the previous calculate values
recurrence_cache={}

def recurrence(n):

    # check if recurrence(n) already in cache
    if n in recurrence_cache:
        return recurrence_cache[n]
    if n ==0:
        value = 3
    if n == 1:
        value = 5
    elif n > 1:
        value  = recurrence(n-2) * 3 + recurrence(n -1) * 2
    
    # save the value in recurrence_cache before return function
    recurrence_cache[n] = value
    
    return value       

def main():
    flag_encoded = [0x76,0x71,0xc5,0xa9,0xe2,0x22,0xd8,0xb5,0x73,0xf1,0x92,0x28,0xb2,0xbf,0x90,0x5a,0x76,0x77,0xfc,0xa6,0xb3,0x21,0x90,0xda,0x6f,0xb5,0xcf,0x38]
    flag_decoded= []

    # iterate over encoded flag
    for i in range(len(flag_encoded)):

        rax = recurrence(i*i)
        ebx= c_int32(rax).value ^ flag_encoded[i]
        bx = c_int8(ebx).value
        flag_decoded.append(bx)
    
    flag=''.join(chr(i) for i in flag_decoded)
    print(f"[+] flag: {flag}")

if __name__=='__main__':
    main()

```



<img src="https://raw.githubusercontent.com/pwndumb/pwndumb.github.io/master/assets/img/commons/recur/image-8.png" alt="image-20210315154102523" style="zoom:67%;" />

# Related Links 

[Recursion, the Fibonacci Sequence and Memoization || Python Tutorial || Learn Python Programming](https://www.youtube.com/watch?v=Qk0zUZW-U_M&t=1s)
[https://en.wikipedia.org/wiki/Memoization](https://en.wikipedia.org/wiki/Memoization)

# Tools 

- [rizin.re](https://rizin.re)
- [cutter.re](cutter.re)
- [rz-ghidra](https://github.com/rizinorg/rz-ghidra)
- [pwndocker](https://github.com/pwndumb/pwndumb-docker.git)
- [flameshot](https://github.com/flameshot-org/flameshot.git)

