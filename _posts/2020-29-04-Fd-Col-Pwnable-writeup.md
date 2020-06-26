---
title: FD and Collision  pwnables.kr writeup made by a dumb !!!
author: dumbx90
date: 2020-05-29 14:10:00 +0800
categories: [Blogging, Pwn, Writeup]
tags: [pwn,linux,ctf]
---

# Pwnable.kr 



## Linux File IO 

***

## File Descriptor

> A unique non negative number that identifies an open files handled by a process in computer operation system.

File Descriptor  are primary used in Unix system, but nowadays are used by the modern operation system.  In POSIX system all process have at least three file descriptor: Input , Output and Error.

###  Index File Descriptor Table

The file descriptor are indexed into a file descriptor table handle by the kernel. Each process handle with our file description table. If your process open 10 files,so they will be handle with 10 files. In table are record what mode the file or other resource are open: writing., reading, reading-write and so on. There is no relation in a process file description with a number n, and other processes with a file descriptor with number n.  Beside the same file descriptor name, they are two file, handled by the different process in the system.

Beside the better explanation of Linux File Descriptor, lets dig in the first challenge.



## fd 

```bash
Mommy! what is a file descriptor in Linux?

* try to play the wargame your self but if you are ABSOLUTE beginner, follow this tutorial link:
https://youtu.be/971eZhMHQQw

ssh fd@pwnable.kr -p2222 (pw:guest)
```

After log in the machine, we see three files in directory:

```bash
fd@pwnable:~$ export TERM=xterm
fd@pwnable:~$ ls --color -lh
total 16K
-r-sr-x--- 1 fd_pwn fd   7.2K Jun 11  2014 fd
-rw-r--r-- 1 root   root  418 Jun 11  2014 fd.c
-r--r----- 1 fd_pwn root   50 Jun 11  2014 flag
fd@pwnable:~$
```

We have permission to execute `fd` , read `fd.c` , but we don't have permission to read flag.  Lets analyze the source code.


#### fd.c

```c
1	#include <stdio.h>
2	#include <stdlib.h>
3	#include <string.h>
4	char buf[32];
5	int main(int argc, char* argv[], char* envp[]){
6		if(argc<2){
7			printf("pass argv[1] a number\n");
8			return 0;
9		}
10		int fd = atoi( argv[1] ) - 0x1234;
11		int len = 0;
12		len = read(fd, buf, 32);
13		if(!strcmp("LETMEWIN\n", buf)){
14			printf("good job :)\n");
15			system("/bin/cat flag");
16			exit(0);
17		}
18		printf("learn about Linux file IO\n");
19		return 0;
20	
21	}
```



The program get the first argument and in the line 10,  transform that in integer,subtract from 0x1234 (4660 in decimal). The result will be a file descriptor to read the variable `buf` with 32 bytes in the line 12. In the line 13 the program compare the `buf`variable with the string "LETMEWIN\n". Pay attention, we don't have  any control in `buf`variable for now. The  string "LETMEWIN\n" has 32 bytes, the same size of `buf`variable. 

##### Main Idea

The variable `fd` is used as file descriptor, we can control what number the `fd` will have because we control  the first argument. We already know the three most important Linux file descriptor: 0 for Standard Input  , 1 for Standard Output and 3 for Standard error. 

The standard input is keyboard, so if the `fd` be 0, we can control the `buf` variable,  typing "LETMEWIN" and press "Enter" in keyboard we read the flag. For `fd` be 0 , just type `./fd 4660` as we can see in the line 10 of source code.

```bash
fd@pwnable:~$ ./fd 46
learn about Linux file IO
fd@pwnable:~$ ./fd 4660
LETMEWIN
good job :)
mommy! I think I know what a file descriptor is!!
fd@pwnable:~$
```



# Collision



The challenge present us with some sort of cryptography program with a self development algorithm. What could be wrong ? 

```bash
col ./col ADASDJAHSDAJSD
passcode length should be 20 bytes
```

So, lets look in the source code:

### col.c

```bash
   1 #include <stdio.h>
   2 #include <string.h>
   3 unsigned long hashcode = 0x21DD09EC;
   4 unsigned long check_password(const char* p){
   5     int* ip = (int*)p;
   6     int i;
   7     int res=0;
   8     for(i=0; i<5; i++){
   9         res += ip[i];
  10     }
  11     return res;
  12 }
  13
  14 int main(int argc, char* argv[]){
  15     if(argc<2){
  16         printf("usage : %s [passcode]\n", argv[0]);
  17         return 0;
  18     }
  19     if(strlen(argv[1]) != 20){
  20         printf("passcode length should be 20 bytes\n");
  21         return 0;
  22     }
  23
  24     if(hashcode == check_password( argv[1] )){
  25         system("/bin/cat flag");
  26         return 0;
  27     }
  28     else
  29         printf("wrong passcode.\n");
  30     return 0;
  31 }
```

 The code is straightforward: The program only show the flag if the 20 bytes passcode is equal  to `hashcode = 0x21DD09EC` . The program get our input, send to check_password function. This function split the 20 bytes input  in five chunks of our bytes and then sum all. If the result was equal `0x21DD09EC` the flag is show to us.  So, the only thing we have to do is make a 20 bytes input  with five chunks of four bytes that sum is equal hashcode. Hold on for a minute and breath. What the function check_password was doing is called 2's  complements and in this case is equivalent to addition module 2<sup>32</sup>.  In simple terms we need : `e = 0x21DD09EC - (a + b + c + d) % 2^32`.
If we do something dumb and choose `a=b=c=d`, maybe this is a solution. The only  problem with this solution is  the fact of the C language not handle well with some bytes like `00`. So instead of try and error I write a really dumb python script to give me a solution:

### really dumb python script with bad programming skills 

```python
1 #!/usr/bin/python3
2
3
4 def find_collision(hash_code,number_string):
5
6     number=int(number_string,16)
7     sum_numbers = (hash_code - 4 * number) % 2**32
8
9     return hex(sum_numbers)
10
11 def main():
12
13     hash_code=0x21DD09EC
14
15     print(f"The hash code is: {hash_code}")
16
17
18     badchars=[0x00,0x0a,0x0d,0x20,0x09]
19
20     # looking for numbers avoiding badchars
21
22     for i in range(17,255):
23         if i not in badchars:
24             number_string="0x" + str(hex(i))[2:]*4
25
26             result=str(find_collision(hash_code,number_string))[2:]
27
28
29             # chunk the result in four groups of bytes
30
31             chunks = [result[i:i+2] for i in range(0,len(result),2)]
32
33
34             # see if some byte is in badchars
35
36             for n in chunks:
37
38                 flag=0
39                 hex_number='0x' + n
40                 hex_number = int(hex_number,16)
41
42                 if hex_number in badchars:
43                     flag = 1
44
45             # print only if the flag is 0, that mean the value of
46             # result doest have any forbidden byte
47
48             if flag == 0:
49
50                 print(f"the number can be = {number_string}")
51                 print(f"the key can be = {result}")
52                 exit(0)
53 if __name__ == "__main__":
54     main()
```

The program is simple. In line 18 I put all bad char in a list. In line 22 I start a loop., in line 23 I check if the hex number is in bad char list what is reveal later totally unnecessary because I start the loop in 17 decimal (0x11). Why I did  that ? To avoid the chunks with less than four bytes. In the line 24 I created a hex number with four chunks of the variable `i`. In the line 26, I send the chunks to `find_collision` functions which returns the `equation` in line 7 and save in the variable `result` . Line 31 get  the `result` variable and create a four chunks. Lines 36-44, get this chunks and check if this is the bad char list, if is, set the flag to 1 in line 43. Lines 48-52 , check the if flag is present (badchar in hexadecimal result), if not, print number and exit the program.

### Collision.py output

```bash
 $ ./collision.py
The hash code is: 568134124
the number can be = 0x11111111
the key can be = dd98c5a8
```

```bash
col@pwnable:~$ ./col $(python -c 'print "\x11" * 16 + "\xa8\xc5\x98\xdd"')
daddy! I just managed to create a hash collision :)
```



## Reference Links

- https://en.wikipedia.org/wiki/File_descriptor
- https://en.wikipedia.org/wiki/Two%27s_complement
- https://en.wikipedia.org/wiki/Modular_arithmetic
