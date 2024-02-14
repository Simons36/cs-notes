#notes #cybersecurity #operating-systems 


This note goes over **buffer overflow vulnerabilities**, and how exploits can be conducted using them. If you wish to go over **security mechanisms** to mitigate attacks using buffer overflows (aka **dynamic protection**), please check [[Dynamic Protection|this note]].

---

Buffer overflows are anomalies in computers, that happen when a program tries to write to a certain **contiguous memory space** (buffer) more data than the **allocated data** to that buffer (resulting in a **buffer overflow**).

But why are buffer overflows dangerous? Buffer overflows can happen accidentally (due to bugs), and its effects have **no impact security-wise**. However, an attacker can intentionally cause a buffer overflow, with the objective of **running code with superuser privileges.** An attacker can also use this to **steal data** (buffer overread in this case).

# Cause

The cause for buffer overflows has to do with how the **C/C++** languages work; ==these languages do not verify if data being written exceeds the capacity of a buffer/array/vector.== Buffer overflows cannot be exploited in languages like **Java/C#**, as these languages do this type of verifications at runtime.

The problem, whilst being related with C/C++, is present in a **set of vulnerable functions** that should never be used, like: ^9d1ca4

- _gets()_ 
- _strcpy()_
- _sprintf()_
- _scanf()_

# Defending against BOs

The solution against buffer overflows attacks is simple: ==always perform bounds checking==. This can be done manually, or through replacing unsafe functions (the one above) by **safe functions** (these perform bounds checking).

## Example: _gets()_

**Wrong:**
Never use _gets()_!
```c
char buf[1024];
gets (buf);
```

**Right:**

```c
char buf [BUFSIZE];
fgets (buf, BUFSIZE, stdin);
```

## Example: _strcpy()_

**Solution 1:**

```c
if (strlen (src) >= dst_size) {
	/* throw an error */ 
} else 
	strcpy (dst, src)
```

**Solution 2:**

```c
strncpy (dst, src, dst_size - 1); 
dst [dst_size - 1] = ‘\0’;
```

**Solution 3:**

```c
dst = (char *) malloc (strlen(src) + 1);
strcpy (dst, src)
```

# Stack Smashing

Stack smashing is the classical buffer overflow attack: here is an example of code that is vulnerable to this attack:

<pre><code>
void test(char *<span style="color:lightgreen">s</span>) { 
	char <b><span style="color:lightskyblue">buf</span></b>[10]; // gcc stores extra space
	<b><span style="color:orange">strcpy(</span><span style="color:lightskyblue">buf</span><span style="color:orange">, </span><span style="color:lightgreen">s</span><span style="color:orange">); // does not check buffer’s limit</span></b>
	printf("&s = %p\n&buf[0] = %p\n\n", &s, buf);
} 

main(int argc, char **argv){
	test(argv[1]);
}
</pre></code>

^fd52c1

Here, *strcpy* simply copies the content of **<span style="color:lightgreen">s</span>** into **<span style="color:lightskyblue">buf</span>**, without checking the length of <span style="color:lightgreen">s</span>, which can lead to content being written **after** the allocated space for **<span style="color:lightskyblue">buf</span>**. These writes are used in stack smashing attacks, and the attacker can use this for several effects; to understand what can the attacker do, we first need to understand **the stack layout**.

## Stack Layout

The following image depicts the general layout of the stack:

![[Stack Layout with arrows.png]]
**Fig.1:** Stack Layout; the red arrows point to the "targets" of stack smashing attacks

In stack smashing attacks, the overflow can happen in two places:

- **Local vars**
- **Saved EIP**

The possible effects that this can have are:

- **Change state of program**
- **Crash program**
- **Execute code**

Now that we know the general layout of the stack, we will take a look at the assembly code of the **[[Buffer Overflows#^fd52c1|code above]]**.

## Stack Smashing Attack

<pre><code>
test 
	push ebp
	mov ebp,esp
	sub esp,0x14    // <span style="color:orange">allocate buffer</span>
	
	----------------------------------------------------- <span style="color:orange">strcpy part</span>

	mov eax,DWORD PTR [ebp+0x8] // <span style="color:orange">corresponds to the loading of </span><span style="color:lightskyblue">s</span><span style="color:orange">.
	                            Notice that </span><span style="color:lightskyblue">s</span> <span style="color:orange"> is 8 chars below
	                            the ebp (return address)</span>
	
	sub esp,0x8 
	push eax //<span style="color:orange"> add &s to stack </span>
	
	lea eax,[ebp-0x12] // <span style="color:orange">corresponds to the loading of </span><span style="color:lightgreen">buf</span><span style="color:orange">.
						Notice that </span><span style="color:lightgreen">buf</span> <span style="color:orange"> is 0x12 = 18 chars above
						the ebp (return address)</span>
	
	push eax //<span style="color:orange"> add &buf to stack </span>
	call strcpy 
	-----------------------------------------------------
	
	... 
	ret // <span style="color:orange">jumps to return address</span>
main: 
	... 
	call test
</pre></code>

> ___Note:___ Notice how memory space for <span style="color:lightgreen">buf</span> is allocated _**above**_ the return address, and memory space of <span style="color:lightskyblue">s</span> is _**below**_ return address. This is because of the [[Stack Layout with arrows.png|stack layout]] shown previously: if you look at that figure, in the stack frame for the first function, we can see that <span style="color:green">local vars function</span> is above the return address, and <span style="color:orange">parameters function</span> in the main stack frame (which is the case of <span style="color:lightskyblue">s</span>), is below the return address of 1st function.

There are a couple of important things we can take from this assembly code. In the first two lines we can see that we "save" the previous function's (_`main()`_) stack pointer in the **`ebp`** register. Then, we proceed to allocate 18 bytes for <span style="color:lightgreen">buf</span> (right above the saved **`ebp`** and **return address** (saved **`eip`**)). Therefore, when we **overflow** <span style="color:lightgreen">buf</span>, the first affected memory locations correspond to **`ebp`** and **`eip`**.

Up next is an image that makes this much clearer:

![[Stack layout in allocation of variables.png]]
**Fig.2:** Location of variables in stack

From this we can take the following conclusion: ==by overflowing <span style="color:lightgreen">buf</span>, we can alter the content of **ebp**, and potentially the **return address** of the function.== But what is the purpose of changing the return address to an attacker? The answer is that, if the attacker provides the right input, he can effectively **call other functions** that wouldn't be called in the normal execution of the program, thus **controlling the flow** of the program.

Let's take a modified version of the [[Buffer Overflows#^fd52c1|previously provided code:]]

<pre><code>
<span style="color:red">
void cannot(){ 
	puts("This function cannot be executed!\n");
	 exit(0); 
} 
</span>

void test(char *<span style="color:lightgreen">s</span>) { 
	char <b><span style="color:lightskyblue">buf</span></b>[10]; // gcc stores extra space
	<b><span style="color:orange">strcpy(</span><span style="color:lightskyblue">buf</span><span style="color:orange">, </span><span style="color:lightgreen">s</span><span style="color:orange">); // does not check buffer’s limit</span></b>
	printf("&s = %p\n&buf[0] = %p\n\n", &s, buf);
} 

main(int argc, char **argv){
	<span style="color:red">printf("&cannot = %p\n", &cannot);</span>
	test(argv[1]);
}
</pre></code>

The question is: **are we able to call _cannot_?** Here is what we are trying to achieve, in a shortened version of the assembly code of this program:


![[return address subversion.png]]
**Fig.3:** Can we call <span style="color:red">cannot</span>?

To call <span style="color:red">cannot</span>, we first need to know its address (can try to guess). If the address of <span style="color:red">cannot</span> is, for example, **`0x80484b6`**, we can successfully redirect the flow of the program with the following input:

```python
b"x"*22 + b”\xb6\x84\x04\x08"
```


Here we assume we know the address, but in a real world scenario, how can an attacker know the address? It depends whether the attacker **has access to the code:**

- **With the code:** Analyze memory (_gdb_)
- **Without the code:** Trial and error

### Code Injection

In the [[Buffer Overflows#Stack Smashing Attack|previous chapter]] we saw how we could use stack smashing to alter the **control flow** of a program; however, this is not the only thing we can do, as it is possible to **inject shell code**. To way we do this depends on the OS:

- In Unix, make program give a **shell:** _/bin/sh_
- In Windows, install rootkit/RAT

#### Code Injection in Unix

In Unix, the following code can span a shell:

```c
char *args[] = {“/bin/sh”, NULL}; 
execve(“/bin/sh”, args, NULL};
```

This corresponds to the following assembly code:

<pre><code>xor %eax, %eax                       // %eax=0
movl %eax, %edx                      // %edx = envp = NULL
movl $address_of_bin_sh, %ebx        //%ebx = /bin/sh 
movl $address_of_argv, %ecx          //%ecx = args 
movl $0x0b, %al                      //syscall number for execve() 
int $0x80                            //do syscall</pre></code>

The last two lines serve the purpose of calling the **execve syscall**. System calls serve for several purposes; the execve syscall makes the OS launch a certain program, in this case a shell. There is more info about syscalls [[Buffer Overflows#Additional Content|here]].

### Difficulties with Code Injection

Injecting code using vulnerable programs is not simple, as there are many difficulties/restraints with what an attacker can do. These are some of the main problems an attacker can encounter:

- **Lack of space** for code
	- Forces attacker to reduce code
- Code may not include **zeros/_NULL_ bytes**
	- Some functions like _strcpy()_ stop at the first **`\0`**
	- Substitute places with zeros by equivalent code:
		- <span style="color:red">mov eax, 0</span> -> <span style="color:green">xor eax, eax</span>
- Difficulties discovering **address** where code is injected
- Stack **has to be executable** (usually is)
	- If it isn't there are other ways to attack: [[Buffer Overflows#Return to _libc_|next chapter]]

## Return to _libc_

One other way to exploit buffer overflows is through inserting a new **arc** in the **control flow graph** of the program (arc is simply another node in the graph). This means inserting a new call to a function in the program, but this time **from the _libc_ library** (C standard library), and typically to the **`system()`** function of _libc_.

This type of attack is **effective against non-executable stacks**, because it calls a function of _libc_, which doesn't belong to the stack. Also, the **`system()`** function executes anything that it is passed to it, making it a good candidate for these types of attacks

The following code is an example of the attack using this (**`R`** should contain the address of **attacker supplied data**):

```c
void system(char *arg){
	check_validity(arg); //bypass this 
	R=arg;
} 

target: execl(R, …); //target is usually fixed
```

## Pointer Subterfuge

So far we have seen two types of exploits with buffer overflows: **[[Buffer Overflows#Code Injection|code injection]]** and **[[Buffer Overflows#Stack Smashing Attack|return address alteration]]**. But there is another effect we can achieve with buffer overflows: **pointer modification**; these types of exploits go by the name of **pointer subterfuge**, and there are several types:

- **Function-pointer clobbering**
	- Modify a function pointer to point to attacker supplied code
- **Data-pointer modification**
	- Modify address used to assign data
- **Exception-handler hijacking**
	- Modify pointer to an exception handler function
- **Virtual pointer smashing**
	- Modify the C++ virtual function table associated with a class

### Function-pointer clobbering

Function-pointer clobbering aims at changing a function's pointer, to point to the code desired by the attacker (usually this **malicious code** is provided by the attacker). Here is a code example:

```c
void f2a(void * arg, size_t len) {
	void (*f)() = ...; /* function pointer */
	char buff[100];
	memcpy(buff, arg, len); /* buffer overflow! We want to overwrite f with
								address of malicious code in buff*/
	f(); /* call function f*/ 
	return;
}
```

Here is a diagram of what the stack will look like in this program:

![[Stack of function pointer clobbering code example.png]]
**Fig.4:** Example of stack of code above

As we can see, if we overflow **`buff`**, the first memory chunks being affected are the chunks belonging to **`f`**. We can then change the address of **`f`** arbitrarily, and make it point to a desired location (maybe code present in **`buff`**, variable that is controlled by the attacker).

> ___Note:___ This type of attack combines well with **arc injection/return to libc** (make f point to **`system`**)

### Data-pointer modification

In data-pointer modification, the attacker aims at changing a pointer used to assign a value, with the objective of making **arbitrary memory writes**. Up next is some example code:

```c
void f2b(void * arg, size_t len) { 
	long val = ...; 
	long *ptr = ...; 
	char buff[100]; 
	extern void (*f)(); 
	memcpy(buff, arg, len); /* buffer overflow! */ 
	
	*ptr = val; /* A buffer overflow in buff can overwrite
					ptr and val, allowing us to write 4 bytes
					of arbitrary values to the memory*/
	 
	f(); /* ... */ 
	return; 
}
```

### Exception-handler hijacking

This next type of pointer subterfuge is possible in **Windows OS**, but to understand it we need to understand **how Windows handles exceptions**.

Windows keeps exception handlers in a linked list, called **Windows Structured Exception Handler** (SEH). When an exception occurs, the OS will iterate over this linked list; when it finds the correct exception handler corresponding to that exception, it will call that exception handler.

The important thing to note is that **SEH is stored in the stack** (and therefore vulnerable to buffer overflow attacks). A typical attack would:

1. Change entries of SEH to point to **attacker's malicious code**, or to **libc**
2. **Generate an exception** (e.g., an exception is generated when stack base pointer is overwritten)

To prevent this, **validity** and **integrity** checking of SEH were introduced in Windows.

### Virtual pointer smashing

Virtual pointer smashing takes advantage of a characteristic of the **C++ language**: most C++ compilers keep the functions of each class in a **_virtual function table_** (VTBL). This table is simply an array of function pointers, pointing to the functions corresponding to the methods of a certain class (there is a VTBL for each different class).

To access a VTBL, each **object** keeps a **_virtual table pointer_** (VPTR) to the its class VTBL. The attack simply consists in **altering the VPTR**, to point to **supplied code by the attacker**, or to **libc** (similar to attacks we have seen previously).

Here is a snippet of code vulnerable to this type of attack:

<pre><code>void f4(void * arg, size_t len) {
	 C *ptr = new C;
	 char *buff = new char[100];
	 <span style="color:orange">memcpy(buff, arg, len); // buffer overflow! 
	 ptr -> vf(); // call to a virtual function </span> 
	 return;
}</pre></code>

## Off-by-one errors

The main way to prevent buffer overflows is through **bounds checking**. However, we still need to be careful to **not make mistakes** while performing bounds checking. Let's take a look at the following code snippet:

```c
int get_user(char *user) { 
	char buf[1024];
	if (strlen(user) > sizeof(buf))
		 handle_error (“string too long”);
	strcpy(buf, user); 
}
```

All seems well with this code: before calling _strcpy_, we check if the length of the provided user string **is greater** than the size of the **`buf`** variable. However, there is a mistake in this code: **`sizeof(buf)`** always return 1024, but the user might provide a string of **1024 chars** **_plus_** a '\0' in the end, making **`strlen(user)`** return 1024 (_strlen_ doesn't count the '\0'), which means that the if statement returns **true**, but _strcpy_ will in fact copy 1025 bytes into **`buf`**, **_overflowing 1 byte_**. These types of overflows are called **off-by-one errors**.

But what is the possible harm caused by overflowing just one byte? To understand this we need to remind ourselves of the **stack layout:**

![[Stack Layout off-by-one error.png]]
**Fig.5:** Stack layout 

As we can see, the address immediately after **`buf`** corresponds to the **saved ebp** (base pointer). If we consider that the saved ebp's length is 4 bytes, if the attacker sets the last char of the provided string **equal to 0**, then he is setting **the most significant byte** of ebp **equal to 0**. This means that ebp is reduced by **0 to 255 bytes**. This makes the saved ebp point to a different location, and the attacker is able to **change local variables/return address** (like it is shown in Fig.5).

## Return-Oriented Programming Attacks

The [[Buffer Overflows#Return to _libc_|return to libc attacks]] we saw previously have a major impracticality to use as an exploit: **they don't work well in 64-bit CPUs** (because parameters of 1st function are put in registers). An alternative to this is **return-oriented programming** (ROP).

In ROP attacks, we analyze assembly code looking for **`ret`** calls (in machine code, **`c3`**). The sequence of instructions preceded by **`ret`** are called **gadgets**.

> **Gadget:**
> Sequence of instructions ending with **`ret`**

Gadgets might not necessarily be included in the original code: we just need to find **`c3`** instructions. Here is an example of this:

![[ret example.png]]
**Fig.5:** ret example

The job of an attacker in return-oriented programming attacks is to analyze binary code, **find instructions sequences ending in `c3`** (gadgets), and collect the addresses of these gadgets. Finally, to run the attack the attacker should:

1. Overflow the stack with addresses of gadgets
2. Overflow the stack with other data the gadgets may pick from the stack

Here is an example of this:

![[return oriented programming attack example.png]]
**Fig.6:** Example of a diagram of a return-oriented programming attack

# Integer Overflows

Integer overflows are often related to the **improper assignment** of the several data types that can be used to represent integers (signed vs unsigned, long vs short, etc.). Integer semantics are often complex, and programmers don't fully know all the details, which can lead to problems in several languages (but especially C/C++). The **4 possible problems** that can occur from assigning different types of integer types are: ^4e9398

- **Overflow**
- **Underflow**
- **Signedness error**
- **Truncation**

These problems can lead to **5 possible exploits:**

- **Insufficient memory allocation** -> BO -> attacker code execution
- **Excessive memory allocation/infinite loop** -> denial of service
- **Attack against array byte index** -> overwrite arbitrary byte in memory
- **Attack to bypass sanitization** -> cause a BO -> ...
- **Logic errors** (e.g., modify variable to change program behaviour)

We will now take a closer look at each of [[Buffer Overflows#^4e9398|these problems;]]

## Overflow

Overflow problem is the **most common integer overflow form**, and it happens when the result of an expression **exceeds** the maximum value used by a certain data type (e.g., max size of int is **2147483647**).

Let's take a closer look at this code example:

```c
void vulnerable(char *matrix, size_t x, size_t y, char val){
	int i, j;
	matrix = (char *) malloc (x*y);
	for (i=0; i < x; i++){
		for(j = 0; j < y; j++){
			matrix[i*y+j] = val;
		}
	}
```

The problem with this code is that if <span style="color:red">x * y > MAXINT</span>, then _malloc_ doesn't reserve enough memory.

## Underflow

Underflow are usually related to **subtractions** of unsigned types, e.g. subtracting $0 - 1$ and storing the result in a **unsigned int**. This problem is rarer than overflow, as it only happens with subtraction.

Here is a real-world example _(Netscape JPEG comment length vulnerability)_:

<pre><code>
void vulnerable(char *src, <span style="color:red">size_t</span> len){ 
	<span style="color:red">size_t</span> real_len;
	char *dst;
	if (len < MAX_SIZE) {
		<span style="color:red">
		real_len = len - 1;
		dst = (char *) malloc (real_len);
		memcpy(dst, src, real_len);
		</span>
	}                           
	                            <span style="color:orange"> /* if len = 0
									then real_len = FFFFFFFF
									malloc allocs FFFFFFFF bytes */
									 </span>
}
</pre></code>

## Signedness Error

In these cases what happens is a **signed integer** is assigned to an **unsigned variable**, or vice-versa. One example of what can result from this is if a **positive unsigned integer** is assigned to a **signed integer variable**; if the number being assigned is larger than $2^{31}$, this means that the most significant bit is 1, and therefore a signed variable will interpret it as **negative**.

The following example illustrates this:


<pre><code>void vuln(char *src, <span style="color:red">size_t</span> len){
	<span style="color:red">int</span> real_len;
	char *dst;
	if (len > 1) {
		<span style="color:red">real_len = len - 1;</span>
		if (real_len < MAX_SIZE) {
			<span style="color:red">dst=(char *) malloc(real_len);
			memcpy(dst, src, real_len);</span>
		}
	}
}                    <span style="color:orange"> /* line 5 is negative if len > 2^(31)</span></pre></code>

## Truncation

This error happens when we assign a value of data type that can hold numbers of greater lengths to a data type that can hold smaller lengths (e.g, assign _long_ to _short_). This can lead to **unauthorized writes** to memory.

Take a look at the following example:

<pre><code>
void vuln(char *src, <span style="color:red">unsigned</span> len) {
    <span style="color:red">unsigned</span> short real_len;
    char *dst;

    real_len = len;

    if (real_len < MAX_SIZE) {
        <span style="color:red">dst = (char *)malloc(real_len);
        strcpy(dst, src);</span>
    }
}

</pre></code>

The problem with this code is that the value in **`real_len`** might become become truncated, leading to **insufficient memory** being allocated by **`malloc`**. Because of this, **`dst`** might not have enough memory allocated to it, leading to _strcpy_ overwriting memory after **`dst`**.

# Heap Overflows

So far we have only seen overflows that affect memory in the **stack**. However, as one can imagine, an attacker can also take advantage of buffer overflows to influence data in the **heap**.

Let's take a look at the following code example:

<pre><code>main(int argc, char **argv) {
	int i;
	char *str = (char *)malloc(4);
	char *critical = (char *)malloc(9);
	strcpy(critical, "secret");
	<span style="color:red">strcpy(str, argv[1]);</span>
	printf("%s\n", critical);
}</pre></code>

^3c3556

The heap resultant of this program would look something like this:

![[heap diagram.png]]
**Fig.7:** Variables **`str`** and __`critical`___ allocated in the heap

Let's say we created a program that analyzes the memory and prints the **content of each memory position**, starting in **`str`** and ending in the end of memory allocated to **`critical`** (you can find this code [[Buffer Overflows#Code to Write Memory Content|here]]). If we provided as input the string **`"xyz"`** to the [[Buffer Overflows#^3c3556|program above]] , the resulting memory content would be this:

<pre><code>Address of str is: 0x80497e0
Address of critical is: 0x80497f0
<span style="color:red">0x80497e0: x (0x78)
0x80497e1: y (0x79)
0x80497e2: z (0x7a)</span>
0x80497e3: ? (0x0)
0x80497e4: ? (0x0)
0x80497e5: ? (0x0)
0x80497e6: ? (0x0)
0x80497e7: ? (0x0)
0x80497e8: ? (0x0)
0x80497e9: ? (0x0)
0x80497ea: ? (0x0)
0x80497eb: ? (0x0)
0x80497ec: ? (0x11)
0x80497ed: ? (0x0)
0x80497ee: ? (0x0)
0x80497ef: ? (0x0)
<span style="color:green">0x80497f0: s (0x73)
0x80497f1: e (0x65)
0x80497f2: c (0x63)
0x80497f3: r (0x72)
0x80497f4: e (0x65)
0x80497f5: t (0x74)</span>
0x80497f6: ? (0x0)
0x80497f7: ? (0x0)
0x80497f8: ? (0x0)
</code></pre>

However, if we take a look at the code, we can see that bounds checking is not performed on the string given by the user, and therefore the second _strcpy_ can cause a **buffer overflow**. If that overflow is long enough, we can **change the value of `critical`**.

To do this, we can run the code with the following input: **`"xyz1234567890123FooBar"`**. If we run our memory printing program, we get the following output:

<pre><code>Address of str is: 0x80497e0
Address of critical is: 0x80497f0
<span style="color:red">0x80497e0: x (0x78)
0x80497e1: y (0x79)
0x80497e2: z (0x7a)</span>
0x80497e3: 1 (0x0)
0x80497e4: 2 (0x0)
0x80497e5: 3 (0x0)
0x80497e6: 4 (0x0)
0x80497e7: 5 (0x0)
0x80497e8: 6 (0x0)
0x80497e9: 7 (0x0)
0x80497ea: 8 (0x0)
0x80497eb: 9 (0x0)
0x80497ec: 0 (0x11)
0x80497ed: 1 (0x0)
0x80497ee: 2 (0x0)
0x80497ef: 3 (0x0)
<span style="color:green">0x80497f0: F (0x73)
0x80497f1: o (0x65)
0x80497f2: o (0x63)
0x80497f3: B (0x72)
0x80497f4: a (0x65)
0x80497f5: r (0x74)</span>
0x80497f6: ? (0x0)
0x80497f7: ? (0x0)
0x80497f8: ? (0x0)</code></pre>

# Additional Content

## Syscall Table

![[System Calls Table.png]]
Table with some of Linux's syscalls

## Code to Write Memory Content

```c
main(int argc, char **argv) {
	int i;
	char *str = (char *)malloc(4);
	char *critical = (char *)malloc(9);
	char *tmp;
	printf("Address of str is: %p\n", str);
	printf("Address of critical is: %p\n", critical);
	strcpy(critical, "secret");
	strcpy(str, argv[1]);
	tmp = str;
	while(tmp < critical + 9) { // print heap content
		printf("%p: %c (0x%x)\n",
				tmp, isprint(*tmp) ? *tmp: '?', (unsigned)(*tmp));
		tmp += 1;
	 }
	printf("%s\n", critical);
}
```

