# Authentication

Authentication is **crucial** in cybersecurity, as we only want authorized users performing certain actions, and before **authorization** must come **authentication**.

Authentication must follow a set of properties, such as:

- **Thrustworthiness:** authentication step **must** prove the user trying to authenticate **is who they claim to be**
- **Secure:** attackers cannot **impersonate** other users
- **Simple:** Authentication process should not be very complex, specially for human users
- It should also take into account that users often choose **poor password**

And these are the set of **goals** it is trying to achieve:

- **Entity authentication:**
	- It can be users, machines, services, etc.
- **Simplify the use of the protocol:**
	- Provide mechanisms to simplify the usage of authentication credentials (password, keys, etc.)
- **Never break correctness/accuracy, even in hostile environments:**
	- Accuracy in the proof of authentication
	- Confidentiality of used secrets for authentication
- **Prevent impersonations**
	- Prevent online attacks to the authentication protocol
	- Prevent offline attacks like dictionary attacks

## Machine Authentication

We will start by taking a look at **machine authentication**. One possible way one could think to authenticate machines would be by using **name/IP** credentials. But, just like only using a username to authenticate a user, this is an **insecure** way to authenticate machines, as IP addresses and hostnames can very easily be **spoofed**.

Instead, one of the most commonly used authentication methods for machines is the usage of **keys**. Keys, like we saw [[Cryptographic Services|here]], have several advantages, like:

- Being too long to **brute-force**
- Machines can safely **permanently store** them
- We can make use of key properties, like **asymmetry** (private/public key-pairs)

Key authentication is used in several protocols used today, like:

- IPSec
- SSH
- Etc.

## Service Authentication

Service authentication differs from machine authentication in the sense that service authentication corresponds to the authentication of a **specific service** running on a machine (and not the machine as a whole). Examples of this are **web servers**.

Just like in machine authentication, the most common way of authenticating services is through **keys.** There are two options

- **Shared secret keys**
- **Asymmetric keys** (most commonly used, for example private key corresponding to public key in certificate)

## Personal Authentication

In personal authentication, there are three main **methods** to authenticate a user:

- Using something **they know** (e.g., password, PIN, etc.)
- Using something **they have** (e.g., smart card. magnetic card, etc.)
- Using something **they are** (e.g., fingerprint scanning, face scanning)

The "using something they are" method makes use of the **biometric features**, and besides taking advantage of **physical characteristics** (the example above), can also take advantage of **behavioral characteristics** (e.g., how you normally type in a keyboard).

### Multi-Factor Authentication

Multi-Factor authentication is taking advantage of a combination of these authentication methods, and require the user to pass the authentication check in all of them. A really common multi-factor authentication used today is **two-factor authentication** with a **password** plus a **verification with your smartphone** (that is something only you possess).

Multi-factor authentication is considered very secure for user authentication, an it is recommended to be used.

## Password Authentication

We will now look deeper at **password authentication**. Passwords are commonly used for **user authentication**, as it would be impossible for us humans to memorize a cryptographic key, for example. Passwords have their upsides and downsides:

**Advantages:**

- Simple to use and memorize
- Can be used in any device with text input

**Disadvantages:**

- Weak passwords can be easily cracked
- Sometimes we need to transmit them through insecure channels

### Password Storage

For the verification of the password, the authentication service needs to compare the provided password with something stored, to confirm it is the right password. However, ==we should never store passwords in plaintext==. We should, when storing the password, use a **one way function** like a **cryptographic hash** or a **key-deriving function** (KDF) to transform the password, and then store it in a database. Then, in the password verification process, we pass the input of the user through the **same function**, and then compare with the stored value.

(TODO)