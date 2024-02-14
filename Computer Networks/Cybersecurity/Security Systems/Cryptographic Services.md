- To enforce security in systems, we will need to use the following Cryptographic Services:
### Confidentiality

- It's a service used to keep the information concealed from everyone but the authorized parties to access that information
- It's typically achieved with **encryption**

> ___Note:___ Encrypting everything is not the solution to all problems; we can have all the messages exchanged be encrypted and still have vulnerabilities. **E.g.:** Replay attacks, tampering attacks, cryptanalysis, etc.

- Encryption has its costs:
	- Encrypting and decrypting a high number of messages can be **slow** (specially if using **asymmetric keys**)
	- Makes debugging **harder** and systems **more complex**
	- If key is lost, access to the content of messages is also lost
	- There are other services that might be more appropriate than encryption
### Integrity

- It's a service that detects the alteration of information by unauthorized parties
- An intruder should not replace a false message with a legitimate one
- It is typically achieved using some type of **digest algorithm** (see below)

### Authenticity
	Entity Authentication
	Data origin authentication
	Non-repudiation

- Authenticity is a service that allows a party to authenticate itself to others, or to confirm the author of a message
- Requires _message integrity_ and _[[Cryptographic Services#Authenticity|freshness]]_
- It is typically achieved using a combination of **digest algorithm** with some mechanism of **asymmetric keys**
- It can be divided into three types:
#### Entity Authentication:
- It's used so that the receiver of the message can confirm the identity of the sender
- It counters **impersonation** attacks
- It can be used to authenticate both **devices** and **humans**

- **Device authentication:**
	- Typically using some type of **key**, whether it be **symmetric**, **asymmetric** or a combination of these two
	- Keys are usually very large, but this is no problem for machines
	
- **Human authentication:**
	- We cannot use keys because we can't memorize such large keys
	- We must use other mechanisms like:
		- Password authentication
		- Biometrics authentication
		- Tokens
		- Two-factor authentication, etc.

#### Data origin Authentication
- Receiver must confirm that the messages it has just received were sent by the correct entity
- It will prevent **tampering** and **replay** attacks
- For this

#### Non-repudiation
- After sending a message, the author of that message cannot deny it sent that message
- In this case, there is no **attacker** from which we are defending

## Cryptographic Building Blocks

- To create the services described above, we will need to use the following **building blocks:**

- #### Ciphers
	- ##### Symmetric
	- ##### Asymmetric

- #### Hash

### Ciphers

- Ciphers have two main basic functions: **cipher** and **decipher**

- **Cipher Function**:
	- Takes the **plaintext** and the provided **key**, and outputs a **ciphered text**
- **Decipher Function:**
	- Takes the **ciphered text** and the **correct key**, and outputs the original **plaintext**
	- Only entities with the right key will be able to access it (that key will depend on the chosen algorithm)

#### Symmetric Cipher

- In this type of cipher, the key use in the **decipher** and **cipher** functions is the **same**
- The receiver of the message must have in its possession the key the sender used to encrypt the message. We either assume:
	- The receiver already has the secret key
	- A **secret key sharing** will have to be used (E.g.: Diffie-Hellman)
- In cryptographic notation, we have:
	- **Cipher:**
		- E(M, K) -> C
		- Ciphering the message **M** with key **K** produces the cryptogram **C**
	- **Decipher:**
		- D(C, K) -> M
		- Deciphering the cryptogram **C** with key **K** produces message **M'**
		- If key is correct, **M' = M**
	- D(E(M,K), K) = D(C, K) = M

#### Asymmetric Cipher

* Instead of a pair of identical keys, we have two different keys:
	* A **public key** (KU)
	* A **private key** (KR)

- Like the name says, the public key is known by **everyone**, while the **private key** is kept secret by one of the entities communicating
- These keys complement each other, in the sense that if I cipher using the **public key**, I can only decipher using the **private key** (and vice-versa)

- **Ciphering with public key and decipher with private key:**
	- AE(M, KU) -> C
	- AD(C, KR) -> M'
	- Any entity will be able to produce cryptogram **C**
	- Only the right entity (owner of private key KR) will be able to decipher **C** and obtain **M**
- **Ciphering with private key and decipher with public key:**
	- AE(M, KR) -> C
	- AD(C, KU) -> M'
	- Only the owner of private key KR will be able to create cryptogram **C**
	- Anyone will be able to decipher it using KU

#### Symmetric vs Asymmetric Ciphers
| Property | Symmetric Cipher | Asymmetric Cipher |
| ---- | ---- | ---- |
| Speed | Significantly faster | Significantly slower |
| Key Size | Smaller sizes, <br>typically 128-256 bits | Larger sizes,<br>typically 1024-4096 bits  |
| Key distribution | If secret key is not already<br>shared, a key distribution<br>algorithm will have to be used | Public key can be shared<br>in plaintext |

### Cryptographic Hash

- A **hash function** is a function that is typically applied to data being sent, and has the following properties:
	- **Fixed-length:** A hash function produces an output that is always the same length, no matter the input
	- **Deterministic:** The same input always returns the same output
	- **Unique:** The result of hashing a certain input should be **unique** to that input (although collisions can occur, they must be **highly** unlikely
	- **Irreversible:** It is computationally unfeasible to obtain the **original** message with the hash of that message
	- **Sensitive to input changes:** A small change to the input produces a big change to the output (avalanche effect)

## Composite Building Blocks

* We can combine the previously discussed [[Cryptographic Services#Cryptographic Building Blocks|building blocks]] to make other useful **building blocks**, such as:
	* **Hybrid Cipher**
	* **Integrity Check:**
		* MIC (Message Integrity Code)
		* MAC (Message Authenticity Code)
		* HMIC (Hash-based Message Integrity Code)
		* Digital Signature

### Hybrid Ciphers

- Addresses both the disadvantages of **symmetric ciphers** (difficulty in sharing secret) and of the **asymmetric ciphers** (speed)
- Combines these two to get the best of them

#### How it works

- **Sender:**
	- First the sender of the message creates a **symmetric key K**
	- Encrypts the message **M** with **K** to produce **C**
	- Then it will encrypt K with the **public key of the receiver** (KU) to produce **CK**
	- Then it will send **C** and **CK**

	> ***In cryptographic notation:***
	> **E(M, K) -> C
	> AE(K, KU) -> CK
	> Send(CK)
	> Send(C)**

- **Receiver:**
	- Gets the encrypted symmetric key **CK** and deciphers it with its **private key (KR)**, and obtains **K'**
	- Deciphers **C** with **K'** to produce **M'**

	> ***In cryptographic notation:***
	> **AD(CK, KR) -> K'
	> D(C, K') -> M**

### Message Integrity Code (MIC)

- The MIC is a mechanism using **hash functions** and **symmetric cryptography** to ensure the **integrity property**
- Sender will produce the MIC of a message, and send it to receiver (along with the message)
- Receiver will be able to detect changes to  a message using MIC ([[#Message Integrity Code (MIC)#How it works|see below how]])
- It is often combined with some **[[Cryptographic Services#Authenticity|freshness element]]** to also provide **authenticity**; in that case it is called **MAC** (Message Authentication Code)

#### How it works

- **Sender:**
	- Sender will produce, using a hash function, the digest of message **M** (we will call it **DT**)
	- It will then cipher **DT** with **symmetric key K** to produce the **MIC value**
	- Then sends **M** and **MIC** to receiver
	>___Note:___ Usually, it will not send M in plaintext; it will cipher it, using one of the mechanisms discussed above

	> ___In cryptographic notation:___
	> **E(H(M),K) -> MIC
	> <=>
	> E(DT, K) -> MIC
	> Send(M)
	> Send(MIC)**

- **Receiver:**
	- __Hashes__ the received message **M** to produce **DT'**
	- Ciphers **DT'** with key **K** to get **MIC'**
	- If **MIC = MIC'**, then the message was **not** corrupted (if they are different, it was corrupted)
	>___Note:___ the receiver can also decipher the received MIC to get DT', and compare the **deciphered** DT with the **computed** DT

	> ***In cryptographic notation:***
	> **H(M) -> DT'
	> E(DT', K) -> MIC'
	> Compare(MIC, MIC')**

### Hash-based Message Integrity Code (HMIC)

- HMIC is another version of the MIC, but **faster** because it doesn't use **ciphers**
- It will instead use a **mixing function**, for example XOR, to combine the message with the secret
- Can also be used to provide **authenticity** (int that case, it's called HMAC)

#### How it works

- **Sender:**
	- Using the **mixing function MIX** (typically XOR), we combine message **M** and secret key **K**
	- We hash the output of MIX and send it to the receiver

	> ___In cryptographic notation:___
	> **H(MIX(M, K)) -> HMIC
	> Send(M)
	> Send(HMIC)**

- **Receiver:**
	- Combines the received message **M** with key **K** using the **same mixing function**
	- Hashes the output of this to produce **HMIC'** and compares with received **HMIC**
	- If they are equal, message was ***not*** corrupted; if they are not equal, it ***was*** corrupted

	> ___In cryptographic notation:___
	> **H(MIX(M, K)) -> HMIC'
	> Compare(HMIC, HMIC')**

### Digital Signature

- **MIC** and its variations can provide **integrity** and **authenticity** (MAC and HMAC), but fail to provide an additional property: ***non-repudiation***
- To ensure non-repudiation we can use **digital signature**
- Similar to MIC, but uses **asymmetric cryptography**

> The reason why **MIC** fails to ensure **non-repudiation** is the following: in MIC, because we use **symmetric cryptography,** there are two parties that possess the key: the **sender** and the **receiver**. This means that the sender can send a message M, and later **claim** that it did not send M, and that the receiver **forged** M (sender can claim that because receiver holds in fact the **secret key**, which is the key that is used by the sender to create new messages)
> On the other hand, in **digital signature**, only the sender has access to the key that creates messages (private key KR), so after sending a message and after receiver deciphers it, it cannot claim that receiver forged that message

#### How it works

- **Sender:**
	- Sender computes the hash of message **M** to produce **DT**
	- Then encrypts **DT** with its **private key KR** to create the **digital signature DS**

	> ***In cryptographic notation:***
	> **AE(H(M), KR) <=> AE(DT, KR) -> DS
	> Send(M)
	> Send(DS)**

- **Receiver:**
	- Receiver deciphers the received **digital signature DS'** with **public key KU** to produce the digest **DT'**
	- Then takes the received message and applies a hash function to produce another **DT''**
	- Then checks if **DT' = DT''**

	> ***In cryptographic notation:***
	> **AD(DS', KU) -> DT'
	> H(M') -> DT''
	> Compare(DT', DT'')**

## Cryptographic Services Design (Introduction)

 Now that we have seen the primitive and composite building blocks of cryptography, we can use them to begin designing our cryptographic services.

### Confidentiality

To ensure confidentiality, we should use a **[[Cryptographic Services#Ciphers|cipher]]** mechanism. The cipher we choose depends on a couple of factors, such as:

- **Key sharing:** If sender and receiver share **secret keys**, use **[[Cryptographic Services#Symmetric Cipher|symmetric cryptography]]**; if **public keys** are shared, then use **[[Cryptographic Services#Asymmetric Cipher|asymmetric cryptography]]**
- **Message size:** If we need to send large messages, but have shared public keys, it might be better to use a **[[Cryptographic Services#Hybrid Ciphers|hybrid cipher]]**

### Integrity

Integrity mechanisms will make use of mechanisms that include some sort of **[[Cryptographic Services#Cryptographic Hash|hash]]** (due to its properties, hash functions are ideal to verify integrity). But which one?

- **[[Cryptographic Services#Message Integrity Code (MIC)|MIC]]** if sender and receiver have shared secret keys; a faster alternative to MIC is **[[Cryptographic Services#Hash-based Message Integrity Code (HMIC)|HMIC]]**
- **[[Cryptographic Services#Digital Signature|Digital Signature]]**, if sender and receiver have shared public keys

Besides integrity, we might also want to guarantee **authenticity**. For this, we need to incorporate a **freshness** element; [[Cryptographic Services#Authenticity|up next]] we will see how.

### Authenticity

Authenticity is typically assured combining an integrity mechanism with **freshness**. Freshness requires sending a **nonce** (number used once) along with the message. This nonce can be composed by:

- **Random number** (RN): Before sending a message, sender will generate a big random number and send it coupled with the message; receiver will only accept messages with nonces **not received before** (if attacker sends a repeated message, it will not be accepted)
- **Counter** (CTR): Sender will keep a counter of how many messages it has sent; every time a message is sent, the counter is also sent and then it's incremented. The receiver only accepts messages that follow the correct order (therefore, messages need to be received in the same order they were sent)
- **Timestamp** (TS): Sender sends the message and a **timestamp of when that message was sent**, and will only accept messages with a certain delay in respect to TS. This **requires the sender and receiver clocks to be synchronized**

**IMPORTANT:** It is not safe to use only one of the previous elements to form the nonce. Typically it's used a **combination of two of them** to form the nonce.

>___Note:___ Freshness elements protect against **replay** attacks

>___Note:___ MIC and HMIC, with freshness, become **MAC** and **HMAC**, respectively

### Non-Repudiation

To ensure non-repudiation, a **digital signature** has to be used (if sender is the only entity that knows the private key)