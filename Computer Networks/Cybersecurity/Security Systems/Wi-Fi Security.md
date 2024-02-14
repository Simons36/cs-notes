# Wireless Security Challenges

Wireless networks possess some additional security challenges that don't exist in traditional, because the communication can be easily is propagated through an **uncontrolled environment** (you can intercept all communication using a **radio antenna**; in wired communication is harder). The two main **problems** of wireless communication are:

- **Eavesdropping:** Anyone with a radio antenna can listen to the communication, breaking **confidentiality**
- **Impersonation:** Anyone with a radio transmitter can forge communication frames, breaking **authenticity**

We will analyze the several security mechanisms of **Wi-Fi** networks (IEEE 802.11*)

# IEEE 802.11*

The architecture of a IEEE 802.11* wireless network is comprised of **three** elements:

- **Stations**
	- A station is any device that is able to connect to a wireless network
	- Each station has its unique **MAC** (Media Access Control) address
- **APs** (Access Points):
	- The **provider** of the wireless connection; stations connect to them
- **Wireless Network:**
	- The set of **stations** and **access points** that communicate with each other via **radio signals**

## Evolution of Security in IEEE 802.11*

Security in IEEE 802.11* has come a long way since its first releases, and has been evolving as new versions of Wi-Fi are released throughout the years (first version released in **1999**).

Initially, the security mechanisms were very simple, and they included:

- **SSID** (Service Set Identifier)
- **MAC Access Control**
- **WEP** (Wired Equivalent Privacy)

We will now take a look at each of this mechanisms.

## SSID (Service Set Identifier)

SSID refers to the **identifier** of a particular wireless network; each network, provided by an AP, will have its own SSID, and it will act as a kind of a **password**. If a station wants to use a particular wireless network, it will have to **send** that network's SSID in **every message** (in plaintext). Each AP **broadcasts** its wireless network's SSID, so **everyone knows it**.

## MAC Address Filtering

Each station has its own **MAC** (initially it was designed for this MAC to be fixed, but today stations can change MAC). An AP can **filter** stations out, by simply blocking unwanted MAC addresses.

**However**, this MAC address is sent in plaintext, so an attacker can very easily discover other users' MAC addresses and **impersonate** them (eavesdropping), and can also easily **spoof** MAC addresses (so MAC address filtering can be easily circumvented).

## WEP (Wired Equivalent Privacy)

The goal of the WEP security mechanism was to **protect** wireless communications, and confer **confidentiality and integrity** in this means of communication.

For this, WEP uses:

- **Shared symmetric keys:**
	- Defined by administrator, these keys are either **40** or **104** bits long
	- Shared between stations
- **Manual key distribution**
- Uses the **RC4** stream cipher

### How it works

We take every message M, and create its **CRC value** (CRC is Cyclic Redundancy Check) for **integrity**; then, we concatenate M with the CRC and **XOR** it with the RC4 stream cipher, created from the **shared symmetric key** plus an **IV** (to ensure confidentiality). The following image is a representation of this process:

![[Pasted image 20240113165054.png]]

### Problems

WEP security has several problems, such as:

- **Reutilization** of the same shared secret key
- **AP** is not authenticated
	- Attacker can **impersonate** AP
- IV variation is **not controlled**
- Same key stream may be reused
- **CRC** is a weak integrity control mechanism

#### Key stream reutilization

Because for the same SSID (same network) the encrypting key used is **always the same**, and there is no control over the IV repetition, we may obtain cases of two different messages encrypted with the **same** key stream. This is a problem because:

> For messages $M_1$ and $M_2$, and key stream $K_S$
> $C_1 = M_1$ $\oplus$ $K_S$
> $C_2 = M_2$ $\oplus$ $K_S$
> $C_1$ $\oplus$ $C_2 = M_1 \oplus K_S \oplus M_2 \oplus K_S$ 
> <=>
> $M_1 \oplus M_2 \oplus (K_S \oplus K_S) = M_1 \oplus M_2 \oplus (0) = M_1 \oplus M_2$

This way, from two messages encrypted with the same keystream, we can obtain the XOR of the two unencrypted messages.

Besides this, the IV used in this security standard is only **24 bits**, it is not always **renewed** after each message, and can be **0** (in some equipments, after restart).

### WEP Authentication

For authentication, WEP security follows this protocol:

1. Station makes **authentication request** to AP
2. AP sends back a **128 byte nonce**
3. Station encrypts the nonce with **shared symmetric key** plus **IV**, and sends back the encrypted nonce plus the IV
4. AP decrypts the nonce and confirms it is correct

The following diagram depicts this process:

![[Pasted image 20240113175233.png]]

#### WEP Authentication Attack

This authentication mechanism is very easily attacked in the following manner:

1. <span style="color:green">Good station</span> sends authentication request to **AP**
2. **AP** generates **nonce** (we will call this nonce message **M**) and sends it to <span style="color:green">good station</span>
3. <span style="color:green">Good station</span> receives message M, encrypts it using **keystream(K, IV)**, thus creating cryptogram **C**, and sends C and IV to AP
4. <span style="color:red">Attacker</span> intercepts the original message **M** and this last message **C**. Because $C = M \oplus KeyStream(K, IV)$, an attacker can **obtain keystream** for the used IV, without ever knowing K
5. <span style="color:red">Attacker</span> then proceeds to make authentication request to AP; after AP sends a nonce, the <span style="color:red">attacker</span> can encrypt it with the keystream obtained in step 4, and send it back to the AP
6. <span style="color:red">Attacker</span> has now **successfully authenticated** to the AP, **without knowing key K**

## WPA (Wi-Fi Protected Access)

WPA is a security protocol that aims at addressing the weaknesses of the WEP protocol. Some of the improvements it has in relation to WEP are:

- Usage of **128-bit long master key**
	- Never used for **message encryption**; **temporary keys** are derived from it using the [[Wi-Fi Security#TKIP (Temporary Key Integrity Protocol)|TKIP protocol]]
- Substitution of CRC with **MIC**hael (Message Integrity Code)
	- Computed over the entirety of the **unencrypted message data** + **source MAC address** + **destination MAC address**
	- If two wrong MICs are sent in an interval of 60 seconds, the integrity key is **renewed** (to prevent trial-and-error attacks)
- **48-bit** long IVs
- Each packet is encrypted with a different key
- **IV** is used as a **packet counter: TSC (TKIP Sequence Counter)**
	- For each new integrity key, TSC is renewed
	- Out of order received packets are **discarded**, to prevent replay attacks

### TKIP (Temporary Key Integrity Protocol)

The TKIP protocol is the security protocol used in WPA for **message encryption** and **integrity**. It generates new temporary keys from a master key, and it uses **RC4 stream ciphers** for encryption. It also uses **MIC** (Message Integrity Code) to ensure integrity in the sent message data.

TKIP improves on the mechanism used in **WEP** because it generates **temporary keys** for each message, instead of always using the same key. It generates these keys from the **PMK** (Pairwise Master Key); we will call these keys **PTK** (Pairwise Transient Key)

- **PTK** - computed from:
	- **PMK:** Master Key
	- **ST_MAC** and **AP_MAC**: station MAC address and AP MAC address
	- **SNonce** and **ANonce**: Nonces sent by station and access point, respectively

This ensures that temporary keys are truly **unique** (and thus every packet is encrypted with a unique key).

### Problems

The problems with WPA are the following

- MIC only protects **data** portion of the packet (not header)
- Sometimes **same** keystream can be **reused**

## WPA2 (IEEE 802.11i)

WPA2 aims to improve on WPA, using many of its security mechanisms, but adding **AES-CCMP**.

**AES