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