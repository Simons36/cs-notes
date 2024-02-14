#notes #cybersecurity #computer-networks #web 

XSS (or Cross Site Scripting) vulnerabilities envolve **running illegal code** (scripts), introduced by an attacker, in the **victim's browser** (typically JavaScript). XSS vulnerabilities are some of the more common web app security issues (according to OWASP, Top3 vulnerability in 2013, Top7 in 2017). 

In this note, we aim to give a full exposure of what is a XSS vulnerability and its different variations, and how to fix them.

# XSS Types

There are three different types of XSS vulnerabilities we will present:

- **Reflected XSS** (or non-persistent)
	- Page _reflects_ input provided by user
- **Stored XSS** (or persistent)
	- Script provided by attacker is stored somewhere in the page (database, file...) and later sent to victim
	- Specially common in social media, blogs, forums
- **DOM based XSS**
	- DOM -> Document Object Model
	- Manipulates JavaScript, not HTML

## Reflected XSS

In reflected XSS, there are three entities involved:

- Attacker
- Victim
- Vulnerable Website (that user might trust)

What usually happens is that the attacker will send (via email, for example) the victim a seemingly normal **URL link** to the victim, that leads to a **trustworthy** (but vulnerable to XSS) site; the caveat here is that the sent **URL is modified**, so that when the victim accesses that website, the **response** from the server will contain a **script**, that will be **interpreted** and **run** by the **victim's browser**.

Here is an example of the exchange of messages:

![[Reflected XSS Overview Example.png]]
**Fig.1:** Reflected XSS overview


In the following lines we will compare a possible normal request-response interaction between user and website, and another interaction in a possible attack:

__