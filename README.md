# Light Onion Router

## What is this?
Light Onion Router is a project I developed in 2015 because I needed to make a
hidden service reachable without using Tor (this is kind of strange, I know).
The main purpose, in fact, was to create a malware capable of connecting to its
C&C completely via the Tor network.

## Why not just use Tor?
Well, Tor binary's size is a few megabytes, while this little adapter's size
is about 500KB (maybe less with correct optimizations).
Also this comes as a library to be embedded in your project, so your software
does not need to make SOCKS connections to the Tor binary.

## Crypto
That was the funniest and hardest part to me. I first realized a version using
OpenSSL, but the output was very big, then I decided to switch entirely on
mbed TLS.

## PoC
This is a proof-of-concept and should **NEVER** be used in production
environments.
It was fast coded and has not proper data structures and code design to
handle serious problems (no event loop for example).
It was just made to demonstrate that malware living entirely on Tor, without
any kind of proxy or workarounds, can be realized.

## It is not working now
It does not work because probably network authorities changed from 2015
and maybe also document structures and the protocol itself have been modified.
