# New Methods for Transactions in Blockchain Systems

This work is the result of my master thesis in computer science from the University of Applied Sciences Western Switzerland.

## Abstract

Bitcoin is a decentralized peer-to-peer currency that allows users to to pay for
things electronically. Bitcoin was created by a pseudonymous software developer
going by the name of Satoshi Nakamoto in 2008, as an electronic payment system
based on mathematical proof. Yet the largest challenge in Bitcoin for the coming
years is scalability. Currently, Bitcoin can only handle a few transactions per
second on the network. This is not sufficient in comparison to large payment
infrastructures, which allow tens of thousands of transactions per second. As a
potential scalability solution, the idea of payment channels was suggested by
Satoshi in an email to Mike Hearn. A one-way payment channel specific for retail
commercial transactions is presented, analyzed and optimized with threshold
cryptography. The threshold scheme selected has been adapted and implemented
into the Bitcoin cryptographic library to compute a special two-party threshold
ECDSA signature.

## Related implementations

 * [A python proof of concept](https://github.com/GuggerJoel/poc-threshold-ecdsa-secp256k1)
 * [libsecp256k1 fork with experimental module](https://github.com/GuggerJoel/secp256k1)

#### Thanks to

- Maria Sisto, for the title page
- Loïc Monney, for the section title style, captions style and font idea
- EPFL, for the basic structure

