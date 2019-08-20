# OQUIC v0

This library allows QUIC packets to be wrapped in a simple obfuscation layer intended to reduce it's "fingerprint" when the client and server share a symmetric key.


## Encryption

OQUIC uses the Salsa20\[1\] (8 byte nonce) or XSalsa20\[2\] (24 byte nonce) stream cipher. Obfuscation key exchange is performed out of band for this version. There is no OQUIC specific handshake. All clients of a particular server share the same 256 bit obfuscation key.

Each packet contains a randomly selected nonce which is ideally unique for all packets exchanged with a given server.  If a nonce is repeated, it is trivial to recover the key used.  In general use, the 24 byte nonce is recommended when using random nonces, but this is not considered critical because the goal is primarily to decrease the fingerprint of the protocol when inspecting a small number of packets. The underlying QUIC protocol handles integrity and secrecy of payload using its variant of TLS 1.3 as usual.


## OQUIC Packet
```
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Nonce (64/192)                        ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Encrypted Payload (*)                 ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

Each UDP packet consists of an 8 or 24 byte nonce followed by an encrypted payload that contains either a QUIC packet or a Decoy Payload (which is meaningless and not delivered to the QUIC layer).  The client and server must agree on the nonce size for all packets exchanged ahead of time out of band.

The cipher contains no state outside of the individual packets and does not rely on any ordering, retransmission or any inter-packet relationships.


## OQUIC Decoy Payload

```
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | |0|                     OQUIC Decoy (*)                     ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

A Decoy payload is any payload that has the second bit set to 0 after
decryption.  Decoy packets may be sent at any time and are never passed to the QUIC
layer.  There is no restriction on the structure or size (beyond MTU)
aside from having the second bit set to 0 after decryption.  The QUIC
specification\[3\] considers any packet with the second bit set to 0 as invalid and
thus does not generate them (excepting certain historical version negotiation
packets which are out of scope and excluded below)


## QUIC Payload
```
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | |1|               Embedded QUIC Packet (*)                  ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                   OQUIC Padding (8...2040)                  ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

QUIC payloads begin with an unaltered QUIC packet, followed by a variable amount of padding between 1 and 255 bytes. The behavior and meaning of all embedded QUIC packets is unaltered.

QUIC payloads are distinguised from Decoys by the second bit of the payload (after decryption).  In the QUIC protocol\[3\], this bit is called the "fixed bit" and is set to 1 for all long header and short header packets and SHOULD be set to 1 for all version negotiation packets. OQUIC requires that this bit MUST be set to 1 for all QUIC packets including version negotiation packets.

## Padding

Although the QUIC specification allows for a padding frame to be placed in certain QUIC packets, this is performed at a low level that is not easily exposed in client library code. OQUIC v0 contains its own padding following the QUIC Packet. Each byte of padding contains the total length of the padding (in bytes) when interpreted as an unsigned 8 bit integer. There is always at least 1 byte of padding and at most 255.  The underlying QUIC implementation is configured to target a maximum size that reserves space for the OQUIC nonce and padding marker.

Packets may be padded up to a maximum packet size (including UDP headers) of 1280 bytes according to size of the QUIC payload and padding strategy.  1280 bytes is assumed to be not particularly "suspicious" as several devices and protocols (including QUIC) appear to target it as a general "safe" MTU for avoiding fragmentation when transiting heterogenous networks ostensibly because is the required minimum MTU for an IPV6 router.


*Quic Payload with 1 byte padding*
```
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
   |           Embedded QUIC Packet (*)         ...    
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
   |0|0|0|0|0|0|0|1|             
   +-+-+-+-+-+-+-+-+
```


_Quic Payload with 3 bytes padding_
```
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |            Embedded QUIC Packet (*)         ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |0|0|0|0|0|0|1|1|0|0|0|0|0|0|1|1|0|0|0|0|0|0|1|1|             
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

# References

* [[1]: Salsa20](https://cr.yp.to/snuffle/salsafamily-20071225.pdf)
* [[2]: XSalsa20](https://cr.yp.to/snuffle/xsalsa-20110204.pdf)
* [[3]: QUIC Specification](https://www.ietf.org/id/draft-ietf-quic-transport-22.txt)