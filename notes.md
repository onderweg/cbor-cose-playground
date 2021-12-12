## Things to check if signature verification fails

[ ] Replace empty map (`a0`) protected header with zero length string, or visa versa.

In the bytes to sign (COSE_Sign structure), an empty protected header map should be encoded as a zero length string: 

>"Senders SHOULD encode a zero-length map as a zero-length string rather than as a zero-length map (encoded as h'a0').

_RFC 8152, CBOR Object Signing and Encryption (COSE)_