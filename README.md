
This crate provides the Lioness wide block cipher instantiated with ChaCha20 and Blake2b.

[![build status](https://api.travis-ci.org/applied-mixnetworks/lioness-rs.png)](https://travis-ci.org/applied-mixnetworks/lioness-rs)
[![documenation](https://docs.rs/lioness/badge.svg)](https://docs.rs/lioness/)
[![crates.io link](https://img.shields.io/crates/v/lioness.svg)](https://crates.io/crates/lioness)


### Warning

This code has not been formally audited and should only be use with extreme care and advice from competent cryptographers.  That said, Lionness' security properties mostly reduce to the underlying stream cipher and hash function.


### Documentation

api docs here: <https://docs.rs/lioness/>

_read the paper_
**Two Practical and Provably Secure Block Ciphers: BEAR and LION**
*by Ross Anderson and Eli Biham*

https://www.cl.cam.ac.uk/~rja14/Papers/bear-lion.pdf


### Installation

This crate works with Cargo and is on
[crates.io](https://crates.io/crates/lioness).  Add it to your `Cargo.toml` with:

```toml
[dependencies]
lioness = "^0.1"
```

Use the crate like:

```rust
extern crate lioness;

...
```
