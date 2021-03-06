# rust-lioness
[![](https://travis-ci.org/david415/rust-lioness.png)](https://www.travis-ci.org/david415/rust-lioness) [![](https://img.shields.io/crates/v/rust-lioness.svg)](https://crates.io/crates/rust-lioness) [![](https://docs.rs/rust-lioness/badge.svg)](https://docs.rs/rust-lioness/)

This crate provides a concrete parameterization of the Lioness wide
block cipher using ChaCha20 and Blake2b.


# Warning

This code has not been formally audited and should only be use with
extreme care and advice from competent cryptographers. That said,
Lionness' security properties mostly reduce to the underlying stream
cipher and hash function.

Test vectors are verified in a fork of Yawning golang Lioness
implementation: https://github.com/david415/lioness


# Details

Lioness is a wide block cipher built from a stream cipher and a hash
function.  It remains secure so long as either the stream cipher or
the hash function remains secure.  Lioness is described in
**Two Practical and Provably Secure Block Ciphers: BEAR and LION**
by *Ross Anderson* and *Eli Biham*. 
See <https://www.cl.cam.ac.uk/~rja14/Papers/bear-lion.pdf>

Documentation is available at <https://docs.rs/rust-lioness/>


# Installation

This crate works with Cargo and is on crates.io
https://crates.io/crates/rust-lioness. Add it to your
`Cargo.toml` with:
```toml
rust-lioness = "^0.1.4"
```
Then import the crate as:
```rust,no_run
extern crate rust-lioness;
```


# License

rust-lioness is free software made available via the MIT License.
License details located in the LICENSE file.
