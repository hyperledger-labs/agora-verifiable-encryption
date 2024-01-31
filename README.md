# Verifiable Encryption

[![Crates.io](https://img.shields.io/crates/v/verenc.svg)](https://crates.io/crates/verenc)
[![Documentation](https://docs.rs/verenc/badge.svg)](https://docs.rs/verenc)
![License-Image](https://img.shields.io/badge/License-Apache%202.0/MIT-green.svg)
![minimum rustc 1.50](https://img.shields.io/badge/rustc-1.50+-blue.svg)
[![dependency status](https://deps.rs/repo/github/mikelodder7/verenc/status.svg)](https://deps.rs/repo/github/mikelodder7/verenc)

An implementation of Verifiable Encryption and Decryption of Discrete Logarithms based on [Camenisch Shoup](https://www.shoup.net/papers/verenc.pdf).

The scheme uses the Paillier cryptosystem [P99](https://link.springer.com/chapter/10.1007%2F3-540-48910-X_16).

This crate uses the [unknown-order](https://crates.io/crates/unknown_order) crate which allows
switching the underlying big number implementation based on license preferences and performance.
As such, this crate reexports `unknown_order` so consumers of this crate do not have to have a separate dependency.

**This implementation has not been reviewed or audited. Use at your own risk.**

Efforts have been made to mitigate some side channel attacks but ultimately there are many factors involved.
For a good read, see Thomas Pornin's [Why Constant-Time Crypto](https://www.bearssl.org/constanttime.html) article.

## License

Licensed under either of:

* [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
* [MIT license](http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be licensed as above, without any additional terms or conditions.

This crate is part of the Hyperledger Labs Agora Project
