/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
//! Camenisch-Shoup verifiable encryption and decryption based on
//! <https://www.shoup.net/papers/verenc.pdf> and
//! <https://dominoweb.draco.res.ibm.com/reports/rz3730_revised.pdf>

#![no_std]
#![deny(
    warnings,
    missing_docs,
    unused_import_braces,
    unused_qualifications,
    trivial_casts,
    trivial_numeric_casts
)]
#![cfg_attr(docsrs, feature(doc_cfg))]

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "std")]
#[macro_use]
#[cfg_attr(feature = "wasm", macro_use)]
extern crate std;

#[cfg(feature = "std")]
pub mod camshoup;
pub mod elgamal;
