# probabilisticpubkey

[![Build Status](https://travis-ci.org/crodriguezvega/probabilisticpubkey.svg?branch=master)](https://travis-ci.org/crodriguezvega/probabilisticpubkey)

Probabilistic public-key crypto systems in Rust. Implementations of Goldwasser-Micali and Blum-Goldwasser algorithms as described in [chapter 8](http://cacr.uwaterloo.ca/hac/about/chap8.pdf) of "Handbook of Applied Cryptography" by Alfred J. Menezes et al.

Build:

`cargo build`

Run tests:

`cargo test`

Generate documentation:

`cargo doc --no-deps --document-private-items --open`

Run examples:

`cargo run --example goldwasser_micali`

`cargo run --example blum_goldwasser`

