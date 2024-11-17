# ZK-Auction Toolkit

This repository is intended to provide a playground for you to easily start writing a zkVM application using [RISC Zero (Risc0)](https://dev.risczero.com).

## Installation
### Prerequisites
This projects requires [Rust](https://www.rust-lang.org/), if you don't have Rust and [rustup](https://rustup.rs/) installed, start by [installing Rust and rustup](https://doc.rust-lang.org/cargo/getting-started/installation.html). Risc0 mainly depends on the [rustup](https://rustup.rs/) tool.

### Installation of `rzup`
> This installation guide if for both x86-64 Linux and arm64 mac0S.

`rzup` is the Risc0 toolchain installer.

1. Install `rzup` by running:
```bash
curl -L https://risczero.com/install | bash
```

2. Run `rzup` to install Risc0:
```bash
rzup install
```

Please checkout [Ric0 installation docs](https://dev.risczero.com/api/zkvm/install) for more details.

### Institution of Devtools (optional - only if you are a contributor)
- Installing commitlint tools globally via NPM for the pre-commit tool

```bash
npm install -g @commitlint/cli @commitlint/config-conventional
```
