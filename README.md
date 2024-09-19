# ZK Auction Toolkit
This is a Rust toolkit for building ZK-Snark circuits for applying Zero-knowledge primitives in several kinds of auctions (First-bid, Second-bid, English, Dutch, and SEAL). That governs bidders anonymity, decentralization, and integrity. 

## Setup

- Install rust:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

- Installing commitlint tools globally via NPM for the pre-commit tool 

```bash
npm install -g @commitlint/cli @commitlint/config-conventional
```

### Submodules
#### 1. Clone a Submodule

```bash
git submodule update --init --recursive 
```

#### 2. Applying Patch Changes
- Ensure a clean work directory before applying any patches, by using `git status`.
- If there any uncommitted changes, either commit them or stash them using `git stash`.
- Apply the patch changes by using ``
```bash
# pwd: packages/probabilistic-encryption
git apply ../../submodules-changes.patch
```

#### 3. Making changes in a Submodule
- Navigate to the submodule directory:
```bash
cd packages/probabilistic-encryption
```
- Make your changes.
- Update the Patch File: To update the patch file with your new changes, generate a patch that includes all changes from the initial commit `0a6dd9e` to the current `HEAD`:
```bash
git diff > ../../submodules-changes.patch
```
#### 4. Additional Notes
- Checking Submodule Status:
```bash
git submodule status
```
