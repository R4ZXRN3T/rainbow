# rainbow

**This is rainbow**

rainbow is a cross-platform tool, developed in Rust, for cracking hashes and hashing passwords.

## Installation

In order to use rainbow, you just need to download the latest release of the program and put it into a folder of your
choice.

**Dependencies:** There are **none**!

## Usage

### Windows

`
.\rainbow [<Operation>] [<Arguments>]
`

### Operation `crack`:

&nbsp;&nbsp;&nbsp;&nbsp;`.\rainbow crack [<hashed password>] [<salt>] [<path to password list>]`

- `hashed password`: The hash of the password you want to crack. Needs to be any valid, supported hash to work.
- `salt`: The salt used for hashing. If you don't know what salt is, you might want to look it
  up [here](https://en.wikipedia.org/wiki/Salt_(cryptography)). Optional parameter. If left out, an empty String will be
  used instead.
- `path to password list`: Input for an absolute path on your file system. The file needs to be raw text and encoded in
  UTF-8.

### Operation `hash`:

&nbsp;&nbsp;&nbsp;&nbsp;`.\rainbow hash [<Algorithm>] [<Multiplier>] [<String>]`

- `Algorithm`: The Algorithm you want to use for hashing. Supported: sha224, sha256, sha384, sha512, sha512_224, sha512_256, md5
- `Multiplier`: The amount of times the password should be hashed. Optional parameter.
- `String`: The string you want to hash

### Supported hashes:

MD5, SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256