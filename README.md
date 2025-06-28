# rainbow

**This is rainbow**

rainbow is a cross-platform tool, developed in Rust, for cracking hashes and hashing passwords.

## Installation

In order to use rainbow, you just need to download the latest release of the program and put it into a folder of your
choice.

**Dependencies:** There are **none**!

## Usage

### Windows

#### cracking passwords:

`
.\rainbow [<hashed password>] [<salt>] [<path to password list>]
`

- `hashed password`: The hash of the password you want to crack. Needs to be any valid sha256 hash to work.\
- `salt`: The salt used for hashing. If you don't know what salt is, you might want to look it up [here](https://en.wikipedia.org/wiki/Salt_(cryptography)). Optional parameter. If left out, an empty String will be used instead.\
- `path to password list`: Input for an absolute path on your file system. The file needs to be raw text and encoded in UTF-8.