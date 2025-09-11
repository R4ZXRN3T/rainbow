# rainbow

**rainbow** is a fast, cross-platform hash cracker and password hasher written in Rust. It supports multiple SHA-2 variants and MD5, with optional salt and hash iteration (multiplier).

## Features

- Crack hashed passwords using a wordlist, with optional salt and hash iteration.
- Hash any string using a supported algorithm, with optional hash iteration and salt.
- Supports: MD5, SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256.
- Simple CLI interface.

## Installation

Download the latest release and place the binary anywhere on your system.

_No external dependencies required at runtime._

## Usage

### General Syntax

```
rainbow <COMMAND> [OPTIONS]
```

### Commands

#### 1. `crack`

Attempts to recover the original password from a hash using a password list.

**Syntax:**

```
rainbow crack --input <HASH> [--salt <SALT>] [--multiplier <N>] --password-list <FILE> [--verbosity <LEVEL>]
```

- `--input, -i <HASH>`: The hashed password to crack (hex-encoded).
- `--salt, -s <SALT>`: (Optional) Salt appended to each password before hashing.
- `--multiplier, -m <N>`: (Optional) Number of hash iterations (default: 1).
- `--password-list, -l <FILE>`: Path to a UTF-8 text file with one password per line.
- `--verbosity <LEVEL>`: (Optional) Verbosity level (0=silent, 1=normal, 2=verbose; default: 2).

**Examples:**

```
rainbow crack -i 5d41402abc4b2a76b9719d911017c592 -l passwords.txt
rainbow crack -i 5d41402abc4b2a76b9719d911017c592 -s mysalt -l passwords.txt
rainbow crack -i 5d41402abc4b2a76b9719d911017c592 -m 5 -l passwords.txt
rainbow crack -i 5d41402abc4b2a76b9719d911017c592 -s mysalt -m 5 -l passwords.txt
```

#### 2. `hash`

Hashes a string using the specified algorithm and optional multiplier and salt.

**Syntax:**

```
rainbow hash --algorithm <ALGO> [--multiplier <N>] --input <STRING> [--salt <SALT>] [--verbosity <LEVEL>]
```

- `--algorithm, -a <ALGO>`: One of `sha224`, `sha256`, `sha384`, `sha512`, `sha512_224`, `sha512_256`, `md5`.
- `--multiplier, -m <N>`: (Optional) Number of hash iterations (default: 1).
- `--input, -i <STRING>`: The string to hash.
- `--salt, -s <SALT>`: (Optional) Salt appended to the string before hashing.
- `--verbosity <LEVEL>`: (Optional) Verbosity level (0=silent, 1=normal, 2=verbose; default: 2).

**Examples:**

```
rainbow hash -a sha256 -i password123
rainbow hash -a md5 -m 10 -i password123
rainbow hash -a sha512 -i password123 -s mysalt
```

## Supported Algorithms

- md5
- sha224
- sha256
- sha384
- sha512
- sha512_224
- sha512_256

## Notes

- The program auto-detects the hash type in `crack` mode based on the hash length.
- All arguments are passed as named flags (not positional).
- Verbosity controls the amount of output: 0 = only result, 1 = result with label, 2 = result with timing.
- Salt is always appended to the password/string before hashing.
- Multiplier applies the hash function repeatedly.

## Example Password List

```
password
123456
letmein
password123
```

You can find good password lists in the [SecLists repo](https://github.com/danielmiessler/SecLists/tree/master/Passwords/Common-Credentials) (Cloned repo [here](https://github.com/R4ZXRN3T/SecLists/tree/master/Passwords/Common-Credentials)), or the gigantic [RockTastic password list](https://www.lrqa.com/en/cyber-labs/rocktastic/)

## License

MIT
