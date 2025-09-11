# rainbow

**rainbow** is a fast, cross-platform hash cracker and password hasher written in Rust. It supports multiple SHA-2
variants and MD5, with optional salt and hash iteration (multiplier).

## Features

- Crack hashed passwords using a wordlist, with optional salt and hash iteration.
- Hash any string using a supported algorithm, with optional hash iteration.
- Supports: MD5, SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256.
- Simple CLI interface, no dependencies required at runtime.

## Installation

Download the latest release and place the binary anywhere on your system.

_No external dependencies required._

## Usage

### General Syntax

```
rainbow <operation> [arguments...]
```

### Operations

#### 1. `crack`

Attempts to recover the original password from a hash using a password list.

**Syntax:**

```
rainbow crack <hash> [salt] [multiplier] <password_list>
```

- `<hash>`: The hashed password to crack (hex-encoded).
- `[salt]`: (Optional) Salt appended to each password before hashing.
- `[multiplier]`: (Optional) Number of hash iterations (default: 1).
- `<password_list>`: Path to a UTF-8 text file with one password per line.

**Examples:**

```
rainbow crack 5d41402abc4b2a76b9719d911017c592 passwords.txt
rainbow crack 5d41402abc4b2a76b9719d911017c592 mysalt passwords.txt
rainbow crack 5d41402abc4b2a76b9719d911017c592 5 passwords.txt
rainbow crack 5d41402abc4b2a76b9719d911017c592 mysalt 5 passwords.txt
```

#### 2. `hash`

Hashes a string using the specified algorithm and optional multiplier.

**Syntax:**

```
rainbow hash <algorithm> [multiplier] <string>
```

- `<algorithm>`: One of `sha224`, `sha256`, `sha384`, `sha512`, `sha512_224`, `sha512_256`, `md5`.
- `[multiplier]`: (Optional) Number of hash iterations (default: 1).
- `<string>`: The string to hash.

**Examples:**

```
rainbow hash sha256 password123
rainbow hash md5 10 password123
```

## Supported Algorithms

- MD5
- SHA-224
- SHA-256
- SHA-384
- SHA-512
- SHA-512/224
- SHA-512/256

## Notes

- The program auto-detects the hash type in `crack` mode based on the hash length.
- If you provide both a salt and a multiplier, the order is: `<hash> <salt> <multiplier> <password_list>`.
- All arguments are positional.

## Example Password List

```
password
123456
letmein
password123
```
You can find a good password lists in the [SecLists repo](https://github.com/danielmiessler/SecLists/tree/master/Passwords/Common-Credentials) (Cloned repo [here](https://github.com/R4ZXRN3T/SecLists/tree/master/Passwords/Common-Credentials)), or the gigantic [RockTastic password list](https://www.lrqa.com/en/cyber-labs/rocktastic/)

## License

MIT
