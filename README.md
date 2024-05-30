# aragorn2

[![Package Version](https://img.shields.io/hexpm/v/aragorn2)](https://hex.pm/packages/aragorn2)
[![Hex Docs](https://img.shields.io/badge/hex-docs-ffaff3)](https://hexdocs.pm/aragorn2/)
![Erlang-compatible](https://img.shields.io/badge/target-erlang-b83998)

Secure password hashing, powered by Argon2.

## Platform support

`aragorn2` uses a [NIF](https://www.erlang.org/doc/system/nif) to provide the Argon2 implementation. This NIF leverages the [`argon2`](https://crates.io/crates/argon2) crate, which is a pure Rust implementation of Argon2.

Precompiled binaries are available for the following platforms for your convenience:

| OS      | Architecture(s) |
| ------- | --------------- |
| Linux   | x86_64          |
| macOS   | aarch64, x86_64 |
| Windows | x86_64          |

## Installation

```sh
gleam add aragorn2
```

## Usage

```gleam
import aragorn2
import gleam/io

pub fn main() {
  // Create a hasher to use to hash and verify passwords.
  //
  // You can customize the hasher's parameters, but be mindful of the security
  // implications! The defaults are based on the current OWASP recommendations,
  // so don't change them unless you know what you are doing.
  let hasher = aragorn2.hasher()

  // Provide a plaintext password to be hashed:
  let assert Ok(hashed_password) =
    aragorn2.hash_password(hasher, <<"correct horse battery staple":utf8>>)
  // This will return a hashed password that you can store (e.g., in your database).
  // Reminder: Don't print out your hashed passwords in production.
  io.debug(hashed_password)
  // "$argon2id$v=19$m=19456,t=2,p=1$SgDirmQl/Revk9+l7XtpZw$fz3xDI6cocCYpNB63FmMV4PhRpRTBK8KMuhYaWnAIKc"

  // When a user enters their candidate password, check it against the hashed
  // password.
  //
  // When the candidate password does not match, an `Error` will be returned.
  case
    aragorn2.verify_password(
      hasher,
      candidate: <<"wrong password":utf8>>,
      hash: <<hashed_password:utf8>>,
    )
  {
    Ok(Nil) -> io.println("You're in!")
    Error(Nil) -> io.println("Oops, wrong password!") // <--
  }

  // When the password does match, an `Ok` will be returned.
  case
    aragorn2.verify_password(
      hasher,
      candidate: <<"correct horse battery staple":utf8>>,
      hash: <<hashed_password:utf8>>,
    )
  {
    Ok(Nil) -> io.println("You're in!") // <--
    Error(Nil) -> io.println("Oops, wrong password!")
  }
}
```
