//// Aragorn2 provides secure password hashing, powered by Argon2.
////
//// From the [Argon2 repo](https://github.com/P-H-C/phc-winner-argon2):
////
//// > Argon2 is a password-hashing function that summarizes the state of the art in the design of memory-hard functions and can be used to hash passwords for credential storage, key derivation, or other applications.
//// >
//// > It has a simple design aimed at the highest memory filling rate and effective use of multiple computing units, while still providing defense against tradeoff attacks (by exploiting the cache and memory organization of the recent processors).
//// >
//// > Argon2 has three variants: Argon2i, Argon2d, and Argon2id. Argon2d is faster and uses data-depending memory access, which makes it highly resistant against GPU cracking attacks and suitable for applications with no threats from side-channel timing attacks (eg. cryptocurrencies). Argon2i instead uses data-independent memory access, which is preferred for password hashing and password-based key derivation, but it is slower as it makes more passes over the memory to protect from tradeoff attacks. Argon2id is a hybrid of Argon2i and Argon2d, using a combination of data-depending and data-independent memory accesses, which gives some of Argon2i's resistance to side-channel cache timing attacks and much of Argon2d's resistance to GPU cracking attacks.
//// >
//// > Argon2i, Argon2d, and Argon2id are parametrized by:
//// >
//// > - A **time cost**, which defines the amount of computation realized and therefore the execution time, given in number of iterations
//// > - A **memory cost**, which defines the memory usage, given in kibibytes
//// > - A **parallelism degree**, which defines the number of parallel threads

import gleam/dynamic.{type Dynamic}
import gleam/result

/// An Argon2 hashing algorithm.
pub type Algorithm {
  /// Argon2d is faster and uses data-depending memory access, which makes it highly resistant against GPU cracking attacks and suitable for applications with no threats from side-channel timing attacks (eg. cryptocurrencies).
  Argon2d
  /// Argon2i instead uses data-independent memory access, which is preferred for password hashing and password-based key derivation, but it is slower as it makes more passes over the memory to protect from tradeoff attacks.
  Argon2i
  /// Argon2id is a hybrid of Argon2i and Argon2d, using a combination of data-depending and data-independent memory accesses, which gives some of Argon2i's resistance to side-channel cache timing attacks and much of Argon2d's resistance to GPU cracking attacks.
  ///
  /// This is the default algorithm.
  Argon2id
}

/// An Argon2 password hasher.
pub opaque type Hasher {
  Hasher(
    algorithm: Algorithm,
    time_cost: Int,
    memory_cost: Int,
    parallelism: Int,
    hash_length: Int,
  )
}

/// Returns the default `Hasher`.
pub fn hasher() -> Hasher {
  Hasher(
    algorithm: Argon2id,
    time_cost: 2,
    memory_cost: mib_to_kib(19),
    parallelism: 1,
    hash_length: 32,
  )
}

/// Converts the given number of mebibytes (MiB) to kibibytes (KiB).
fn mib_to_kib(mib: Int) -> Int {
  mib * 1024
}

/// Sets the time cost of the `Hasher`.
///
/// This is the number of iterations that will be performed when hashing a password.
///
/// Must be a value between `1` and `(2^32) - 1`.
///
/// The default value is `2`.
pub fn with_time_cost(hasher: Hasher, time_cost: Int) -> Hasher {
  Hasher(..hasher, time_cost: time_cost)
}

/// Sets the memory cost of the `Hasher`.
///
/// This is the memory size, expressed in kibibytes (KiB).
///
/// Must be a value between `8 * parallelism` and `(2^32) - 1`.
///
/// The default value is `19,456` (19KiB).
pub fn with_memory_cost(hasher: Hasher, memory_cost: Int) -> Hasher {
  Hasher(..hasher, memory_cost: memory_cost)
}

/// Sets the parallelism of the `Hasher`.
///
/// This is the number of threads that will be used when hashing a password.
///
/// Must be a value between `1` and `(2^32) - 1`.
///
/// The default value is `1`.
pub fn with_parallelism(hasher: Hasher, parallelism: Int) -> Hasher {
  Hasher(..hasher, parallelism: parallelism)
}

/// Sets the output hash length of the `Hasher`.
///
/// This is the length of the output hash, in bytes.
///
/// Must be a value between `4` and `(2^32) - 1`.
///
/// The default value is `32`.
pub fn with_hash_length(hasher: Hasher, hash_length: Int) -> Hasher {
  Hasher(..hasher, hash_length: hash_length)
}

/// Returns the hash of the given password.
pub fn hash_password(hasher: Hasher, password: BitArray) -> Result(String, Nil) {
  do_hash_password(hasher, password)
  |> result.nil_error
}

@external(erlang, "aragorn2_ffi", "hash_password")
fn do_hash_password(hash: Hasher, password: BitArray) -> Result(String, Dynamic)

/// Returns whether the candidate password matches the given hashed password.
pub fn verify_password(
  hasher: Hasher,
  candidate candidate_password: BitArray,
  hash hashed_password: BitArray,
) -> Result(Nil, Nil) {
  do_verify_password(hasher, candidate_password, hashed_password)
  |> result.map(fn(_) { Nil })
  |> result.nil_error
}

@external(erlang, "aragorn2_ffi", "verify_password")
fn do_verify_password(
  hash: Hasher,
  candidate_password: BitArray,
  hashed_password: BitArray,
) -> Result(Dynamic, Dynamic)
