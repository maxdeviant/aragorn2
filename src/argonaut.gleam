import gleam/dynamic.{type Dynamic}
import gleam/result

pub type Algorithm {
  Argon2d
  Argon2i
  Argon2id
}

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
    memory_cost: 19 * 1024,
    parallelism: 1,
    hash_length: 32,
  )
}

pub fn hash_password(hasher: Hasher, password: BitArray) -> Result(String, Nil) {
  do_hash_password(hasher, password)
  |> result.nil_error
}

@external(erlang, "argonaut_ffi", "hash_password")
fn do_hash_password(hash: Hasher, password: BitArray) -> Result(String, Dynamic)

pub fn verify_password(
  hasher: Hasher,
  candidate candidate_password: BitArray,
  hashed hashed_password: BitArray,
) -> Result(Nil, Nil) {
  do_verify_password(hasher, candidate_password, hashed_password)
  |> result.map(fn(_) { Nil })
  |> result.nil_error
}

@external(erlang, "argonaut_ffi", "verify_password")
fn do_verify_password(
  hash: Hasher,
  candidate_password: BitArray,
  hashed_password: BitArray,
) -> Result(Dynamic, Dynamic)
