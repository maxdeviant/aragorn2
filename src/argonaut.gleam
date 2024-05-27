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

pub fn hasher() -> Hasher {
  Hasher(
    algorithm: Argon2id,
    time_cost: 3,
    memory_cost: 19 * 1024,
    parallelism: 1,
    hash_length: 32,
  )
}

pub fn hash_password(hasher: Hasher, password: BitArray) -> Result(String, Nil) {
  do_hash_password(hasher, password)
}

@external(erlang, "argonaut_ffi", "hash_password")
fn do_hash_password(hash: Hasher, password: BitArray) -> Result(String, Nil)
