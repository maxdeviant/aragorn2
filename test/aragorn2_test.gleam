import aragorn2
import gleam/string
import startest.{describe, it}
import startest/expect

pub fn main() {
  startest.run(startest.default_config())
}

pub fn hash_password_tests() {
  describe("aragorn2", [
    describe("hash_password", [
      it("hashes the provided password", fn() {
        let hashed_password =
          aragorn2.hash_password(aragorn2.hasher(), <<"ilovegleam":utf8>>)
          |> expect.to_be_ok

        let components =
          hashed_password
          |> string.split("$")

        case components {
          [_, algorithm, version, params, salt, hash] -> {
            algorithm
            |> expect.to_equal("argon2id")

            version
            |> expect.to_equal("v=19")

            params
            |> expect.to_equal("m=19456,t=2,p=1")

            salt
            |> string.length
            |> expect.to_equal(22)

            hash
            |> string.length
            |> expect.to_equal(43)
          }
          _ -> panic as "Malformed password hash"
        }
      }),
    ]),
  ])
}

pub fn verify_password_tests() {
  describe("aragorn2", [
    describe("verify_password", [
      it("accepts a candidate password that matches the hashed password", fn() {
        let candidate_password = <<"very good password":utf8>>
        let hashed_password = <<
          "$argon2id$v=19$m=19456,t=3,p=1$ZYCzcZSdMx22PjYmDQJshw$+9l+TA6qymw31yLAuvOQV0niFc81i/48v/HSUhT0MhY":utf8,
        >>

        aragorn2.verify_password(
          aragorn2.hasher(),
          candidate: candidate_password,
          hash: hashed_password,
        )
        |> expect.to_be_ok
      }),
      it(
        "rejects a candidate password that does not match the hashed password",
        fn() {
          let candidate_password = <<"very bad password":utf8>>
          let hashed_password = <<
            "$argon2id$v=19$m=19456,t=3,p=1$ZYCzcZSdMx22PjYmDQJshw$+9l+TA6qymw31yLAuvOQV0niFc81i/48v/HSUhT0MhY":utf8,
          >>

          aragorn2.verify_password(
            aragorn2.hasher(),
            candidate: candidate_password,
            hash: hashed_password,
          )
          |> expect.to_be_error
        },
      ),
    ]),
  ])
}
