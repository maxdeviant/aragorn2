import argonaut
import gleam/io
import startest.{describe, it}
import startest/expect

pub fn main() {
  startest.run(startest.default_config())
}

pub fn hash_password_tests() {
  describe("argonaut", [
    describe("hash_password", [
      it("hashes the provided password", fn() {
        let hashed_password =
          argonaut.hash_password(argonaut.hasher(), <<"hunter2":utf8>>)
          |> expect.to_be_ok

        io.debug(hashed_password)
        Nil
      }),
    ]),
  ])
}
