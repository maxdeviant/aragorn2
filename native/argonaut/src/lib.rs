use argon2::password_hash::{PasswordHasher, SaltString};
use argon2::{Argon2, ParamsBuilder, PasswordHash, PasswordVerifier, Version};
use rand_core::OsRng;
use rustler::{Encoder, Env, NifRecord, NifResult, NifUnitEnum, Term};

mod atoms {
    rustler::atoms! {
        ok,
        error,
    }
}

rustler::init!("argonaut_ffi", [hash_password, verify_password]);

#[derive(NifUnitEnum, Clone, Copy)]
enum Algorithm {
    Argon2d,
    Argon2i,
    Argon2id,
}

impl From<Algorithm> for argon2::Algorithm {
    fn from(value: Algorithm) -> Self {
        match value {
            Algorithm::Argon2d => Self::Argon2d,
            Algorithm::Argon2i => Self::Argon2i,
            Algorithm::Argon2id => Self::Argon2id,
        }
    }
}

#[derive(NifRecord)]
#[tag = "hasher"]
struct Hasher {
    algorithm: Algorithm,
    time_cost: u32,
    memory_cost: u32,
    parallelism: u32,
    hash_length: usize,
}

impl Hasher {
    fn as_argon2(&self) -> argon2::password_hash::Result<Argon2> {
        let params = ParamsBuilder::new()
            .t_cost(self.time_cost)
            .m_cost(self.memory_cost)
            .p_cost(self.parallelism)
            .output_len(self.hash_length)
            .build()?;

        Ok(Argon2::new(self.algorithm.into(), Version::V0x13, params))
    }
}

#[rustler::nif(schedule = "DirtyCpu")]
fn hash_password<'a>(env: Env<'a>, hasher: Hasher, password: &str) -> NifResult<Term<'a>> {
    let salt = SaltString::generate(&mut OsRng);
    do_hash_password(hasher, password, salt).to_nif_result(env)
}

#[rustler::nif(schedule = "DirtyCpu")]
fn hash_password_with_salt<'a>(
    env: Env<'a>,
    hasher: Hasher,
    password: &str,
    salt: &str,
) -> NifResult<Term<'a>> {
    let salt = match SaltString::from_b64(salt) {
        Ok(salt) => salt,
        Err(err) => return Ok((atoms::ok(), err.to_string()).encode(env)),
    };
    do_hash_password(hasher, password, salt).to_nif_result(env)
}

fn do_hash_password(
    hasher: Hasher,
    password: &str,
    salt: SaltString,
) -> Result<String, argon2::password_hash::Error> {
    let argon2 = hasher.as_argon2()?;
    let password_hash = argon2.hash_password(&password.as_bytes(), &salt)?;
    Ok(password_hash.to_string())
}

#[rustler::nif(schedule = "DirtyCpu")]
fn verify_password<'a>(
    env: Env<'a>,
    hasher: Hasher,
    candidate_password: &str,
    hashed_password: &str,
) -> NifResult<Term<'a>> {
    do_verify_password(hasher, candidate_password, hashed_password).to_nif_result(env)
}

fn do_verify_password(
    hasher: Hasher,
    candidate_password: &str,
    hashed_password: &str,
) -> Result<(), argon2::password_hash::Error> {
    let argon2 = hasher.as_argon2()?;
    let parsed_hash = PasswordHash::new(&hashed_password)?;
    argon2.verify_password(candidate_password.as_bytes(), &parsed_hash)
}

trait ResultExt<'a> {
    fn to_nif_result(&self, env: Env<'a>) -> NifResult<Term<'a>>;
}

impl<'a, T> ResultExt<'a> for Result<T, argon2::password_hash::Error>
where
    T: Encoder,
{
    fn to_nif_result(&self, env: Env<'a>) -> NifResult<Term<'a>> {
        match self {
            Ok(value) => Ok((atoms::ok(), value).encode(env)),
            Err(err) => Ok((atoms::error(), err.to_string()).encode(env)),
        }
    }
}
