use argon2::password_hash::{PasswordHasher, SaltString};
use argon2::{Argon2, ParamsBuilder, Version};
use rand_core::OsRng;
use rustler::{Encoder, Env, NifRecord, NifResult, NifUnitEnum, Term};

mod atoms {
    rustler::atoms! {
        ok,
        error,
    }
}

rustler::init!("argonaut_ffi", [hash_password]);

#[derive(NifUnitEnum)]
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
    let params = ParamsBuilder::new()
        .t_cost(hasher.time_cost)
        .m_cost(hasher.memory_cost)
        .p_cost(hasher.parallelism)
        .output_len(hasher.hash_length)
        .build()?;

    let argon2 = Argon2::new(hasher.algorithm.into(), Version::V0x13, params);

    let password_hash = argon2.hash_password(&password.as_bytes(), &salt)?;
    Ok(password_hash.to_string())
}

trait ResultExt<'a> {
    fn to_nif_result(&self, env: Env<'a>) -> NifResult<Term<'a>>;
}

impl<'a> ResultExt<'a> for Result<String, argon2::password_hash::Error> {
    fn to_nif_result(&self, env: Env<'a>) -> NifResult<Term<'a>> {
        match self {
            Ok(value) => Ok((atoms::ok(), value).encode(env)),
            Err(err) => Ok((atoms::error(), err.to_string()).encode(env)),
        }
    }
}
