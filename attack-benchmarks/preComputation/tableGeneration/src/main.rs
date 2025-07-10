use std::time::Instant;

use ::argon2::{Algorithm::Argon2id, Argon2, Params, Version};
use bench_pwd_hash::{argon2, gen_empty_table};
use rand::{RngCore, rng};

fn main() {
    let mut salt: [u8; 32] = [0u8; 32];
    rng().fill_bytes(&mut salt);

    let mut empty_table = gen_empty_table();

    let params = Params::new(7168, 5, 1, Some(32)).unwrap();
    let argon2id_hasher = Argon2::new(Argon2id, Version::default(), params.clone());

    let timer = Instant::now();
    argon2::fill_table(&mut empty_table, &salt, &argon2id_hasher);
    let duration = timer.elapsed();

    println!("{}", duration.as_secs());
}