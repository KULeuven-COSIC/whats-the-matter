use argon2::{Algorithm::Argon2id, Argon2, Params, Version};
use rayon::prelude::*;

pub fn hash<'a>(
    output_buffer: &mut [u8; 32],
    passcode: &[u8; 4],
    salt: &[u8; 32],
    hasher: &Argon2<'a>,
) {
    hasher
        .hash_password_into(passcode, salt, output_buffer)
        .unwrap();
}

pub fn fill_table<'a>(table: &mut [([u8; 4], [u8; 32])], salt: &[u8; 32], hasher: &Argon2<'a>) {
    table.par_iter_mut().for_each(|row| {
        hash(&mut row.1, &row.0, salt, &hasher);
    });
}
