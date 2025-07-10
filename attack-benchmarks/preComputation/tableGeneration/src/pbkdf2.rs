use pbkdf2::{pbkdf2_hmac, pbkdf2_hmac_array};
use rayon::prelude::*;
use sha2::Sha256;

pub fn hash(output_buffer: &mut [u8; 32], passcode: &[u8; 4], salt: &[u8; 32], iter_count: u32) {
    pbkdf2_hmac::<Sha256>(passcode, salt, iter_count, output_buffer);
}

pub fn fill_table(table: &mut [([u8; 4], [u8; 32])], salt: &[u8; 32], iter_count: u32) {
    table.par_iter_mut().for_each(|row| {
        hash(&mut row.1, &row.0, salt, iter_count);
    });
}
