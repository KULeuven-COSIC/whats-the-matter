pub mod argon2;
pub mod pbkdf2;

use rand::{
    distr::{Distribution, Uniform},
    rng,
};


use std::collections::HashSet; // for faster invalid value checking

static INVALID_VALUES_ARRAY: [u32; 12] = [
    0, 11111111, 22222222, 33333333, 44444444, 55555555, 66666666, 77777777, 88888888, 99999999,
    12345678, 87654321,
];

const MIN_PASSCODE_VALUE: u32 = 0x0000001;
const MAX_PASSCODE_VALUE: u32 = 0x5F5E0FE; // 99 999 998

/// Generates an "empty" table of valid passcodes (excluding invalid values) 
/// with each passcode mapped to a placeholder 32-byte array of zeros.
pub fn gen_empty_table() -> Vec<([u8; 4], [u8; 32])> {

    let total_range = (MAX_PASSCODE_VALUE - MIN_PASSCODE_VALUE + 1) as usize;
    let capacity = total_range - INVALID_VALUES_ARRAY.len();
    let mut table = Vec::with_capacity(capacity);
    let invalid_set: HashSet<u32> = INVALID_VALUES_ARRAY.iter().cloned().collect();

    for i in MIN_PASSCODE_VALUE..=MAX_PASSCODE_VALUE {
        if !invalid_set.contains(&i) {
            table.push((i.to_le_bytes(), [0u8; 32]));
        }
    }

    table
}