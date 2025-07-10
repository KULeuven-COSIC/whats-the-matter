use ::argon2::{Algorithm::Argon2id, Argon2, Params, Version};

use bench_pwd_hash::{argon2, gen_empty_table, pbkdf2};
use criterion::{BatchSize, Criterion, criterion_group, criterion_main};

use rand::{
    RngCore,
    distr::{Distribution, Uniform},
    rng,
};

/// Benchmarks the `gen_empty_table` function, which generates a table of valid passcodes
/// mapped to placeholder 32-byte arrays of zeros.
fn gen_empty_table_bench(c: &mut Criterion) {
    c.bench_function("gen_empty_table", |b| {
        b.iter(|| {
            bench_pwd_hash::gen_empty_table();
        })
    });
}

/// Benchmarks the process of filling a table with PBKDF2-derived hashes for various iteration counts.
/// The table is pre-generated using `gen_empty_table`, and the salt is randomly generated.
fn pbkdf2_table_bench(c: &mut Criterion) {
    let mut salt: [u8; 32] = [0u8; 32];
    rng().fill_bytes(&mut salt);

    let empty_table = gen_empty_table();

    let iter_count_list: Vec<u32> = vec![1000, 10_000, 100_000, 600_000, 1_000_000];

    for iter_count in iter_count_list {
        c.bench_function(format!("hash_table_{}", iter_count).as_str(), |b| {
            b.iter_batched(
                || empty_table.clone(),
                |mut empty_table| {
                    pbkdf2::fill_table(&mut empty_table, &salt, iter_count);
                },
                BatchSize::PerIteration,
            )
        });
    }
}

/// Benchmarks the process of filling a table with Argon2id-derived hashes using specific parameters.
/// The table is pre-generated using `gen_empty_table`, and the salt is randomly generated.
fn argon2id_table_bench(c: &mut Criterion) {
    let mut salt: [u8; 32] = [0u8; 32];
    rng().fill_bytes(&mut salt);

    let empty_table = gen_empty_table();

    let param1 = Params::new(7168, 5, 1, Some(32)).unwrap();

    let params_list: Vec<Params> = vec![param1];

    for params in params_list {
        c.bench_function(format!("argon2id_hash_table_{:?}", params).as_str(), |b| {
            b.iter_batched(
                || {
                    (
                        Argon2::new(Argon2id, Version::default(), params.clone()),
                        empty_table.clone(),
                    )
                },
                |(hasher, mut empty_table)| {
                    argon2::fill_table(&mut empty_table, &salt, &hasher);
                },
                BatchSize::PerIteration,
            )
        });
    }
}

/// Benchmarks the PBKDF2 hashing process for individual passcodes with varying iteration counts.
/// Each passcode and salt are randomly generated for each iteration.
fn pbkdf2_bench(c: &mut Criterion) {
    let mut salt: [u8; 32] = [0u8; 32];
    rng().fill_bytes(&mut salt);
    let range = Uniform::new(1 << 26, 0x5F5E0FFu32).unwrap();

    let iter_count_list: Vec<u32> = vec![1000, 10_000, 100_000, 600_000, 1_000_000];

    for iter_count in iter_count_list {
        c.bench_function(format!("pbkdf2_{}", iter_count).as_str(), |b| {
            b.iter_batched(
                || {
                    let mut salt: [u8; 32] = [0u8; 32];
                    rng().fill_bytes(&mut salt);
                    let passcode = range.sample(&mut rng()).to_le_bytes();

                    ([0u8; 32], passcode, salt)
                },
                |(mut buf, passcode, salt)| pbkdf2::hash(&mut buf, &passcode, &salt, iter_count),
                BatchSize::PerIteration,
            )
        });
    }
}

/// Benchmarks the Argon2id hashing process for individual passcodes using specific parameters.
/// Each passcode and salt are randomly generated for each iteration.
fn argon2id_bench(c: &mut Criterion) {
    let mut salt: [u8; 32] = [0u8; 32];
    rng().fill_bytes(&mut salt);

    let param1 = Params::new(7168, 5, 1, Some(32)).unwrap();

    let params_list: Vec<Params> = vec![param1];

    let range = Uniform::new(1 << 26, 0x5F5E0FFu32).unwrap();

    for params in params_list {
        c.bench_function(format!("argon2id_{:?}", params).as_str(), |b| {
            b.iter_batched(
                || {
                    let mut salt: [u8; 32] = [0u8; 32];
                    rng().fill_bytes(&mut salt);
                    let passcode = range.sample(&mut rng()).to_le_bytes();

                    (
                        [0u8; 32],
                        Argon2::new(Argon2id, Version::default(), params.clone()),
                        passcode,
                        salt,
                    )
                },
                |(mut buf, hasher, passcode, salt)| {
                    argon2::hash(&mut buf, &passcode, &salt, &hasher)
                },
                BatchSize::PerIteration,
            )
        });
    }
}

criterion_group!(
    benches,
    gen_empty_table_bench,
    pbkdf2_bench,
    argon2id_bench,
    // pbkdf2_table_bench,
    // argon2id_table_bench
);
criterion_main!(benches);
