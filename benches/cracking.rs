use criterion::{criterion_group, criterion_main, Criterion};
use rainbow::{check_hash, check_md5, hash_md5, hash_sha2};
use sha2::Sha256;
use std::hint::black_box;

fn bench_crack_sha256(c: &mut Criterion) {
	let password_list = vec![
		"123456".to_string(),
		"password".to_string(),
		"letmein".to_string(),
		"secret".to_string(),
	];
	let salt = "salt";
	let multiplier = 1000;
	let hashed = hash_sha2::<Sha256>("secret", multiplier, salt);

	c.bench_function("crack_sha256", |b| {
		b.iter(|| {
			check_hash::<Sha256>(
				black_box(&hashed),
				black_box(salt),
				black_box(&password_list),
				black_box(multiplier),
			)
		})
	});
}

fn bench_crack_md5(c: &mut Criterion) {
	let password_list = vec![
		"123456".to_string(),
		"password".to_string(),
		"letmein".to_string(),
		"secret".to_string(),
	];
	let salt = "salt";
	let multiplier = 1000;
	let hashed = hash_md5("secret", multiplier, salt);

	c.bench_function("crack_md5", |b| {
		b.iter(|| {
			check_md5(
				black_box(&hashed),
				black_box(salt),
				black_box(&password_list),
				black_box(multiplier),
			)
		})
	});
}

criterion_group!(benches, bench_crack_sha256, bench_crack_md5);
criterion_main!(benches);
