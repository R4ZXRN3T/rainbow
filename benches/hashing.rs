use criterion::{criterion_group, criterion_main, Criterion};
use rainbow::{hash_md5, hash_sha2};
use sha2::Sha256;
use std::hint::black_box;

fn bench_hash_sha256(c: &mut Criterion) {
	c.bench_function("hash_sha256", |b| {
		b.iter(|| hash_sha2::<Sha256>(black_box("password"), black_box(1000), black_box("salt")))
	});
}

fn bench_hash_sha512(c: &mut Criterion) {
	c.bench_function("hash_sha512", |b| {
		b.iter(|| {
			hash_sha2::<sha2::Sha512>(black_box("password"), black_box(1000), black_box("salt"))
		})
	});
}

fn bench_hash_md5(c: &mut Criterion) {
	c.bench_function("hash_md5", |b| {
		b.iter(|| hash_md5(black_box("password"), black_box(1000), black_box("salt")))
	});
}

criterion_group!(
	benches,
	bench_hash_sha512,
	bench_hash_md5,
	bench_hash_sha256
);

criterion_main!(benches);
