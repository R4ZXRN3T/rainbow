use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use sha2::{Digest as Sha2Digest, Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256};
use std::fs::read_to_string;
use std::io::Error;

pub enum HashType {
	Md5,
	Sha224,
	Sha256,
	Sha384,
	Sha512,
	Sha512_224,
	Sha512_256,
}

impl HashType {
	pub fn from_length(len: usize) -> Vec<Self> {
		match len {
			32 => vec![Self::Md5],
			56 => vec![Self::Sha224, Self::Sha512_224],
			64 => vec![Self::Sha256, Self::Sha512_256],
			96 => vec![Self::Sha384],
			128 => vec![Self::Sha512],
			_ => vec![],
		}
	}

	pub fn hash(&self, to_hash: &str, multiplier: i32, salt: &str) -> String {
		match self {
			Self::Md5 => hash_md5(to_hash, multiplier, salt),
			Self::Sha224 => hash_sha2::<Sha224>(to_hash, multiplier, salt),
			Self::Sha256 => hash_sha2::<Sha256>(to_hash, multiplier, salt),
			Self::Sha384 => hash_sha2::<Sha384>(to_hash, multiplier, salt),
			Self::Sha512 => hash_sha2::<Sha512>(to_hash, multiplier, salt),
			Self::Sha512_224 => hash_sha2::<Sha512_224>(to_hash, multiplier, salt),
			Self::Sha512_256 => hash_sha2::<Sha512_256>(to_hash, multiplier, salt),
		}
	}

	pub fn check(
		&self,
		original_hashed_password: &str,
		salt: &str,
		password_list: &[String],
		multiplier: i32,
	) -> Option<String> {
		match self {
			Self::Md5 => check_md5(original_hashed_password, salt, password_list, multiplier),
			Self::Sha224 => {
				check_hash::<Sha224>(original_hashed_password, salt, password_list, multiplier)
			}
			Self::Sha256 => {
				check_hash::<Sha256>(original_hashed_password, salt, password_list, multiplier)
			}
			Self::Sha384 => {
				check_hash::<Sha384>(original_hashed_password, salt, password_list, multiplier)
			}
			Self::Sha512 => {
				check_hash::<Sha512>(original_hashed_password, salt, password_list, multiplier)
			}
			Self::Sha512_224 => {
				check_hash::<Sha512_224>(original_hashed_password, salt, password_list, multiplier)
			}
			Self::Sha512_256 => {
				check_hash::<Sha512_256>(original_hashed_password, salt, password_list, multiplier)
			}
		}
	}
}

pub fn check_hash<D: Sha2Digest + Default + Send + Sync>(
	original_hashed_password: &str,
	salt: &str,
	password_list: &[String],
	multiplier: i32,
) -> Option<String> {
	password_list
		.par_iter()
		.find_any(|current_password| {
			let mut hash = current_password.as_str().to_owned();
			for _ in 0..multiplier {
				hash.push_str(salt);
				hash = hex::encode(D::digest(hash.as_bytes()));
			}
			hash == original_hashed_password
		})
		.cloned()
}

pub fn check_md5(
	original_hashed_password: &str,
	salt: &str,
	password_list: &[String],
	multiplier: i32,
) -> Option<String> {
	password_list
		.par_iter()
		.find_any(|current_password| {
			let mut hash = current_password.as_str().to_owned();
			for _ in 0..multiplier {
				hash.push_str(salt);
				hash = format!("{:x}", md5::compute(hash.as_bytes()));
			}
			hash == original_hashed_password
		})
		.cloned()
}

pub fn hash_sha2<D: Sha2Digest>(to_hash: &str, multiplier: i32, salt: &str) -> String {
	let mut final_string = to_hash.to_owned();
	for _i in 0..multiplier {
		final_string = hex::encode(D::digest(format!("{}", final_string + salt)));
	}
	final_string
}

pub fn hash_md5(to_hash: &str, multiplier: i32, salt: &str) -> String {
	let mut final_string = to_hash.to_owned();
	for _i in 0..multiplier {
		final_string = format!("{:x}", md5::compute(format!("{}", final_string + salt)));
	}
	final_string
}

pub fn get_password_list(path: &str) -> Result<Vec<String>, Error> {
	Ok(read_to_string(path)?
		.lines()
		.map(|line| line.to_string())
		.collect())
}
