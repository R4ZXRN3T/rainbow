use sha2::{Digest as Sha2Digest, Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256};
use std::env::args;
use std::fs::read_to_string;

fn main() -> Result<(), &'static str> {
	let args: Vec<String> = args().collect();

	if args[1] == "crack" {
		crack_hash(&args)
	} else if args[1] == "hash" {
		hash(&args)
	} else {
		print_usage();
		Err("Invalid operation")
	}
}

fn hash(args: &Vec<String>) -> Result<(), &'static str> {
	let (algorithm_string, multiplier, to_hash) = match args.len() {
		4 => (args[2].clone(), 1, args[3].clone()),
		5 => (
			args[2].clone(),
			args[3].parse::<i32>().unwrap(),
			args[4].clone(),
		),
		_ => {
			print_usage();
			return Err("Error: Invalid number of arguments");
		}
	};

	let algorithm = match algorithm_string.to_lowercase().as_str() {
		"sha224" => HashType::Sha224,
		"sha-224" => HashType::Sha224,
		"sha256" => HashType::Sha256,
		"sha-256" => HashType::Sha256,
		"sha384" => HashType::Sha384,
		"sha-384" => HashType::Sha384,
		"sha512" => HashType::Sha512,
		"sha-512" => HashType::Sha512,
		"sha512_224" => HashType::Sha512_224,
		"sha-512/224" => HashType::Sha512_224,
		"sha512_256" => HashType::Sha512_256,
		"sha-512/256" => HashType::Sha512_256,
		"md5" => HashType::Md5,
		_ => return Err("Error: hashing algorithm not supported."),
	};

	let hashed_string = algorithm.hash(&to_hash, multiplier);

	println!("\nHashed string: {}\n", hashed_string);

	Ok(())
}

fn crack_hash(args: &Vec<String>) -> Result<(), &'static str> {
	let (original_hashed_password, salt, password_list_path) = match args.len() {
		4 => (args[2].clone(), String::new(), args[3].clone()),
		5 => (args[2].clone(), args[3].clone(), args[4].clone()),
		_ => {
			print_usage();
			return Err("Error: Invalid number of arguments.");
		}
	};

	print!("Reading list...");
	let password_list = get_password_list(&password_list_path)
		.map_err(|_| "Error: Failed to read password list file")?;
	print!(" Done!\n");

	let hash_types = HashType::from_length(original_hashed_password.len());
	if hash_types.is_empty() {
		println!(
			"Unsupported hash length: {}",
			original_hashed_password.len()
		);
		return Err("Unsupported hash length");
	}

	print!("Hashing list...");

	for hash_type in hash_types {
		if let Some(password) = hash_type.check(&original_hashed_password, &salt, &password_list) {
			print!(" Done!\nSuccess! Password found: {}", password);
			return Ok(());
		}
	}

	println!(" Done\nPassword not found in list.");
	Ok(())
}

fn get_password_list(path: &str) -> Result<Vec<String>, std::io::Error> {
	Ok(read_to_string(path)?
		.lines()
		.map(|line| line.to_string())
		.collect())
}

enum HashType {
	Md5,
	Sha224,
	Sha256,
	Sha384,
	Sha512,
	Sha512_224,
	Sha512_256,
}

impl HashType {
	fn from_length(len: usize) -> Vec<Self> {
		match len {
			32 => vec![Self::Md5],
			56 => vec![Self::Sha224, Self::Sha512_224],
			64 => vec![Self::Sha256, Self::Sha512_256],
			96 => vec![Self::Sha384],
			128 => vec![Self::Sha512],
			_ => vec![],
		}
	}

	fn hash(&self, to_hash: &str, multiplier: i32) -> String {
		match self {
			Self::Md5 => hash_md5(to_hash, multiplier),
			Self::Sha224 => hash_sha2::<Sha224>(to_hash, multiplier),
			Self::Sha256 => hash_sha2::<Sha256>(to_hash, multiplier),
			Self::Sha384 => hash_sha2::<Sha384>(to_hash, multiplier),
			Self::Sha512 => hash_sha2::<Sha512>(to_hash, multiplier),
			Self::Sha512_224 => hash_sha2::<Sha512_224>(to_hash, multiplier),
			Self::Sha512_256 => hash_sha2::<Sha512_256>(to_hash, multiplier),
		}
	}

	fn check(
		&self,
		original_hashed_password: &str,
		salt: &str,
		password_list: &[String],
	) -> Option<String> {
		match self {
			Self::Md5 => check_md5(original_hashed_password, salt, password_list),
			Self::Sha224 => check_hash::<Sha224>(original_hashed_password, salt, password_list),
			Self::Sha256 => check_hash::<Sha256>(original_hashed_password, salt, password_list),
			Self::Sha384 => check_hash::<Sha384>(original_hashed_password, salt, password_list),
			Self::Sha512 => check_hash::<Sha512>(original_hashed_password, salt, password_list),
			Self::Sha512_224 => {
				check_hash::<Sha512_224>(original_hashed_password, salt, password_list)
			}
			Self::Sha512_256 => {
				check_hash::<Sha512_256>(original_hashed_password, salt, password_list)
			}
		}
	}
}

fn check_hash<D: Sha2Digest>(
	original_hashed_password: &str,
	salt: &str,
	password_list: &[String],
) -> Option<String>
where
	D: Default,
{
	password_list.iter().find_map(|current_password| {
		let hash = hex::encode(D::digest(format!("{}{}", current_password, salt)));
		if hash == original_hashed_password {
			Some(current_password.clone())
		} else {
			None
		}
	})
}

fn check_md5(
	original_hashed_password: &str,
	salt: &str,
	password_list: &[String],
) -> Option<String> {
	password_list.iter().find_map(|current_password| {
		let hash = format!(
			"{:x}",
			md5::compute(format!("{}{}", current_password, salt))
		);
		if hash == original_hashed_password {
			Some(current_password.clone())
		} else {
			None
		}
	})
}

fn hash_sha2<D: Sha2Digest>(to_hash: &str, multiplier: i32) -> String {
	let mut final_string = to_hash.to_owned();
	for _i in 0..multiplier {
		final_string = hex::encode(D::digest(format!("{}", final_string)));
	}
	final_string
}

fn hash_md5(to_hash: &str, multiplier: i32) -> String {
	let mut final_string = to_hash.to_owned();
	for _i in 0..multiplier {
		final_string = format!("{:x}", md5::compute(format!("{}", final_string)));
	}
	final_string
}

fn print_usage() {
	eprintln!("Wrong Arguments!\n");
	eprintln!("Usage: rainbow [<Operation>] [<Arguments>]");
	eprintln!("\nOperation crack:\n");
	eprintln!("Usage: rainbow crack [<Hash>] [<Salt>] [<Password list>]\n");
	eprintln!("\tHash:\t\tThe hashed password you want to crack");
	eprintln!("\tSalt:\t\tThe salt used for generating the password. This is optional");
	eprintln!("\tPassword list:\tThe path to the password list you want to go through");
	eprintln!("\nOperation hash:\n");
	eprintln!("Usage: rainbow hash [<Algorithm>] [<Multiplier>] [<String>]\n");
	eprintln!(
		"\tAlgorithm:\tThe Algorithm you want to use for hashing. Supported: sha224, sha256, sha384, sha512, sha512_224, sha512_256, md5"
	);
	eprintln!(
		"\tMultiplier:\tThe amount of times the password should be hashed. Optional parameter."
	);
	eprintln!("\tString:\t\tThe string you want to hash");
	eprintln!();
}
