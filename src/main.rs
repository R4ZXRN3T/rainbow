use sha2::{Digest, Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256};
use std::env::args;
use std::fs::read_to_string;

fn main() -> Result<(), Box<dyn std::error::Error>> {
	let args: Vec<String> = args().collect();

	let (original_hashed_password, salt, password_list_path) = parse_args(&args)?;

	println!("Processing list...");
	let password_list = get_password_list(&password_list_path)?;

	let hash_types = HashType::from_length(original_hashed_password.len());
	if hash_types.is_empty() {
		println!(
			"Unsupported hash length: {}",
			original_hashed_password.len()
		);
		return Ok(());
	}

	for hash_type in hash_types {
		if let Some(password) = hash_type.check(&original_hashed_password, &salt, &password_list) {
			println!("Success! Password found: {}", password);
			return Ok(());
		}
	}

	println!("Password not found in list.");
	Ok(())
}

fn parse_args(args: &[String]) -> Result<(String, String, String), &'static str> {
	match args.len() {
		3 => Ok((args[1].clone(), String::new(), args[2].clone())),
		4 => Ok((args[1].clone(), args[2].clone(), args[3].clone())),
		_ => {
			print_usage();
			Err("Invalid number of arguments")
		}
	}
}

fn get_password_list(path: &str) -> Result<Vec<String>, std::io::Error> {
	Ok(read_to_string(path)?
		.lines()
		.map(|line| line.to_string())
		.collect())
}

enum HashType {
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
			56 => vec![Self::Sha224, Self::Sha512_224],
			64 => vec![Self::Sha256, Self::Sha512_256],
			96 => vec![Self::Sha384],
			128 => vec![Self::Sha512],
			_ => vec![],
		}
	}

	fn check(
		&self,
		original_hashed_password: &str,
		salt: &str,
		password_list: &[String],
	) -> Option<String> {
		match self {
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

fn check_hash<D: Digest>(
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

fn print_usage() {
	eprintln!("Wrong Arguments!\n");
	eprintln!("Usage: rainbow [<Hash>] [<Salt>] [<Password list>]\n");
	eprintln!("\tHash:\t\tThe hashed password you want to crack");
	eprintln!("\tSalt:\t\tThe salt used for generating the password. This is optional");
	eprintln!("\tPassword list:\tThe path to the password list you want to go through");
}
