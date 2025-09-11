use clap::{Parser, Subcommand};
use sha2::{Digest as Sha2Digest, Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256};
use std::fs::read_to_string;
use std::io::stdout;
use std::io::Error;
use std::io::Write;
use std::time::SystemTime;

#[derive(Parser, Debug)]
#[command(
	name = "rainbow",
	version,
	about = "A tool for hashing and cracking hashes.",
	long_about = "\nUsage: rainbow [<Operation>] [<Arguments>]\n\n\
Operation crack:\n\
Usage: rainbow crack --input <Hash> [--salt <Salt>] [--multiplier <Multiplier>] --password-list <Password list>\n\n\
\tHash:           The hashed password you want to crack\n\
\tSalt:           The salt used for generating the password. This is optional\n\
\tMultiplier:     The number of times the password was hashed. This is optional\n\
\tPassword list:  The path to the password list you want to go through\n\n\
Operation hash:\n\
Usage: rainbow hash --algorithm <Algorithm> [--multiplier <Multiplier>] [--salt <Salt>] --input <String>\n\n\
\tAlgorithm:      The Algorithm you want to use for hashing. Supported: sha224, sha256, sha384, sha512, sha512_224, sha512_256, md5\n\
\tMultiplier:     The amount of times the password should be hashed. Optional parameter.\n\
\tSalt:           A salt to add of the end of the string. Only relevant with multiplier enabled\n\
\tString:         The string you want to hash"
)]
struct Args {
	#[command(subcommand)]
	command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
	#[command(about = "Hash a string using a specified algorithm")]
	Hash(HashArgs),
	#[command(about = "Crack a hash using a password list")]
	Crack(CrackArgs),
}

#[derive(Parser, Debug)]
struct HashArgs {
	#[arg(
		short = 'a',
		long = "algorithm",
		help = "Hash algorithm (sha224, sha256, sha384, sha512, sha512_224, sha512_256, md5)"
	)]
	algorithm: String,
	#[arg(
		short = 'm',
		long = "multiplier",
		default_value_t = 1,
		help = "Number of times to hash"
	)]
	multiplier: i32,
	#[arg(short = 'i', long = "input", help = "String to hash")]
	string: String,
	#[arg(short = 's', long = "salt", default_value = "", help = "Optional salt")]
	salt: String,
	#[arg(
		long = "verbosity",
		default_value_t = 2,
		help = "Verbosity level (0-2)"
	)]
	verbosity_level: i32,
}

#[derive(Parser, Debug)]
struct CrackArgs {
	#[arg(short = 'i', long = "input", help = "Hash to crack")]
	hash: String,
	#[arg(short = 's', long = "salt", default_value = "", help = "Optional salt")]
	salt: String,
	#[arg(
		short = 'l',
		long = "password-list",
		help = "Path to password list file"
	)]
	password_list: String,
	#[arg(
		short = 'm',
		long = "multiplier",
		default_value_t = 1,
		help = "Number of times to hash (default: 1)"
	)]
	multiplier: i32,
	#[arg(
		long = "verbosity",
		default_value_t = 2,
		help = "Verbosity level (0-2)"
	)]
	verbosity_level: i32,
}
fn main() -> Result<(), &'static str> {
	let args = Args::parse();

	match args.command {
		Commands::Hash(hash_args) => hash(
			hash_args.algorithm,
			hash_args.multiplier,
			hash_args.string,
			hash_args.salt,
			hash_args.verbosity_level,
		),
		Commands::Crack(crack_args) => crack_hash(
			crack_args.hash,
			crack_args.salt,
			crack_args.multiplier,
			crack_args.password_list,
			crack_args.verbosity_level,
		),
	}
}

fn hash(
	algorithm_string: String,
	multiplier: i32,
	to_hash: String,
	salt: String,
	verbosity_level: i32,
) -> Result<(), &'static str> {
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

	let start_time = SystemTime::now();
	let hashed_string = algorithm.hash(&to_hash, multiplier, &salt);
	let total_milliseconds: f64 =
		(start_time.elapsed().expect("Error getting time").as_nanos() as f64) / 1000000.0;

	match verbosity_level {
		0 => println!("{}", hashed_string),
		1 => println!("\nHashed string: {}\n", hashed_string),
		_ => println!(
			"\nHashed string: {}\n took: {}ms\n",
			hashed_string, total_milliseconds
		),
	}

	Ok(())
}

fn crack_hash(
	original_hashed_password: String,
	salt: String,
	multiplier: i32,
	password_list_path: String,
	verbosity_level: i32,
) -> Result<(), &'static str> {
	if verbosity_level != 0 {
		print!("\nReading list...");
		stdout().flush().expect("Error flushing console");
	}
	let total_start_time = SystemTime::now();

	let mut start_time = SystemTime::now();
	let password_list = get_password_list(&password_list_path)
		.map_err(|_| "Error: Failed to read password list file")?;
	let total_milliseconds: f64 =
		(start_time.elapsed().expect("Error getting time").as_nanos() as f64) / 1000000.0;
	match verbosity_level {
		0 => (),
		1 => {
			print!(" Done!\n");
			stdout().flush().expect("Error flushing console");
		}
		_ => {
			print!(" Done! in {}ms\n", total_milliseconds);
			stdout().flush().expect("Error flushing console");
		}
	}

	let hash_types = HashType::from_length(original_hashed_password.len());
	if hash_types.is_empty() {
		println!(
			"Unsupported hash length: {}",
			original_hashed_password.len()
		);
		return Err("Unsupported hash length");
	}

	if verbosity_level != 0 {
		print!("Hashing list...");
		stdout().flush().expect("Error flushing console");
	}

	start_time = SystemTime::now();
	for hash_type in hash_types {
		if let Some(password) =
			hash_type.check(&original_hashed_password, &salt, &password_list, multiplier)
		{
			let hash_milliseconds: f64 =
				(start_time.elapsed().expect("Error getting time").as_nanos() as f64) / 1000000.0;
			let total_milliseconds: f64 = (total_start_time
				.elapsed()
				.expect("Error getting time")
				.as_nanos() as f64)
				/ 1000000.0;
			match verbosity_level {
				0 => println!("{}", password),
				1 => println!(" Done!\n\nHashed string: {}\n", password),
				_ => println!(
					" Done! in {}ms\n\nHashed string: {}\n took: {}ms\n",
					hash_milliseconds, password, total_milliseconds
				),
			}
			return Ok(());
		}
	}

	println!(" Done\nPassword not found in list.");
	stdout().flush().expect("Error flushing console");
	Ok(())
}

fn get_password_list(path: &str) -> Result<Vec<String>, Error> {
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

	fn hash(&self, to_hash: &str, multiplier: i32, salt: &str) -> String {
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

	fn check(
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

fn check_hash<D: Sha2Digest>(
	original_hashed_password: &str,
	salt: &str,
	password_list: &[String],
	multiplier: i32,
) -> Option<String>
where
	D: Default,
{
	password_list.iter().find_map(|current_password| {
		let mut final_string = String::with_capacity(current_password.len() + salt.len());
		final_string.push_str(current_password);
		final_string.push_str(salt);

		if multiplier == 1 {
			let hash = hex::encode(D::digest(&final_string));
			if hash == original_hashed_password {
				return Some(current_password.clone());
			}
		} else {
			let mut hash = final_string;
			for _ in 0..multiplier {
				hash = hex::encode(D::digest(&hash));
			}
			if hash == original_hashed_password {
				return Some(current_password.clone());
			}
		}
		None
	})
}

fn check_md5(
	original_hashed_password: &str,
	salt: &str,
	password_list: &[String],
	multiplier: i32,
) -> Option<String> {
	password_list.iter().find_map(|current_password| {
		let mut final_string = format!("{}{}", current_password, salt);
		for _ in 0..multiplier {
			final_string = format!("{:x}", md5::compute(&final_string));
		}
		if final_string == original_hashed_password {
			Some(current_password.clone())
		} else {
			None
		}
	})
}

fn hash_sha2<D: Sha2Digest>(to_hash: &str, multiplier: i32, salt: &str) -> String {
	let mut final_string = to_hash.to_owned();
	for _i in 0..multiplier {
		final_string = hex::encode(D::digest(format!("{}", final_string + salt)));
	}
	final_string
}

fn hash_md5(to_hash: &str, multiplier: i32, salt: &str) -> String {
	let mut final_string = to_hash.to_owned();
	for _i in 0..multiplier {
		final_string = format!("{:x}", md5::compute(format!("{}", final_string + salt)));
	}
	final_string
}
