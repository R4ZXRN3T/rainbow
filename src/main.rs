use clap::{Parser, Subcommand};
use rainbow::{get_password_list, HashType};
use std::io::stdout;
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
