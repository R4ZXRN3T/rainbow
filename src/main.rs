use sha2::{Digest, Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256};
use std::env::args;
use std::fs::read_to_string;

fn main() {
	let args: Vec<String> = args().collect();

	let original_hashed_password;
	let password_list_path;
	let mut salt: String = "".to_owned();

	if args.len() == 3 {
		original_hashed_password = args[1].clone();
		password_list_path = args[2].clone();
	} else if args.len() == 4 {
		original_hashed_password = args[1].clone();
		salt = args[2].clone();
		password_list_path = args[3].clone();
	} else {
		print_usage();
		return;
	}

	println!("Processing list...");

	drop(args);
	let password_list = get_password_list(&password_list_path);
	drop(password_list_path);

	let mut correct_password: Option<String>;
	if original_hashed_password.len() == 56 {
		correct_password = check_for_sha224(&original_hashed_password, &salt, &password_list);
		if correct_password == None {
			correct_password =
				check_for_sha512_224(&original_hashed_password, &salt, &password_list);
		}
	} else if original_hashed_password.len() == 64 {
		correct_password = check_for_sha256(&original_hashed_password, &salt, &password_list);
		if correct_password == None {
			correct_password =
				check_for_sha512_256(&original_hashed_password, &salt, &password_list);
		}
	} else if original_hashed_password.len() == 96 {
		correct_password = check_for_sha348(&original_hashed_password, &salt, &password_list);
	} else if original_hashed_password.len() == 128 {
		correct_password = check_for_sha512(&original_hashed_password, &salt, &password_list);
	} else {
		correct_password = None;
	}

	if correct_password == None {
		println!("Password is not in list or hashed differently.");
	} else {
		print!(
			"Success! Password found in list: {}",
			correct_password.as_deref().unwrap_or("none-case string")
		);
	}
}

fn check_for_sha224(
	original_hashed_password: &str,
	salt: &str,
	password_list: &Vec<String>,
) -> Option<String> {
	let correct_password = password_list.iter().find_map(|current_password| {
		if hex::encode(Sha224::digest(format!("{}{}", current_password, salt)))
			== original_hashed_password
		{
			Some(current_password.clone())
		} else {
			None
		}
	});
	correct_password
}
fn check_for_sha256(
	original_hashed_password: &str,
	salt: &str,
	password_list: &Vec<String>,
) -> Option<String> {
	let correct_password = password_list.iter().find_map(|current_password| {
		if hex::encode(Sha256::digest(format!("{}{}", current_password, salt)))
			== original_hashed_password
		{
			Some(current_password.clone())
		} else {
			None
		}
	});
	correct_password
}

fn check_for_sha348(
	original_hashed_password: &str,
	salt: &str,
	password_list: &Vec<String>,
) -> Option<String> {
	let correct_password = password_list.iter().find_map(|current_password| {
		if hex::encode(Sha384::digest(format!("{}{}", current_password, salt)))
			== original_hashed_password
		{
			Some(current_password.clone())
		} else {
			None
		}
	});
	correct_password
}

fn check_for_sha512(
	original_hashed_password: &str,
	salt: &str,
	password_list: &Vec<String>,
) -> Option<String> {
	let correct_password = password_list.iter().find_map(|current_password| {
		if hex::encode(Sha512::digest(format!("{}{}", current_password, salt)))
			== original_hashed_password
		{
			Some(current_password.clone())
		} else {
			None
		}
	});
	correct_password
}

fn check_for_sha512_224(
	original_hashed_password: &str,
	salt: &str,
	password_list: &Vec<String>,
) -> Option<String> {
	let correct_password = password_list.iter().find_map(|current_password| {
		if hex::encode(Sha512_224::digest(format!("{}{}", current_password, salt)))
			== original_hashed_password
		{
			Some(current_password.clone())
		} else {
			None
		}
	});
	correct_password
}

fn check_for_sha512_256(
	original_hashed_password: &str,
	salt: &str,
	password_list: &Vec<String>,
) -> Option<String> {
	let correct_password = password_list.iter().find_map(|current_password| {
		if hex::encode(Sha512_256::digest(format!("{}{}", current_password, salt)))
			== original_hashed_password
		{
			Some(current_password.clone())
		} else {
			None
		}
	});
	correct_password
}

fn get_password_list(path: &str) -> Vec<String> {
	let mut contents: Vec<String> = Vec::new();
	for line in read_to_string(path).unwrap().lines() {
		contents.push(line.to_string());
	}
	contents
}

fn print_usage() {
	eprintln!("Wrong Arguments!\n");
	eprintln!("Usage: rainbow [<Hash>] [<Salt>] [<Password list>]\n");
	eprintln!("\tHash:\t\tThe hashed password you want to crack");
	eprintln!("\tSalt:\t\tThe salt used for generating the password. This is optional");
	eprintln!("\tPassword list:\tThe path to the password list you want to go through");
}
