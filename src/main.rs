use sha2::{Digest, Sha256};
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

	let correct_password = password_list.iter().find_map(|current_password| {
		if hex::encode(Sha256::digest(format!("{}{}", current_password, salt)))
			== original_hashed_password
		{
			Some(current_password.clone())
		} else {
			None
		}
	});

	if correct_password == None {
		println!("Password is not in list or hashed differently.");
	} else {
		print!(
			"Success! Password found in list: {}",
			correct_password.as_deref().unwrap_or("none-case string")
		);
	}
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
