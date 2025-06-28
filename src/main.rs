use sha256::{digest, try_digest};
use std::env::args;
use std::fs::read_to_string;

fn main() {
	let args: Vec<String> = args().collect();
	let mut original_hashed_password: String = "".to_owned();
	let mut salt: String = "".to_owned();
	let mut password_list_path: String = "".to_owned();

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
	drop(args);
	let password_list = get_password_list(password_list_path.as_str());
	drop(password_list_path);

	let correct_password = "".to_owned();

	for current_password in password_list {
		let hashed_password = digest(current_password);
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
