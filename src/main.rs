use std::env;

fn main() {
    let mut args: Vec<String> = env::args().collect();
    let mut hashed_password: String = "".to_owned();
    let mut salt: String = "".to_owned();
    let mut password_list_path: String = "".to_owned();
    
    if args.len() == 2 {
        hashed_password = args[0].clone();
        password_list_path = args[1].clone();
    } else if args.len() == 3 {
        hashed_password = args[0].clone();
        salt = args[1].clone();
        password_list_path = args[2].clone();
    } else {
        print_usage();
        return;
    }
    drop(args);
}

fn print_usage() {
    eprintln!("Wrong Arguments!\n");
    eprintln!("Usage: rainbow [<Hash>] [<Salt>] [<Password list>]\n");
    eprintln!("\tHash:\t\tThe hashed password you want to crack");
    eprintln!("\tSalt:\t\tThe salt used for generating the password. This is optional");
    eprintln!("\tPassword list:\tThe path to the password list you want to go through");
}
