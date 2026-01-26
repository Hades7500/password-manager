use std::{
    io::{self, Write},
    fs
};
use argon2::{
    Argon2, password_hash::{
        SaltString, rand_core::OsRng
    }
};

use rpassword::prompt_password;
use aes_gcm::{AeadCore, Aes256Gcm, Key, KeyInit, aead::{Aead}};

enum StatusCode {
    CreateVault,
    Quit,
    IncorrectInput(String)
}

fn main() {
    encrypt(b"1234", "password");
    return;
    let mut home = std::env::home_dir().unwrap();
    home.push(".local/share/hsv");
    let _ = fs::create_dir(home);
    loop {
        let mut input: String = String::new();
        println!("Welcome to Password Manager!");
        println!("What would you like to do?");
        println!("1. Create a new password vault");
        println!("Quit (enter q to quit)");
        io::stdin().read_line(&mut input).expect("Failed to read line");
        match read_input(input.trim()) {
            StatusCode::CreateVault => (),
            StatusCode::Quit => break,
            StatusCode::IncorrectInput(err) => println!("Incorrect Option Selected {err}")
        }
    }
}

fn read_input(input: &str) -> StatusCode {
    match input {
        "1" => {create_vault();
                StatusCode::CreateVault},
        "q" => StatusCode::Quit,
        err => StatusCode::IncorrectInput(String::from(err))
    }
}

fn create_vault() {
    let mut name: String = String::new();
    println!("Creating a new vault");
    print!("Enter a Vault Name: ");
    io::stdout().flush().unwrap();
    io::stdin().read_line(&mut name).expect("Failed to read Vault Name");
    let m_pass = prompt_password("Please Enter a master password: ").expect("Failed to read password");
    let r_pass = prompt_password("Please re-enter master password: ").expect("Failed to read password");
    match r_pass {
        pass if pass == m_pass => (),
        _ => println!("Passwords do not match")
    }
    let mut path = std::env::home_dir().unwrap();
    path.push(format!(".local/share/hsv/{}.hsv", name.trim()));

    match fs::exists(&path) {
        Ok(true) => println!("A vault with this name already exsists"),
        Ok(false) => fs::write(path, "").expect("Unable to write to file"),
        Err(err) => panic!("Unable to check if vault exists: {err}")
    }
    
}

fn encrypt(data: &[u8], password: &str) {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let mut password_hash: [u8; 32] = [0u8; 32];
    argon2.hash_password_into(password.as_bytes(), salt.as_str().as_bytes(), &mut password_hash).unwrap();
    let key: &Key<Aes256Gcm> = &password_hash.into();
    let cipher = Aes256Gcm::new(&key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher.encrypt(&nonce, data).expect("dsds");
    println!("{ciphertext:?}");
}

fn decrypt() {
    
}