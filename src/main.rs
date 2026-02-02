use aes_gcm::{aead::Aead, AeadCore, Aes256Gcm, Key, KeyInit, Nonce};
use argon2::{
    password_hash::{rand_core::OsRng, SaltString},
    Argon2,
};
use rpassword::prompt_password;
use serde_derive::{Deserialize, Serialize};
use std::{
    fs::{self, OpenOptions},
    io::{self, Write},
};

#[derive(Debug, Serialize, Deserialize)]
struct Entry {
    name: String,
    data: Vec<u8>,
    nonce: Vec<u8>,
    salt: Vec<u8>,
}

fn main() {
    let username = "abhinav";
    let pass = "1235";
    let enc = encrypt(format!("{username}\n{pass}").as_bytes(), "password", "asd");
    let de = decrypt(enc, "password");
    println!("{de}");
    return;
    let mut home = std::env::home_dir().unwrap();
    home.push(".local/share/hsv");
    let _ = fs::create_dir(home);
    loop {
        let mut input: String = String::new();
        println!("Welcome to Password Manager!");
        println!("What would you like to do?");
        println!("1. Create a new password vault");
        println!("2. Retreive Password");
        println!("Quit (enter q to quit)");
        io::stdin()
            .read_line(&mut input)
            .expect("Failed to read line");

        match input.as_str() {
            "1" => create_vault(),
            "2" => get_pass(),
            "q" => break,
            err => println!("{err}"),
        }
    }
}

fn create_vault() {
    let mut name: String = String::new();
    println!("Creating a new vault");
    print!("Enter a Vault Name: ");
    io::stdout().flush().unwrap();
    io::stdin()
        .read_line(&mut name)
        .expect("Failed to read Vault Name");
    let m_pass =
        prompt_password("Please Enter a master password: ").expect("Failed to read password");
    let r_pass =
        prompt_password("Please re-enter master password: ").expect("Failed to read password");
    match r_pass {
        pass if pass == m_pass => (),
        _ => println!("Passwords do not match"),
    }
    let mut path = std::env::home_dir().unwrap();
    path.push(format!(".local/share/hsv/{}.hsv", name.trim()));

    match fs::exists(&path) {
        Ok(true) => println!("A vault with this name already exsists"),
        Ok(false) => fs::write(path, "").expect("Unable to write to file"),
        Err(err) => panic!("Unable to check if vault exists: {err}"),
    }
}

fn get_pass() {
    todo!()
}

fn gen_hash(password: &str, salt: &[u8]) -> [u8; 32] {
    let argon2 = Argon2::default();
    let mut hash: [u8; 32] = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut hash)
        .unwrap();
    hash
}

fn encrypt(data: &[u8], password: &str, name: &str) -> Entry {
    let salt = SaltString::generate(&mut OsRng);
    let salt = salt.as_str().as_bytes();

    let password_hash: [u8; 32] = gen_hash(password, salt);
    let key: &Key<Aes256Gcm> = &password_hash.into();
    let cipher = Aes256Gcm::new(key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    match cipher.encrypt(&nonce, data) {
        Ok(encrypted_data) => Entry {
            name: name.to_owned(),
            data: encrypted_data,
            nonce: nonce.to_vec(),
            salt: salt.to_vec(),
        },
        Err(err) => panic!("Unable to encrypt data: {err}"),
    }
}

fn decrypt(encrypted_data: Entry, password: &str) -> String {
    let password_hash: [u8; 32] = gen_hash(password, &encrypted_data.salt);
    let key: &Key<Aes256Gcm> = &password_hash.into();
    let data = encrypted_data.data;
    let nonce = encrypted_data.nonce;
    let nonce = Nonce::from_slice(&nonce);
    let cipher = Aes256Gcm::new(key);
    let op = cipher.decrypt(nonce, data.as_slice()).unwrap();
    let plaintext = str::from_utf8(&op).unwrap();
    plaintext.to_owned()
}

fn read(path: &str) {
    let file_content: String = fs::read_to_string(path).unwrap();
}

fn write(path: &str, data: Entry) {
    let mut file = OpenOptions::new().append(true).open(path).unwrap();
    writeln!(file, "{data:?}").unwrap();
}
