mod utils;

use clap::{arg, Command};
use std::fs::File;
use std::io::{self, Read, Write};
use std::process::exit;
use std::env;
use zeroize::Zeroize;

pub use utils::crypto::crypto::{decrypt, encrypt};

fn main() {
    let matches = build_matches();

    let decrypt = matches.get_flag("decrypt");
    let view = matches.get_flag("view");

    let file = matches.get_one::<String>("file").unwrap();

    let must_prompt = !matches.contains_id("passphrase");
    let mut  passphrase = if let Some(p) = matches.get_one::<String>("passphrase") {
        p.to_string()
    } else {
        prompt_passphrase("Enter passphrase: ")
    };

    if passphrase.is_empty() {
        eprintln!("Error: passphrase is required");
        exit(1);
    }

    if view {
        match decrypt_file(file, &passphrase) {
            Ok(content) => println!("{}", content),
            Err(e) => eprintln!("Failed to decrypt file: {}", e),
        }
    } else if decrypt {
        let decrypted_file = format!("{}", file);
        if let Err(e) = decrypt_to_file(file, &decrypted_file, &passphrase) {
            eprintln!("Failed to decrypt file: {}", e);
        } else {
            println!("File decrypted");
        }
    } else {
        if must_prompt {
            let confirm_passphrase = prompt_passphrase("Confirm passphrase: ");
            if passphrase != confirm_passphrase {
                eprintln!("Passphrases do not match");
                exit(1);
            }
        }
        let encrypted_file = format!("{}", file);
        if let Err(e) = encrypt_to_file(file, &encrypted_file, &passphrase) {
            eprintln!("Failed to encrypt file: {}", e);
        } else {
            println!("File encrypted");
        }
    }

    passphrase.zeroize();

    exit(0);
}

fn build_matches() -> clap::ArgMatches {
    let matches = Command::new(env!("CARGO_PKG_NAME"))
        .version(env!("CARGO_PKG_VERSION"))
        .author(env!("CARGO_PKG_AUTHORS"))
        .about(env!("CARGO_PKG_DESCRIPTION"))
        .arg(arg!([file] "File to encrypt/decrypt").required(true).index(1))
        .arg(arg!(-p --passphrase <passphrase> "Passphrase for encryption/decryption"))
        .arg(arg!(-d --decrypt "Decrypt the file").conflicts_with("view"))
        .arg(arg!(-v --view "View decrypted content without saving").conflicts_with("decrypt"))
        .arg_required_else_help(true);

    matches.get_matches()
}

fn encrypt_to_file(input_file: &str, output_file: &str, passphrase: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = match File::open(input_file) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Failed to open file '{}': {}", input_file, e);
            exit(1);
        }
    };
    let mut content = Vec::new();
    file.read_to_end(&mut content)?;

    let encrypted_content = encrypt(passphrase, &content)?;

    let mut out = File::create(output_file)?;
    out.write_all(&encrypted_content)?;

    Ok(())
}

fn decrypt_to_file(input_file: &str, output_file: &str, passphrase: &str) -> Result<(), Box<dyn std::error::Error>> {
    let content = decrypt_file(input_file, passphrase)?;
    let mut out = File::create(output_file)?;
    out.write_all(content.as_bytes())?;
    Ok(())
}

fn decrypt_file(input_file: &str, passphrase: &str) -> Result<String, Box<dyn std::error::Error>> {
    let mut file = match File::open(input_file) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Failed to open file '{}': {}", input_file, e);
            exit(1);
        }
    };
    let mut content = Vec::new();
    file.read_to_end(&mut content)?;

    let decrypted = decrypt(passphrase, &content)?;
    Ok(String::from_utf8_lossy(&decrypted).into_owned())
}

// #[cfg(not(target_os = "windows"))]
fn prompt_passphrase(prompt: &str) -> String {
    use rpassword::read_password;
    print!("{}", prompt);
    io::stdout().flush().unwrap();
    read_password().unwrap_or_else(|_| {
        eprintln!("Failed to read passphrase");
        exit(1);
    })
}

// #[cfg(target_os = "windows")]
// fn prompt_passphrase(prompt: &str) -> String {
//     use rpassword::read_password_from_bufread;
//     print!("{}", prompt);
//     io::stdout().flush().unwrap();
//     read_password_from_bufread(None).unwrap_or_default()
// }
