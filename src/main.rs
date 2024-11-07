mod utils;

use crate::utils::hasher::{decrypt, encrypt};
use clap::{arg, Command};
use std::fs::File;
use std::io::{self, Read, Write};
use std::process::exit;
use std::env;

fn main() {
    let name = env!("CARGO_PKG_NAME");
    let version = env!("CARGO_PKG_VERSION");
    let authors = env!("CARGO_PKG_AUTHORS");
    let about = env!("CARGO_PKG_DESCRIPTION");


    let matches = Command::new(name)
        .version(version)
        .author(authors)
        .about(about)
        .arg(arg!([file] "File to encrypt/decrypt").required(true).index(1))
        .arg(arg!(-p --passphrase <passphrase> "Passphrase for encryption/decryption"))
        .arg(arg!(-d --decrypt "Decrypt the file"))
        .arg(arg!(-v --view "View decrypted content without saving"))
        .get_matches();

    if matches.contains_id("help") {
        print_help();
        exit(0);
    }

    let decrypt = matches.get_flag("decrypt");
    let view = matches.get_flag("view");

    let file = matches.get_one::<String>("file").unwrap();

    let passphrase: &str;
    let mut must_prompt = !matches.contains_id("passphrase");
    if matches.contains_id("passphrase") {
        passphrase = matches.get_one::<String>("passphrase").unwrap();
        must_prompt = false;
    } else {
        passphrase = prompt_passphrase("Enter passphrase: ");
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
}

fn print_help() {
    println!("Usage: [options] <file>");
    println!("Options:");
    println!("  -h, --help             Show this help message");
    println!("  -v, --view             View decrypted content");
    println!("  -d, --decrypt          Decrypt the file");
    println!("  -p, --passphrase <passphrase>   Provide passphrase directly");
}
fn encrypt_to_file(input_file: &str, output_file: &str, passphrase: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = File::open(input_file)?;
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
    let mut file = File::open(input_file)?;
    let mut content = Vec::new();
    file.read_to_end(&mut content)?;

    let decrypted = decrypt(passphrase, &content)?;
    Ok(String::from_utf8_lossy(&decrypted).into_owned())
}

fn prompt_passphrase(prompt: &str) -> &str {
    use rpassword::read_password;
    print!("{}", prompt);
    io::stdout().flush().unwrap();
    let result = read_password().unwrap_or_default().clone();

    Box::leak(result.into_boxed_str())
}
