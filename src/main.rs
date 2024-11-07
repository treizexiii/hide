mod utils;

use crate::utils::hasher::{decrypt, encrypt};
use std::env;
use std::fs::File;
use std::io::{self, Read, Write};
use std::process::exit;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 || args.len() > 4 {
        print_help();
        exit(1);
    }

    let flag = if args.len() == 3 { &args[1] } else { "" };
    let file = if args.len() == 3 { &args[2] } else { &args[1] };

    let passphrase = prompt_passphrase("Enter passphrase: ");

    match flag {
        "-h" => {
            print_help();
            exit(0);
        }
        "-v" => {
            match decrypt_file(file, &passphrase) {
                Ok(content) => println!("{}", content),
                Err(e) => eprintln!("Failed to decrypt file: {}", e),
            }
        }
        "-d" => {
            // remove the .enc extension
            // let decrypted_file = file.replace(".enc", "");
            // // remove the . prefix
            // let decrypted_file = &decrypted_file[1..];
            let decrypted_file = format!("{}", file);

            if let Err(e) = decrypt_to_file(file, &decrypted_file, &passphrase) {
                eprintln!("Failed to decrypt file: {}", e);
            } else {
                println!("File decrypted");
            }
        }
        _ => {
            let confirm_passphrase = if flag != "-v" {
                prompt_passphrase("Confirm passphrase: ")
            } else {
                passphrase.clone()
            };

            if passphrase != confirm_passphrase {
                eprintln!("Passphrases do not match");
                exit(1);
            }

            let encrypted_file = format!("{}", file);
            if let Err(e) = encrypt_to_file(file, &encrypted_file, &passphrase) {
                eprintln!("Failed to encrypt file: {}", e);
            } else {
                println!("File encrypted");
            }
        }
    }
}

fn print_help() {
    println!("Usage: [-v] [-d] <file>");
    println!("-v: View the contents of the file");
    println!("-d: Decrypt the file");
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

fn prompt_passphrase(prompt: &str) -> String {
    use rpassword::read_password;
    print!("{}", prompt);
    io::stdout().flush().unwrap();
    read_password().unwrap_or_default()
}
