mod utils;

use io::stdout;
use clap::{arg, Command};
use std::env;
use std::fs::File;
use std::io::{self, Read, Write};
use std::process::exit;
use std::time::Duration;
use zeroize::Zeroize;
use rpassword::read_password;
use sysinfo::System;
use utils::compressor::{compress_folder, CompressionType};
pub use utils::crypto::crypto::{decrypt, encrypt};
#[cfg(windows)]
use crate::utils::win_api::file_attributes::{hide_file, unhide_file};

fn main() {
    let matches = build_matches();

    let decrypt = matches.get_flag("decrypt");
    let view = matches.get_flag("view");

    let file = matches.get_one::<String>("file").unwrap();
    let mut target_file = file.clone();

    let metadata = std::fs::metadata(&file).unwrap();
    if metadata.is_dir() {
        // compress folder as TAR
        target_file = compress_folder(&file, &file, CompressionType::Tar)
            .unwrap_or_else(|e| {
                eprintln!("Failed to compress folder: {}", e);
                exit(1);
            });
    }

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
        match decrypt_file(&target_file, &passphrase) {
            Ok(content) => {
                if let Ok(text) = String::from_utf8(content.clone()) {
                    println!("=== File content ===");
                    println!("{}", text);
                } else {
                    println!("The file is binary and cannot be displayed as text.");
                    let size = content.len() as f64 / 1024.0 / 1024.0;
                    println!("File size: {:.2} MB", size);
                    println!();
                }
            }
            Err(e) => eprintln!("Failed to decrypt file: {}", e),
        }
    } else if decrypt {
        let decrypted_file = format!("{}", target_file);
        if let Err(e) = decrypt_to_file(&target_file, &decrypted_file, &passphrase) {
            eprintln!("Failed to decrypt file: {}", e);
        } else {
            println!("File decrypted");
            let _ = std::fs::remove_file(target_file);
        }
    } else {
        if must_prompt {
            let confirm_passphrase = prompt_passphrase("Confirm passphrase: ");
            if passphrase != confirm_passphrase {
                eprintln!("Passphrases do not match");
                exit(1);
            }
        }
        let encrypted_file = format!("{}", target_file);
        if let Err(e) = encrypt_to_file(&target_file, &encrypted_file, &passphrase) {
            eprintln!("Failed to encrypt file: {}", e);
        } else {
            println!("File encrypted");
            let _ = std::fs::remove_file(target_file);
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
    let mut system = System::new();
    system.refresh_cpu_usage();
    let initial_cpu_usage = system.global_cpu_usage();
    std::thread::sleep(Duration::from_millis(200));

    let start = std::time::Instant::now();

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

    let file_name = format!(".{}", output_file);

    let mut out = File::create(&file_name)?;
    out.write_all(&encrypted_content)?;

    #[cfg(windows)]
    hide_file(&file_name)?;

    system.refresh_cpu_usage();
    let final_cpu_usage = system.global_cpu_usage();
    let cpu_usage_diff = (final_cpu_usage - initial_cpu_usage).max(0.0);

    let size = content.len() as f64 / 1024.0 / 1024.0;

    println!("Encryption duration:: {:.2?}", start.elapsed());
    println!("Encryption CPU usage: {:.2}%", cpu_usage_diff);
    println!("Encrypted file size: {:.2} MB", size);

    Ok(())
}

fn decrypt_to_file(input_file: &str, output_file: &str, passphrase: &str) -> Result<(), Box<dyn std::error::Error>> {
    let content = decrypt_file(input_file, passphrase)?;

    let file_name = output_file.trim_start_matches(".");

    let mut out = File::create(file_name)?;
    out.write_all(&content)?;

    #[cfg(windows)]
    unhide_file(&file_name)?;

    Ok(())
}

fn decrypt_file(input_file: &str, passphrase: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut system = System::new();
    system.refresh_cpu_usage();
    let initial_cpu_usage = system.global_cpu_usage();
    std::thread::sleep(Duration::from_millis(200));

    let start = std::time::Instant::now();

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

    system.refresh_cpu_usage();
    let final_cpu_usage = system.global_cpu_usage();
    let cpu_usage_diff = (final_cpu_usage - initial_cpu_usage).max(0.0);

    println!("Decryption duration: {:.2?}", start.elapsed());
    println!("Decryption CPU usage: {:.2}%", cpu_usage_diff);
    Ok(decrypted)
}

fn prompt_passphrase(prompt: &str) -> String {
    print!("{}", prompt);
    stdout().flush().unwrap();
    read_password().unwrap_or_else(|_| {
        eprintln!("Failed to read passphrase");
        exit(1);
    })
}
