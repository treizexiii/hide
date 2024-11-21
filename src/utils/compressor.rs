use std::fs::File;
use std::path::Path;
use tar::Builder;
use zip::write::{ExtendedFileOptions, FileOptions};
use zip::{CompressionMethod, ZipWriter};
use super::{Error, Result};

pub enum CompressionType {
    Tar,
    Zip,
}

impl CompressionType {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "tar" => Some(CompressionType::Tar),
            "zip" => Some(CompressionType::Zip),
            _ => None,
        }
    }
}

pub fn compress_folder(folder_path: &str, flag: CompressionType) -> Result<String> {
    match flag {
        CompressionType::Tar => compress_folder_as_tar(folder_path),
        CompressionType::Zip => compress_folder_to_zip(folder_path),
    }
}

fn compress_folder_as_tar(folder_path: &str) -> Result<String> {
    let folder_path = Path::new(folder_path);
    if !folder_path.is_dir() {
        return Err(Error::FolderNotFound);
    }

    let file_name = format!("{}.tar", folder_path.file_name().unwrap().to_str().unwrap());
    let tar_file = File::create(&file_name)
        .map_err(|_| Error::FileCreateFail(file_name.to_string()))?;
    let mut tar_builder = Builder::new(tar_file);

    for entry in walkdir::WalkDir::new(folder_path) {
        let entry = entry
            .map_err(|_| Error::FolderNotFound)?;
        let path = entry.path();
        let relative_path = path.strip_prefix(&folder_path)
            .map_err(|_| Error::FolderNotFound)?;

        if path.is_file() {
            let mut file = File::open(path)
                .map_err(|_| Error::FolderNotFound)?;
            tar_builder.append_file(relative_path, &mut file)
                .map_err(|_| Error::FolderNotFound)?;
        } else if path.is_dir() && relative_path != Path::new("") {
            tar_builder.append_dir(relative_path, path)
                .map_err(|_| Error::FolderNotFound)?;
        }
    }

    tar_builder.finish()
        .map_err(|_| Error::CompressionFailed)?;

    Ok(file_name)
}

fn compress_folder_to_zip(folder_path: &str) -> Result<String> {
    let folder_path = Path::new(folder_path);
    if !folder_path.is_dir() {
        return Err(Error::FolderNotFound);
    }

    let file_name = format!("{}.zip", folder_path.file_name().unwrap().to_str().unwrap());
    let file = File::create(&file_name)
        .map_err(|_| Error::FileCreateFail(file_name.to_string()))?;
    let mut zip = ZipWriter::new(file);

    // Utiliser ExtendedFileOptions pour la compression
    let options: FileOptions<ExtendedFileOptions> = FileOptions::default()
        .compression_method(CompressionMethod::Deflated)
        .unix_permissions(0o755);

    for entry in walkdir::WalkDir::new(folder_path) {
        let entry = entry
            .map_err(|_| Error::FolderNotFound)?;
        let path = entry.path();
        let name = path.strip_prefix(Path::new(folder_path))
            .map_err(|_| Error::FolderNotFound)?
            .to_str().unwrap();

        if path.is_file() {
            let mut file = File::open(path)
                .map_err(|_| Error::FolderNotFound)?;
            zip.start_file(name, options.clone())
                .map_err(|_| Error::CompressionFailed)?;

            use std::io;
            io::copy(&mut file, &mut zip)
                .map_err(|_| Error::CompressionFailed)?;
        } else if !name.is_empty() {
            zip.add_directory(name, options.clone())
                .map_err(|_| Error::CompressionFailed)?;
        }
    }

    zip.finish()
        .map_err(|_| Error::CompressionFailed)?;

    Ok(file_name)
}
