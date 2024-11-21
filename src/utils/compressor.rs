use std::fs::File;
use std::path::Path;
use tar::Builder;
use super::{Error, Result};

pub enum CompressionType {
    Tar,
    // Zip,
}

pub fn compress_folder(folder_path: &str, compress_file: &str, flag: CompressionType) -> Result<String> {
    match flag {
        CompressionType::Tar => compress_folder_as_tar(folder_path, compress_file),
        // CompressionType::Zip => unimplemented!(),
    }
}

fn compress_folder_as_tar(folder_path: &str, compress_file: &str) -> Result<String> {
    let folder_path = Path::new(folder_path);
    if !folder_path.is_dir() {
        return Err(Error::FolderNotFound);
    }

    let file_name = format!("{}.tar", compress_file);
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
