use std::path::Path;
use std::process::Command;
use super::{Error, Result};

#[cfg(target_os = "windows")]
pub fn hide_file_windows(file_path: &str) -> Result<()> {
    let file_path = Path::new(file_path);
    let command = format!("attrib +h +s +r \"{}\"", file_path.display());
    let output = Command::new("cmd")
        .args(&["/C", &command])
        .output()
        .or(Err(Error::WindowsCommandFail))?;
    if !output.status.success() {
        return Err(Error::WindowsCommandFail);
    }
    Ok(())
}

#[cfg(target_os = "windows")]
pub fn unhide_file_windows(file_path: &str) -> Result<()> {
    let file_path = Path::new(file_path);
    let command = format!("attrib -h -s -r \"{}\"", file_path.display());
    let output = Command::new("cmd")
        .args(&["/C", &command])
        .output()
        .or(Err(Error::WindowsCommandFail))?;
    if !output.status.success() {
        return Err(Error::WindowsCommandFail);
    }
    Ok(())
}
