#[cfg(target_os = "windows")] use super::Result;

#[cfg(target_os = "windows")]
pub fn hide_file_windows(file_path: &str) -> Result<()> {
    use super::Error;
    use std::path::Path;
    use std::process::Command;
    let file_path = Path::new(file_path);
    let command = format!("attrib +h {}", file_path.display());
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
    use super::Error;
    use std::path::Path;
    use std::process::Command;
    let file_path = Path::new(file_path);
    let command = format!("attrib -h {}", file_path.display());
    let output = Command::new("cmd")
        .args(&["/C", &command])
        .output()
        .or(Err(Error::WindowsCommandFail))?;
    if !output.status.success() {
        return Err(Error::WindowsCommandFail);
    }
    Ok(())
}
