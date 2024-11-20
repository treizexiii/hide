// #[cfg(windows)]
pub mod file_attributes {
    use std::ptr::null_mut;
    use winapi::um::fileapi::SetFileAttributesA;
    use winapi::um::winnt::FILE_ATTRIBUTE_HIDDEN;
    use winapi::um::winnt::FILE_ATTRIBUTE_NORMAL;

    pub fn hide_file(file_path: &str) -> Result<(), Box<dyn std::error::Error>> {
        let c_path = std::ffi::CString::new(file_path)?;
        unsafe {
            if SetFileAttributesA(c_path.as_ptr(), FILE_ATTRIBUTE_HIDDEN) == 0 {
                return Err(Box::from("Failed to hide the file"));
            }
        }
        Ok(())
    }

    pub fn unhide_file(file_path: &str) -> Result<(), Box<dyn std::error::Error>> {
        let c_path = std::ffi::CString::new(file_path)?;
        unsafe {
            if SetFileAttributesA(c_path.as_ptr(), FILE_ATTRIBUTE_NORMAL) == 0 {
                return Err(Box::from("Failed to unhide the file"));
            }
        }
        Ok(())
    }
}
