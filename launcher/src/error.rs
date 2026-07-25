use std::fmt::{Display, Formatter};

use anyhow::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ExitCategory {
    ProjectRoot = 10,
    CapsuleConflict = 11,
    ClientConflict = 12,
    WorkflowPolicy = 13,
    RuntimeMissing = 20,
    RuntimeIntegrity = 21,
    Incompatible = 22,
    Signature = 23,
    Installer = 24,
    SidecarLaunch = 30,
    Doctor = 31,
    ClientLaunch = 32,
    Update = 40,
    UpdateRolledBack = 41,
    Uninstall = 42,
    Internal = 50,
}

#[derive(Debug)]
pub struct CategorizedError {
    category: ExitCategory,
    message: String,
}

impl CategorizedError {
    pub fn new(category: ExitCategory, message: impl Into<String>) -> Self {
        Self {
            category,
            message: message.into(),
        }
    }

    pub fn code(&self) -> u8 {
        self.category as u8
    }
}

impl Display for CategorizedError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for CategorizedError {}

pub fn fail(category: ExitCategory, message: impl Into<String>) -> Error {
    Error::new(CategorizedError::new(category, message))
}

pub fn categorize<T>(result: Result<T>, category: ExitCategory) -> Result<T> {
    result.map_err(|error| {
        if exit_code(&error).is_some() {
            error
        } else {
            Error::new(CategorizedError::new(category, format!("{error:#}")))
        }
    })
}

pub fn exit_code(error: &Error) -> Option<u8> {
    error.chain().find_map(|cause| {
        cause
            .downcast_ref::<CategorizedError>()
            .map(CategorizedError::code)
    })
}

#[cfg(test)]
mod tests {
    use anyhow::{anyhow, Context};

    use super::*;

    #[test]
    fn categorization_preserves_the_first_stable_category_through_context() {
        let original: Result<()> = Err(fail(ExitCategory::Signature, "bad signature"));
        let contextual = original.context("runtime refused");
        let remapped = categorize(contextual, ExitCategory::RuntimeIntegrity).unwrap_err();
        assert_eq!(exit_code(&remapped), Some(23));
        assert!(format!("{remapped:#}").contains("bad signature"));
    }

    #[test]
    fn uncategorized_errors_receive_the_boundary_category() {
        let result: Result<()> = Err(anyhow!("missing"));
        let error = categorize(result, ExitCategory::RuntimeMissing).unwrap_err();
        assert_eq!(exit_code(&error), Some(20));
    }
}
