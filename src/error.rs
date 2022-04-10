use std::io::Error as IoError;
use std::num::ParseIntError;
use thiserror::Error;

#[cfg(target_os = "linux")]
use dynasmrt::DynasmError;
use nix::errno::Errno;
use procfs::ProcError;

pub type InjectionResult<T> = Result<T, InjectionError>;

/// Injection Error Type
#[derive(Debug,Error)]
pub enum InjectionError {
    #[error("INTERNAL ERROR: {0}")]
    InternalError(String),
    #[error("Process was not found, pid: {0}")]
    ProcessNotFound(i32),
    #[error("Library was not found: {0}")]
    LibraryNotFound(String),
    #[error("Symbol was not found: {0}")]
    SymbolNotFound(String),
    #[error("{0}")]
    IoError(#[from] IoError),
    #[error("{0}")]
    ParseIntError(#[from] ParseIntError),
    #[cfg(target_os = "linux")]
    #[error("{0}")]
    DynasmError(#[from] DynasmError),
    #[error("{0}")]
    MemoryError(#[from] MemoryError),
    #[error("{0}")]
    ProcError(#[from] ProcError),
    #[error("Ld was not found")]
    LdNotFound,
    #[error("Freezer Error: {0}")]
    FreezerError(#[from] FreezerError)
}

pub type MemoryResult<T> = Result<T, MemoryError>;

/// Memory Error type
#[derive(Debug,Error)]
pub enum MemoryError {
    #[error("INTERNAL ERROR: {0}")]
    InternalError(String),
    #[error("Read Error: {0}")]
    ReadError(String),
    #[error("Write Error: {0}")]
    WriteError(String),
    #[error("Wildcard Error: {0}")]
    WildcardError(String),
    #[error("{0}")]
    IoError(#[from] std::io::Error),
}

pub type ManipulatorResult<T> = std::result::Result<T, ManipulatorError>;

#[derive(Debug,Error)]
pub enum ManipulatorError {
    #[error("Process not found: {0}")]
    ProcessNotFound(String),
    #[error("{0}")]
    IoError(#[from] std::io::Error),
    #[error("{0}")]
    ProcError(#[from] ProcError),
}

pub type FreezerResult<T> = std::result::Result<T,FreezerError>;

#[derive(Debug,Error)]
pub enum FreezerError {
    #[error("{0}")]
    OtherError(String),
    #[error("{0}")]
    IoError(#[from] std::io::Error),
    #[error("Errno is {0}")]
    Errno(#[from] Errno),
    #[error("{0}")]
    ProcError(#[from] ProcError),
}
