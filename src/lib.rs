//! This library helps injecting dynamic libraries into processes
//! and manipulating the memory of these processes.
//! Currently only Linux is supported but support for other platforms (freebsd, windows) is coming.
//!
//! ```rust
//!  use injex::prelude::*;
//!  use std::path::PathBuf;
//!  use std::error::Error;
//!
//!  fn main() -> Result<(), Box<dyn Error>> {
//!     let pids = find_process_by_name("target").unwrap()[0];
//!     inject::<CGroupFreezer, ProcManipulator, PathBuf>(
//!         pid,"lib.so".into()
//!     ).unwrap();
//!     Ok(())
//!  }
//! ```


pub mod injection;
pub mod manipulator;
pub mod error;
pub mod freezer;

pub mod prelude {
    pub use crate::manipulator::ProcManipulator;
    pub use crate::manipulator::ProcessVMManipulator;
    pub use crate::freezer::SignalFreezer;
    pub use crate::freezer::CGroupFreezer;

    pub use crate::injection::inject;
    pub use crate::injection::find_process_by_name;
    pub use crate::manipulator::MemoryManipulation;
    pub use crate::freezer::Freezer;
}
