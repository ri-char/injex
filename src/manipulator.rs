#[cfg(target_os = "linux")]
use {
    nix::{
        sys::uio::{self, IoVec, RemoteIoVec},
        unistd::Pid,
    },
    std::{
        fs::OpenOptions,
        io::{prelude::*, SeekFrom},
    },
};
use crate::error::{MemoryError, MemoryResult};

pub trait MemoryManipulation {
    fn new(pid: i32) -> Self;
    fn pid(&self) -> i32;
    /// Reads into the buffer at the given address and returns the bytes read
    fn read(&self, address: usize, buf: &mut [u8]) -> MemoryResult<usize>;
    /// Writes the payload into the memory at the given address
    fn write(&self, address: usize, payload: &[u8]) -> MemoryResult<usize>;
}


/// Manipulates the process memory from the outside with system calls
#[derive(Default, Debug, Copy, Clone, PartialEq, Eq)]
pub struct ProcessVMManipulator {
    pub pid: i32,
}

#[cfg(target_os = "linux")]
impl MemoryManipulation for ProcessVMManipulator {
    #[inline(always)]
    fn new(pid: i32) -> ProcessVMManipulator {
        ProcessVMManipulator { pid }
    }

    #[inline(always)]
    fn pid(&self) -> i32 {
        self.pid
    }

    fn read(&self, address: usize, buf: &mut [u8]) -> MemoryResult<usize> {
        let remote = [RemoteIoVec {
            base: address,
            len: std::mem::size_of_val(buf),
        }];
        let local = [IoVec::from_mut_slice(buf)];
        match uio::process_vm_readv(Pid::from_raw(self.pid), &local, &remote) {
            Ok(x) if x > 0 => Ok(x),
            Err(e) => Err(MemoryError::ReadError(e.to_string())),
            _ => Err(MemoryError::ReadError("No bytes read".to_owned())),
        }
    }
    fn write(&self, address: usize, payload: &[u8]) -> MemoryResult<usize> {
        let remote = [RemoteIoVec {
            base: address,
            len: std::mem::size_of_val(payload),
        }];
        let local = [IoVec::from_slice(payload)];
        match uio::process_vm_writev(Pid::from_raw(self.pid), &local, &remote) {
            Ok(x) if x > 0 => Ok(x),
            Err(e) => Err(MemoryError::WriteError(e.to_string())),
            _ => Err(MemoryError::WriteError("No bytes written".to_owned())),
        }
    }
}


/// Manipulates the process memory from the outside with the memory mapped mem file
#[cfg(target_os = "linux")]
#[derive(Default, Debug, Copy, Clone, PartialEq, Eq)]
pub struct ProcManipulator {
    pub pid: i32,
}


#[cfg(target_os = "linux")]
impl MemoryManipulation for ProcManipulator {

    #[inline(always)]
    fn new(pid: i32) -> Self {
        Self { pid }
    }

    #[inline(always)]
    fn pid(&self) -> i32 {
        self.pid
    }

    fn read(&self, address: usize, buf: &mut [u8]) -> MemoryResult<usize> {
        let mut mem_file = OpenOptions::new()
            .read(true)
            .open(format!("/proc/{}/mem", self.pid))?;
        mem_file.seek(SeekFrom::Start(address as u64))?;
        mem_file.read_exact(buf)?;
        Ok(buf.len())
    }
    fn write(&self, address: usize, payload: &[u8]) -> MemoryResult<usize> {
        let mut mem_file = OpenOptions::new()
            .write(true)
            .append(false)
            .open(format!("/proc/{}/mem", self.pid))?;
        mem_file.seek(SeekFrom::Start(address as u64))?;
        mem_file.write_all(payload)?;
        Ok(payload.len())
    }
}
