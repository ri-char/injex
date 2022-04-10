use std::fs;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use nix::sys::signal;
use nix::unistd::Pid;
use crate::error::{FreezerError, FreezerResult};

pub trait Freezer {
    fn new(pid:i32)->Self;
    fn freeze(&self) -> FreezerResult<()>;
    fn defrost(&self) -> FreezerResult<()>;
}

pub struct CGroupFreezer{
    pid:i32,
}

impl Freezer for CGroupFreezer {
    fn new(pid: i32) -> Self {
        Self {pid}
    }

    fn freeze(&self) -> FreezerResult<()> {
        // Create cgroup
        std::fs::create_dir(format!("/sys/fs/cgroup/injex_{}",self.pid))?;
        // Put the pid into the cgroup
        OpenOptions::new()
            .write(true)
            .open(format!("/sys/fs/cgroup/injex_{}/cgroup.procs",self.pid))?
            .write_all(format!("{}\n",self.pid).as_bytes())?;
        // Freeze the cgroup
        OpenOptions::new()
            .write(true)
            .open(format!("/sys/fs/cgroup/injex_{}/cgroup.freeze",self.pid))?
            .write_all("1".as_bytes())?;
        // Loop to check if the cgroup is frozen
        let event_file=format!("/sys/fs/cgroup/injex_{}/cgroup.events",self.pid);
        let mut read_buf=String::new();
        loop {
            File::open(event_file.as_str())?.read_to_string(&mut read_buf)?;
            if let Some(c)=read_buf.split('\n').into_iter()
                .find(|s|s.starts_with("frozen "))
                .map(|s|s.as_bytes())
                .map(|s|s[s.len()-1]=='1' as u8){
                if c {
                    break;
                }
            } else {
                return Err(FreezerError::OtherError("Unknow cgroup.events format".to_string()));
            }
        }

        Ok(())
    }

    fn defrost(&self) -> FreezerResult<()> {
        // Move back the pid to default cgroup
        OpenOptions::new()
            .write(true)
            .open("/sys/fs/cgroup/cgroup.procs")?
            .write_all(format!("{}\n",self.pid).as_bytes())?;
        // Remove the cgroup
        fs::remove_dir(format!("/sys/fs/cgroup/injex_{}",self.pid))?;

        Ok(())
    }
}

pub struct SignalFreezer{
    pid: i32,
}

impl Freezer for SignalFreezer {
    fn new(pid: i32) -> Self {
        Self {pid}
    }

    fn freeze(&self) -> FreezerResult<()> {
        signal::kill(Pid::from_raw(self.pid), nix::sys::signal::Signal::SIGSTOP)?;
        // wait for process to stop
        let state= procfs::process::Process::new(self.pid)?.status()?.state;
        while state != "T (stopped)" && state != "t (tracing stop)" {}
        Ok(())
    }

    fn defrost(&self) -> FreezerResult<()> {
        signal::kill(Pid::from_raw(self.pid), nix::sys::signal::Signal::SIGCONT)?;
        Ok(())
    }
}
