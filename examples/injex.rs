use std::path::PathBuf;
use injex::prelude::*;

use clap::{ArgGroup, Parser};

/// A tool to inject dynamic library into a process
#[derive(Parser)]
#[clap(version, about, long_about = None)]
#[clap(group(
    ArgGroup::new("target")
    .required(true)
    .args(& ["pid", "name"]),
))]
struct Args {
    /// The pid of target process
    #[clap(short, long)]
    pid: Option<i32>,

    ///The name of target process
    #[clap(short, long)]
    name: Option<String>,

    /// The library to inject
    library_path: String,
}


fn main() {
    let args:Args = Args::parse();

    let pid=if let Some(name) = args.name{
        let pids = find_process_by_name(name.as_str()).unwrap();
        if pids.len() < 1 {
            eprintln!("Cannot find the process called {}.",name);
            return;
        } else if pids.len() > 2 {
            eprintln!("There are many process matched {:?}",pids);
            return;
        } else {
            println!("[{}] {}",pids[0],name);
            pids[0]
        }
    } else {
        args.pid.unwrap()
    };

    inject::<CGroupFreezer, ProcManipulator, PathBuf>(
        pid,
        args.library_path.into()
    ).unwrap();
}
