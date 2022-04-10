# Injex

- aims to provide a library in rust to alter other processes
- at the moment only linux is supported, if i enter a state where i am satisfied with the linux implementation i will look at OpenBSD/Mac/Windows
- freezes the process by sending signal or CGroups
- edits the memory of target process by procfs or `process_vm_readv/write` syscall

## Example

```rust
use injex::prelude::*;
use std::path::PathBuf;
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    let pids = find_process_by_name("target").unwrap()[0]; 
    // Freezer: SignalFreezer or CGroupFreezer
    // Manipulator: ProcManipulator or ProcessVMManipulator
    inject::<CGroupFreezer, ProcManipulator, PathBuf>(
        pid,"lib.so".into()
    ).unwrap();
    Ok(())
}
```

## CLI

build:
```shell
cargo build --release --example injex
```

Usage:
```
Gives users the possibility to inject into and manipulate processes

USAGE:
    injex <--pid <PID>|--name <NAME>> <LIBRARY_PATH>

ARGS:
    <LIBRARY_PATH>    The library to inject

OPTIONS:
    -h, --help           Print help information
    -n, --name <NAME>    The name of target process
    -p, --pid <PID>      The pid of target process
    -V, --version        Print version information

```
Example:
```shell
injex -p 12345 ./injection.so # inject the injection.so into pid 12345
injex -n a.out ./injection.so # inject the injection.s into the process of which name is 'a.out'
```

## Credit

- This is forked from [injex](https://crates.io/crates/injex)
- my injection function is basically a rewrite of [dlinject](https://github.com/DavidBuchanan314/dlinject) in rust

## LICENSE

- MIT