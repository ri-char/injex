use crate::error::{InjectionError, InjectionResult};
use crate::manipulator::MemoryManipulation;
use std::{fs::OpenOptions, path::Path};
use std::path::PathBuf;
use object::{Object, ObjectSymbol};
use procfs::ProcResult;

#[cfg(target_os = "linux")]
use {
    dynasm::dynasm,
    dynasmrt::x64::X64Relocation,
    dynasmrt::{DynasmApi, DynasmLabelApi, VecAssembler},
    procfs::process::{MMapPath, MemoryMap, Process as LinuxProcess},
    regex::Regex,
    std::{fs::File, io::prelude::*},
};
use crate::freezer::Freezer;


#[cfg(target_os = "linux")]
fn find_memory_region(regex: &str, process: &LinuxProcess) -> Option<MemoryMap> {
    let re = Regex::new(regex).unwrap();
    let mapped_memory_regions = match process.maps() {
        Ok(m) => m,
        Err(_) => return None,
    };
    mapped_memory_regions.into_iter().find(|x| {
        if let MMapPath::Path(path_buf) = &x.pathname {
            if re.is_match(path_buf.to_str().unwrap()) {
                return true;
            }
        }
        return false;
    })
}

#[cfg(target_os = "linux")]
fn find_elf_symbol_addr(mem_map: &MemoryMap, sym_name: &str) -> Option<u64> {
    let path = match &mem_map.pathname {
        MMapPath::Path(p) => p,
        _ => return None,
    };

    fn read_elf<'a>(path: &PathBuf, buffer: &'a mut Vec<u8>) -> Option<object::File<'a>> {
        std::fs::File::open(path).ok()
            .and_then(|mut f|f.read_to_end(buffer).ok())
            .and_then(move |_|object::File::parse(buffer.as_slice()).ok())
    }
    fn get_elf_symbol_offset(elf: Option<object::File>, sym_name: &str) -> Option<u64> {
        elf.and_then(
            |elf| elf.symbols()
                .find(|x| x.name().map_or_else(|_|false,|name|name == sym_name))
                .map(|x| x.address()))
    }
    let mut buffer:Vec<u8> =Vec::new();
    let main_elf = read_elf(path,&mut buffer);
    let build_id = if let Some(Some(x)) = main_elf.as_ref().and_then(|e| e.build_id().ok()) {
        Some(x.clone())
    } else {
        None
    };
    get_elf_symbol_offset(main_elf, sym_name)
        .or(build_id.and_then(|build_id| {
            // /usr/lib/debug/.build-id/ab/cdef1234.debug
            let mut new_path = PathBuf::from("/usr/lib/debug/.build-id/");
            new_path.push(format!("{}", hex::encode(&build_id[..1])));
            new_path.push(format!("{}.debug", hex::encode(&build_id[1..])));
            let mut buffer:Vec<u8> =Vec::new();
            get_elf_symbol_offset(read_elf(&new_path,&mut buffer), sym_name)
        }))
        .or(
            path.file_name().and_then(|x| x.to_str()).and_then(|name| {
                // /usr/bin/ls.debug
                let name_with_debug = format!("{}.debug", name);
                let mut new_path = path.clone();
                new_path.pop();
                new_path.push(name_with_debug.clone());
                let mut buffer:Vec<u8> =Vec::new();
                if let Some(s)= get_elf_symbol_offset(read_elf(&new_path,&mut buffer), sym_name){
                    Some(s)
                } else {
                    new_path.pop();
                    new_path.push(".debug");
                    new_path.push(name_with_debug.clone());
                    // /usr/bin/.debug/ls.debug
                    let mut buffer:Vec<u8> =Vec::new();
                    if let Some(s) = get_elf_symbol_offset(read_elf(&new_path,&mut buffer), sym_name) {
                        Some(s)
                    } else {
                        new_path.pop();
                        new_path.pop();
                        new_path.push(name_with_debug);
                        let mut new_path2=PathBuf::from("/usr/lib/debug");
                        new_path2.push(new_path);
                        // /usr/lib/debug/usr/bin/ls.debug
                        let mut buffer:Vec<u8> =Vec::new();
                        get_elf_symbol_offset(read_elf(&new_path2,&mut buffer), sym_name)
                    }
                }

            })
        )
        .map(|x|x+mem_map.address.0)
}

/// Find the process list with the given name
pub fn find_process_by_name(name: &str) -> ProcResult<Vec<i32>> {
    Ok(procfs::process::all_processes()?
        .into_iter()
        .filter(|process| process.status().map_or_else(|_|false, |status|status.name==name) )
        .map(|process| process.pid())
        .collect())
}

/// Injects an dynamic library into a process
#[cfg(target_os = "linux")]
pub fn inject<F, T, P>(pid: i32, library: P) -> InjectionResult<()>
    where
        F: Freezer,
        T: MemoryManipulation,
        P: AsRef<Path>,
{
    let library_path = match library.as_ref().to_str() {
        Some(s) => {
            format!("{}\0", s)
        }
        None => {
            return Err(InjectionError::LibraryNotFound(
                "user-defined library".to_owned(),
            ));
        }
    };
    const STACK_BACKUP_SIZE: usize = 8 * 16;
    const STAGE_TWO_SIZE: u32 = 0x8000;

    let process = LinuxProcess::new(pid)?;
    let ld = find_memory_region(r".*/ld-.*\.so", &process).ok_or(InjectionError::LdNotFound)?;
    let dl_open_address = find_elf_symbol_addr(&ld, "_dl_open")
        .ok_or(InjectionError::SymbolNotFound("_dl_open".to_owned()))?;

    // let librt = find_memory_region(r".*/librt-.*\.so", &process)
    //     .ok_or(InjectionError::LibraryNotFound("librt.so".to_owned()))?;
    // let shm_open_address = find_elf_symbol_addr(&librt, "shm_open")
    //     .ok_or(InjectionError::SymbolNotFound("shm_open".to_owned()))?;
    // let shm_unlink_address = find_elf_symbol_addr(&librt, "shm_unlink")
    //     .ok_or(InjectionError::SymbolNotFound("shm_unlink".to_owned()))?;

    let freezer = F::new(pid);
    freezer.freeze()?;
    let shellcode_result= (|| -> InjectionResult<()> {
        let mut syscall_file = File::open(format!("/proc/{}/syscall", pid))?;
        let mut syscall_buffer = String::new();
        syscall_file.read_to_string(&mut syscall_buffer)?;
        syscall_buffer.pop();
        let syscall_buffer: Vec<&str> = syscall_buffer.rsplit(" ").collect();

        let current_rip = usize::from_str_radix(syscall_buffer[0].trim_start_matches("0x"), 16)?;
        let current_rsp = usize::from_str_radix(syscall_buffer[1].trim_start_matches("0x"), 16)?;

        let mut ops: VecAssembler<X64Relocation> = VecAssembler::new(0x00);

        dynasm!(ops
        ; pushf
        ; push rax
        ; push rbx
        ; push rcx
        ; push rdx
        ; push rbp
        ; push rsi
        ; push rdi
        ; push r8
        ; push r9
        ; push r10
        ; push r11
        ; push r12
        ; push r13
        ; push r14
        ; push r15

        // Open shared memory object: stage two
        // funzt nicht gibt ffffffff
        // ; lea rdi, [>shared_object]
        // ; mov rsi, 2
        // ; mov rdx, 0400 // sollte egal sein
        // ; mov rax, QWORD shm_open_address as i64
        // ; call rax
        // ; mov r14, rax

        ; mov rax, 2 // SYS_OPEN
        ; lea rdi, [>shared_object]
        ; xor rsi, rsi // O_RDONLY
        ; xor rdx, rdx // Mode sollte egal sein bei 0_RDONLY
        ; syscall
        ; mov r14, rax // Save the fd

        // mmap it
        ; mov rax, 9 // SYS_MMAP
        ; xor rdi, rdi // addr
        ; mov rsi, STAGE_TWO_SIZE as i32 // len
        ; mov rdx, 0x7 // prot (rwx)
        ; mov r10, 0x2 // flags (MAP_PRIVATE)
        ; mov r8, r14 // fd
        ; xor r9, r9 // off
        ; syscall
        ; mov r15, rax // save mmap addr

        // close the file
        ; mov rax, 3 // SYS_CLOSE
        ; mov rdi, r14 // fd
        ; syscall

        // // Unlink shared memory object
        // ; lea rdi, [>shared_object]
        // ; mov rax, QWORD shm_unlink_address as i64
        // ; call rax

        // Delete the file
        ; mov rax, 87 // SYS_UNLINK
        ; lea rdi, [>shared_object]
        ; syscall

        // Jump to Stage two
        ; jmp r15

        ; shared_object:
        ; .bytes ".stage_two.bin\0".as_bytes()
    );

        let shell_code_buf = ops.finalize()?;

        let manipulator = T::new(pid);
        let mut code_backup = vec![0_u8; shell_code_buf.len()];
        manipulator.read(current_rip, &mut code_backup)?;
        let mut stack_backup = [0_u8; STACK_BACKUP_SIZE];
        manipulator.read(current_rsp - STACK_BACKUP_SIZE, &mut stack_backup)?;

        let mut ops: VecAssembler<X64Relocation> = VecAssembler::new(0x00);

        dynasm!(ops
        ; cld
        ; fxsave [>moar_regs]

        // Open /proc/self/mem
        ; mov rax, 2 // SYS_OPEM
        ; lea rdi, [>proc_self_mem]
        ; mov rsi, 2 // flags (O_RDWR)
        ; xor rdx, rdx
        ; syscall
        ; mov r15, rax // save the fd

        // seek to code
        ; mov rax, 8 // SYS_LSEEK
        ; mov rdi, r15 // fd
        ; mov rsi, QWORD current_rip as i64 // offset
        ; xor rdx, rdx // whence (LEEK_SET)
        ; syscall

        // restore code
        ; mov rax, 1 // SYS_WRITE
        ; mov rdi, r15 // fd
        ; lea rsi, [>old_code] // backup buffer
        ; mov rdx, code_backup.len() as i32 // count
        ; syscall

        // close /proc/self/mem
        ; mov rax, 3 // SYS_CLOSE
        ; mov rdi, r15 // fd
        ; syscall

        // move pushed regs to our new stack
        ; lea rdi, [>new_stack_base - (STACK_BACKUP_SIZE as isize)]
        ; mov rsi, QWORD (current_rsp - STACK_BACKUP_SIZE) as i64
        ; mov rcx, STACK_BACKUP_SIZE as i32
        ; rep movsb

        // restore original stack
        ; mov rdi, QWORD (current_rsp - STACK_BACKUP_SIZE) as i64
        ; lea rsi, [>old_stack]
        ; mov rcx, STACK_BACKUP_SIZE as _
        ; rep movsb

        ; lea rsp, [>new_stack_base - (STACK_BACKUP_SIZE as isize)]

        // call _dl_open
        ; lea rdi, [>lib_path]
        ; mov rsi, 2
        ; xor rcx, rcx
        ; mov rax, QWORD dl_open_address as i64
        ; call rax

        ; fxrstor [>moar_regs]
        ; pop r15
        ; pop r14
        ; pop r13
        ; pop r12
        ; pop r11
        ; pop r10
        ; pop r9
        ; pop r8
        ; pop rdi
        ; pop rsi
        ; pop rbp
        ; pop rdx
        ; pop rcx
        ; pop rdx
        ; pop rax
        ; popf
        ; mov rsp, QWORD current_rsp as i64
        ; jmp QWORD [>old_rip]

        ; old_rip:
        ; .qword current_rip as i64

        ; old_code:
        ; .bytes code_backup.as_slice()

        ; old_stack:
        ; .bytes &stack_backup
        ; .align 16

        ; moar_regs:
        ; .bytes &[0_u8; 512]
        //; .space 512

        ; lib_path:
        ; .bytes library_path.as_bytes()

        ; proc_self_mem:
        ; .bytes "/proc/self/mem\0".as_bytes()

        ; new_stack:
        ; .align 0x8000

        ; new_stack_base:
    );

        let mut injection_buf = ops.finalize()?;

        // let shared_fd = mman::shm_open(
        //     "/stage_two",
        //     OFlag::O_CREAT | OFlag::O_RDWR,
        //     Mode::S_IRWXG | Mode::S_IRWXU | Mode::S_IRWXO,
        // )
        // .unwrap();
        // unistd::ftruncate(shared_fd, injection_buf.len() as i64).unwrap();
        // let shared_data = unsafe {
        //     mman::mmap(
        //         0 as *mut std::ffi::c_void,
        //         injection_buf.len(),
        //         ProtFlags::PROT_WRITE,
        //         MapFlags::MAP_SHARED,
        //         shared_fd,
        //         0,
        //     )
        //     .unwrap()
        // };
        // unsafe {
        //     ptr::copy_nonoverlapping(
        //         injection_buf.as_ptr(),
        //         shared_data as *mut u8,
        //         injection_buf.len(),
        //     );
        //     mman::munmap(shared_data, injection_buf.len()).unwrap();
        //     unistd::close(shared_fd).unwrap();
        // }

        let mut stage_two = OpenOptions::new()
            .write(true)
            .truncate(true)
            .create(true)
            .open(format!("/proc/{pid}/cwd/.stage_two.bin"))?;

        let mut perms = stage_two.metadata()?.permissions();
        perms.set_readonly(false);
        stage_two.set_permissions(perms)?;
        stage_two.write_all(&mut injection_buf)?;

        manipulator.write(current_rip, shell_code_buf.as_slice())?;
        Ok(())
    })();
    freezer.defrost()?;
    shellcode_result
}
