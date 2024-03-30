use windows::Win32::{
    Foundation::{HANDLE, GetLastError},
    System::{
        Diagnostics::{
            Debug::{ReadProcessMemory, WriteProcessMemory, IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER, IMAGE_OPTIONAL_HEADER64},
            ToolHelp::{CREATE_TOOLHELP_SNAPSHOT_FLAGS, CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, MODULEENTRY32W},
        },
        Memory::{self, MEMORY_BASIC_INFORMATION, VirtualQueryEx},
        ProcessStatus::EnumProcesses,
        Threading::{OpenProcess, PROCESS_ACCESS_RIGHTS, PROCESS_NAME_FORMAT, QueryFullProcessImageNameW},
        SystemServices::{IMAGE_DOS_HEADER},
    },
};
use windows::core::PWSTR;
use core::ffi::c_void;
use std::path::PathBuf;
use capstone::prelude::*;

// Should I do a proper "vim" esc editor for memory? 
// say I want to look at location N, and then start to overwrite the ASM with this tool

// We need to implement the following functions:
// memory_readable (check if a page is protected, etc etc)
// writememory ofc
// Some sort of undo ?

fn pop_suffix<T: AsRef<[u16]>>(input: T) -> Vec<u16> {
    let mut buffer = Vec::from(input.as_ref());
    while let Some(&0) = buffer.last() {
        buffer.pop();
    }
    buffer
}

trait FromBytes {
    fn from_bytes(bytes: &[u8]) -> Self;
}

impl<T: Sized + Copy> FromBytes for T {
    fn from_bytes(bytes: &[u8]) -> Self {
        assert!(bytes.len() >= std::mem::size_of::<T>());
        unsafe {
           *(bytes.as_ptr() as *const T)
        }   
    }
}


trait WinUtils {
    fn as_mut_cvoid(&mut self) -> *mut c_void;
    fn as_const_cvoid(&self) -> *const c_void;
    fn size_of_contents(&self) -> usize;
}

impl<T> WinUtils for Vec<T> {
    fn as_mut_cvoid(&mut self) -> *mut c_void {
        self.as_mut_ptr() as *mut c_void
    }
    fn as_const_cvoid(&self) -> *const c_void { 
        self.as_ptr() as *const c_void
    }
    fn size_of_contents(&self) -> usize {
        self.len() * std::mem::size_of::<T>()
    }
}


#[derive(Default, Debug)]
struct WindowsProcess { 
    handle: HANDLE,
    process_name: String,
    file_path: PathBuf,
    pid: u32,
}

impl WindowsProcess {
    fn new(handle: HANDLE, file_path: PathBuf, pid: u32) -> Self {
        let process_name = match file_path.file_name().and_then(|path| path.to_str()) {
            Some(path_string) => String::from(path_string),
            None => String::from("DefaultProcess"),
        };

        WindowsProcess { 
            handle,
            process_name,
            file_path,
            pid,
        }
    }
}

// Enumerate every windows process.
fn enumerate_processes() -> Result<Vec<u32>, windows::core::Error> {
    let mut pids = vec![0u32; 1024];
    let mut bytes_returned = 0u32;
    const SIZE_OF_U32: usize = std::mem::size_of::<u32>();
    unsafe {
        EnumProcesses(
            pids.as_mut_ptr(),
            (pids.len() * SIZE_OF_U32) as u32,
            &mut bytes_returned,
        )?;
    }
    // Let's empty out the pids.
    pids.resize(bytes_returned as usize / SIZE_OF_U32, 0);
    Ok(pids)
}
// Turn an ID to a handle.
fn get_handle(pid: u32) -> Result<HANDLE, windows::core::Error> {
    let desired_access = PROCESS_ACCESS_RIGHTS(0xFFFF); //0x0010 | 0x0020 | 0x0008 | 0x0400 <- Correct flags, at the moment, we are using debug flags.
    let mut handle = HANDLE::default();
    unsafe {
        handle = OpenProcess(
            desired_access,
            false,
            pid
        )?;
    }
    Ok(handle)
}

// Turn a handle to a process name.
fn get_process_name(handle: &HANDLE) -> Result<PathBuf, windows::core::Error> {
    let mut return_buffer: Vec<u16> = vec![0; 1024];
    let buffer_ptr = PWSTR::from_raw(return_buffer.as_mut_ptr());
    let flags = PROCESS_NAME_FORMAT(0);
    let mut buffer_size = return_buffer.len() as u32;
    unsafe {
        QueryFullProcessImageNameW(
            *handle,
            flags,
            buffer_ptr,
            &mut buffer_size
        )?;
    }
    // Cleaning up the buffer.
    return_buffer = pop_suffix(return_buffer);
    Ok(PathBuf::from(String::from_utf16_lossy(&return_buffer)))
}

// Create a handle to a snapshot of the process memory
fn create_snapshot(pid: u32) -> Result<HANDLE, windows::core::Error> {
    let flags = CREATE_TOOLHELP_SNAPSHOT_FLAGS(0x00000008);
    let mut snapshot_handle = HANDLE::default();
    unsafe {
        snapshot_handle = CreateToolhelp32Snapshot(
            flags,
            pid,
        )?;
    }
    Ok(snapshot_handle)
}

// Fetch the first or next module from a process using a snapshot handle.
fn get_module(snapshot_handle: &HANDLE, first: bool) -> Result<MODULEENTRY32W, windows::core::Error> { 
    let module_call = match first {  
        true  => Module32FirstW,
        false => Module32NextW,
    };
    
    let mut module_entry = MODULEENTRY32W::default();
    module_entry.dwSize = std::mem::size_of::<MODULEENTRY32W>() as u32;
    
    unsafe {
        module_call(*snapshot_handle, &mut module_entry)?;
    }

    Ok(module_entry)
} 

// Find the first memory location of a program.
fn get_base_address(pid: u32, target_module: &str) -> Result<u64, windows::core::Error> {
    let mut base_address = 0 as *mut u8;
    let snapshot_handle = create_snapshot(pid)?;
    //let first_module_entry = get_module(&snapshot_handle, true).unwrap();
    loop { 
        let next_module = get_module(&snapshot_handle, false)?;
        if String::from_utf16_lossy(&pop_suffix(&next_module.szModule)) == target_module { 
            base_address = next_module.modBaseAddr;
            break;
        }
    }
    Ok(base_address as u64)
}

// Check whether or not a memory location can be modified.
fn check_memory_status(handle: HANDLE, address: u64, ) -> Result<(MEMORY_BASIC_INFORMATION, bool), windows::core::Error> {
    let mut memory_info: MEMORY_BASIC_INFORMATION = MEMORY_BASIC_INFORMATION::default();
    unsafe {
        if VirtualQueryEx(
            handle,
            Some(address as *const c_void),
            &mut memory_info as *mut _,
            std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
        ) == 0 {
            return Err(GetLastError().into());
        }
    }
    let can_overwrite = match memory_info.AllocationProtect {
        Memory::PAGE_EXECUTE => false,
        Memory::PAGE_EXECUTE_READ => false,
        Memory::PAGE_EXECUTE_READWRITE => true,
        Memory::PAGE_EXECUTE_WRITECOPY => true,
        Memory::PAGE_NOACCESS => false,
        Memory::PAGE_READONLY => false,
        Memory::PAGE_READWRITE => true,
        Memory::PAGE_WRITECOPY => true,
        Memory::PAGE_TARGETS_INVALID => false,
        Memory::PAGE_TARGETS_NO_UPDATE => false,
        _ => false,
    };
    Ok((memory_info, can_overwrite))
}
// Read a process' memory location. Reads the asked amount and returns a vector of u8, u64 or any otherwise defined structure.
fn read_process_memory<T: Copy + Default>(handle: &HANDLE, address: u64, amount_to_read: usize) -> Result<Vec<T>, windows::core::Error> {
    // Let's firstly prepare the types.
    let base_address = address as *const c_void;
    let mut buffer = vec![T::default(); amount_to_read / std::mem::size_of::<T>()]; 
    let buffer_ptr = buffer.as_mut_cvoid();
    let mut bytes_read: usize = 0;

    unsafe {
        ReadProcessMemory(
            *handle,
            base_address,
            buffer_ptr,
            amount_to_read,
            Some(&mut bytes_read as *mut usize),
        )?;
    }
    Ok(buffer)
}

// Writes to memory. Requires the read_process_memory, as the write is verified with a read.
fn write_process_memory<T: Copy + Default + std::cmp::PartialEq>(handle: &HANDLE, address: u64, content: Vec<T>) -> Result<bool, windows::core::Error> {
    // Define variables
    let base_address = address as *const c_void;
    let buffer_ptr = content.as_const_cvoid();
    let buffer_size = content.size_of_contents();
    let mut bytes_read: usize = 0;
    // Overwrite the memory
    unsafe { 
        WriteProcessMemory(
            *handle,
            base_address,
            buffer_ptr,
            buffer_size,
            Some(&mut bytes_read as *mut usize),
        )?;
    }
    // Verify results
    if content == read_process_memory::<T>(&handle, address, buffer_size)? {
        return Ok(true);
    }
    Ok(false)
}

fn get_image_dos_header(handle: &HANDLE, base_address: u64) -> Result<IMAGE_DOS_HEADER, windows::core::Error> {  
    let raw_data = read_process_memory::<u8>(handle, base_address, std::mem::size_of::<IMAGE_DOS_HEADER>())?;
    Ok(IMAGE_DOS_HEADER::from_bytes(&raw_data))
}

fn get_image_nt_header(handle: &HANDLE, base_address: u64, dos_header: &IMAGE_DOS_HEADER) -> Result<IMAGE_NT_HEADERS64, windows::core::Error> {
    let raw_data = read_process_memory::<u8>(handle, 
        base_address + dos_header.e_lfanew as u64, 
        std::mem::size_of::<IMAGE_NT_HEADERS64>()
    )?;
    Ok(IMAGE_NT_HEADERS64::from_bytes(&raw_data))
}

fn get_section_header(handle: &HANDLE, offset: u64) -> Result<IMAGE_SECTION_HEADER, windows::core::Error> {  
    let raw_data = read_process_memory::<u8>(handle, offset, std::mem::size_of::<IMAGE_SECTION_HEADER>())?;
    Ok(IMAGE_SECTION_HEADER::from_bytes(&raw_data))
}

// Returns the start of .text and the size of the section.
fn get_section(handle: &HANDLE, base_address: u64, search_term: &str) -> Result<Option<(u64, u64)>, windows::core::Error> { 
    let dos_header  = get_image_dos_header(handle, base_address)?;
    let nt_header   = get_image_nt_header(handle, base_address, &dos_header)?;
    let mut section_name = [0u8; 8];
    section_name[..search_term.len()].copy_from_slice(search_term.as_bytes());
    let mut current_offset = base_address + dos_header.e_lfanew as u64 + std::mem::size_of::<IMAGE_NT_HEADERS64>() as u64;
    let mut section_size = 0;
    let mut section_location = 0 ;
    let mut section_count = (0..nt_header.FileHeader.NumberOfSections).peekable();

    while let Some(_) = section_count.next() {
        let text_header = get_section_header(handle, current_offset)?;
        section_location = base_address + text_header.VirtualAddress as u64;
        section_size = unsafe { text_header.Misc.VirtualSize as u64}; 
        if text_header.Name == section_name {  
            break; 
        }   
        current_offset += std::mem::size_of::<IMAGE_SECTION_HEADER>() as u64;
        if section_count.peek().is_none() { 
            return Ok(None) 
        } 
    }
    Ok(
        Some(
            (
            section_location, 
            section_size
            )
        )
    )
}

// copy pasta, rewrite.
fn hex_to_asm(bytes: &[u8]) { // -> Option<String> { 
    let cs = Capstone::new()
        .x86()
        .mode(arch::x86::ArchMode::Mode64)
        .syntax(arch::x86::ArchSyntax::Att)
        .detail(true)
        .build()
        .expect("Failed to create Capstone object");

    let insns = cs.disasm_all(bytes, 0x00)
        .expect("Failed to disassemble bytes");

    for i in insns.as_ref() {
        println!("{} :: {}", i, i.len());
    }
}

fn main() {
    let process_list = enumerate_processes().unwrap();
    let mut formatted_list: Vec<WindowsProcess> = Vec::new();
    for pid in process_list {
        let handle = match get_handle(pid) { 
            Ok(t) => t,
            Err(_) => continue, 
        };
        let name = match get_process_name(&handle){
            Ok(name) => name,
            Err(_) => continue,
        };
        let _process = WindowsProcess::new(handle, name, pid);
        formatted_list.push(_process);
    }
    
    println!("Process count: {}", formatted_list.len());
    let current_process = &formatted_list[&formatted_list.len() - 1];
    // Print process information
    println!("Selected process: {}, pid: {}", &current_process.process_name, &current_process.pid);

    // Fetch the base address.
    let base_address = get_base_address(current_process.pid, &current_process.process_name).unwrap();
    // Let's fetch the .text section's start:
    // Wrap dos_header and nt_header to be inside of first_section_header
    let text_section_info = get_section(&current_process.handle, base_address, ".text").unwrap().unwrap();
    let entire_asm = read_process_memory::<u8>(&current_process.handle, text_section_info.0, text_section_info.1 as usize).unwrap();
    hex_to_asm(&entire_asm);
}
