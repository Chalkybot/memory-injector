use windows::Win32::{
    Foundation::{HANDLE, GetLastError},
    System::{
        Diagnostics::{
            Debug::{ReadProcessMemory, WriteProcessMemory},
            ToolHelp::{CREATE_TOOLHELP_SNAPSHOT_FLAGS, CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, MODULEENTRY32W},
        },
        Memory::{self, MEMORY_BASIC_INFORMATION, VirtualQueryEx},
        ProcessStatus::EnumProcesses,
        Threading::{OpenProcess, PROCESS_ACCESS_RIGHTS, PROCESS_NAME_FORMAT, QueryFullProcessImageNameW},
    },
};
use windows::core::PWSTR;
use core::ffi::c_void;
use std::path::PathBuf;

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

trait WinUtils {
    fn as_mut_cvoid(&mut self) -> *mut c_void;
    fn as_const_cvoid(&self) -> *const c_void;
    fn size_of_contents(&self) -> usize;
     // fn cast_as(&self) -> usize;
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
    let desired_access = PROCESS_ACCESS_RIGHTS(0xFFFF); //0x0010 | 0x0020 | 0x0008 | 0x0400);
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
    /*while let Some(&0) = return_buffer.last() {
        return_buffer.pop();
    }*/
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
fn get_base_address(pid: u32, target_module: &str) -> Result<*mut u8, windows::core::Error> {
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
    Ok(base_address)
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

// Messing around with reading process memory. Attempts to map out memory to utf8. Changing the read_size can yield more readable utf8.
fn dump_process_memory(handle: &HANDLE, base_address: u64, read_size: usize) {
    let mut loop_index = 0;
    loop { 
        match read_process_memory::<u8>(&handle, base_address + loop_index, read_size){ 
            Err(e)          => break,
            Ok(memory_read) => {
                let potential_text =String::from_utf8_lossy(&memory_read).replace('\u{FFFD}', ".");
                let hex: String = memory_read.iter().map(|b| format!("{:02X}", b)).collect();
                let hex_string = format!("0x{}", hex);
                println!("{:#x} -> {:?} => {}", (base_address  as u64) + loop_index, hex_string, potential_text)
            
            },
        }
        loop_index += read_size as u64;
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
    
    /* Using a known good location for testing */
    let some_variable: u32 = 12345;
    let variable_address = &some_variable as *const _ as u64;

    // Verifying if the page can be written to or not.
    let page_status = check_memory_status(current_process.handle, base_address as u64).unwrap();
    if page_status.1 == false { 
        panic!("Page at {:?} marked as {:?}", base_address, page_status.0);
    }
    match write_process_memory(&current_process.handle, variable_address, vec![22222u32]) { 
        Err(e) => println!("Error: {:?}", e),
        Ok(result) => { 
            match result {
                true  => println!("Memory written succesfully."),
                false => println!("Memory written unsuccesfully."),
            }
        }
    }
    dump_process_memory(&current_process.handle, base_address as u64, 16);
       
}
