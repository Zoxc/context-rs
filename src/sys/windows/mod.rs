// Copyright 2016 coroutine-rs Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std;
use std::io;
use std::mem;
use std::os::raw::c_void;
use std::sync::atomic::{AtomicUsize, ATOMIC_USIZE_INIT, Ordering};
use std::usize;

use kernel32;
use winapi;

use stack::Stack;

fn get_thread_stack_guarantee() -> usize {
    let min_guarantee = if cfg!(target_pointer_width = "32") {
        0x1000
    } else {
        0x2000
    };
    let mut stack_guarantee = 0; 
    // Note that SetThreadStackGuarantee doesn't work w
    unsafe { kernel32::SetThreadStackGuarantee(&mut stack_guarantee) };
    std::cmp::max(stack_guarantee, min_guarantee) as usize + 0x1000
}

pub unsafe fn allocate_stack(size: usize) -> io::Result<Stack> {
    const NULL: winapi::LPVOID = 0 as winapi::LPVOID;
    const PROT: winapi::DWORD = winapi::PAGE_READWRITE;
    const TYPE: winapi::DWORD = winapi::MEM_COMMIT | winapi::MEM_RESERVE;

    let user_stack_size = (size + 0x1000 - 1) / 0x1000 * 0x1000;

    // We need at least one page of stack
    let user_stack_size = std::cmp::max(user_stack_size, 0x1000);

    // Add a guard page and guaranteed stack
    let stack_guarantee = get_thread_stack_guarantee();
    let stack_size = 0x1000 + stack_guarantee + user_stack_size;

    // Allocate some new stack for ourselves
    let stack_low = kernel32::VirtualAlloc(std::ptr::null_mut(), stack_size as winapi::SIZE_T, winapi::MEM_RESERVE, winapi::PAGE_READWRITE) as usize;
    let stack_high = stack_low + stack_size;
    if stack_low == 0 {
        return Err(io::Error::last_os_error());
    }

    // Commit one page of memory for the user
    let committed_user = 0x1000;

    // Commit the user memory and the guaranteed pages
    let committed_total = committed_user + stack_guarantee;

    kernel32::VirtualAlloc((stack_high - committed_total) as _, committed_total as winapi::SIZE_T, winapi::MEM_COMMIT, winapi::PAGE_READWRITE);

    // Guard the guaranteed pages
    let mut old = 0;
    kernel32::VirtualProtect((stack_high - committed_total) as winapi::LPVOID, stack_guarantee as winapi::SIZE_T, winapi::PAGE_READWRITE | winapi::PAGE_GUARD, &mut old);
    
    let ptr = kernel32::VirtualAlloc(NULL, size as winapi::SIZE_T, TYPE, PROT);

    if ptr == NULL {
        Err(io::Error::last_os_error())
    } else {
        Ok(Stack::new(stack_high as *mut c_void, stack_low as *mut c_void, (stack_high - committed_user) as *mut c_void))
    }
}

pub unsafe fn poison_stack(stack: &Stack) {
    let mut old = 0;
    if kernel32::VirtualProtect(stack.bottom(), stack.len() as winapi::SIZE_T, 0, &mut old) == 0 as _ {
        panic!("unable to poison stack");
    }
}

pub unsafe fn protect_stack(stack: &Stack) -> io::Result<Stack> {
    Ok(Stack::new(stack.top(), stack.bottom(), stack.limit()))
}

pub unsafe fn deallocate_stack(ptr: *mut c_void, _: usize) {
    kernel32::VirtualFree(ptr as winapi::LPVOID, 0, winapi::MEM_RELEASE);
}

pub fn page_size() -> usize {
    static PAGE_SIZE: AtomicUsize = ATOMIC_USIZE_INIT;

    let mut ret = PAGE_SIZE.load(Ordering::Relaxed);

    if ret == 0 {
        ret = unsafe {
            let mut info = mem::zeroed();
            kernel32::GetSystemInfo(&mut info);
            info.dwPageSize as usize
        };

        PAGE_SIZE.store(ret, Ordering::Relaxed);
    }

    ret
}

// Windows does not seem to provide a stack limit API
pub fn min_stack_size() -> usize {
    page_size()
}

// Windows does not seem to provide a stack limit API
pub fn max_stack_size() -> usize {
    usize::MAX
}
