//! Terminal plumbing: virtual-terminal enablement, screen clearing, and
//! reading a single keypress without waiting for Enter.
//!
//! Hand-rolled over the platform APIs rather than pulling in a TUI crate. The
//! menu needs three calls, and the project already reaches for direct FFI at
//! this size (`version.dll` for PE fingerprinting, Toolhelp32 for module
//! enumeration).
//!
//! SPDX-License-Identifier: Apache-2.0

use std::io::{self, Read, Write};

/// Ask the console to interpret ANSI escapes.
///
/// Windows Terminal does this already, but a bare `conhost` — which is what a
/// double-clicked exe still gets — renders the colour codes literally without
/// it. Failure is ignored: a menu in plain monochrome beats no menu.
pub fn enable_virtual_terminal() {
    #[cfg(target_os = "windows")]
    {
        use std::ffi::c_void;

        const STD_OUTPUT_HANDLE: u32 = -11i32 as u32;
        const ENABLE_VIRTUAL_TERMINAL_PROCESSING: u32 = 0x0004;

        #[link(name = "kernel32")]
        extern "system" {
            fn GetStdHandle(n_std_handle: u32) -> *mut c_void;
            fn GetConsoleMode(h_console_handle: *mut c_void, lp_mode: *mut u32) -> i32;
            fn SetConsoleMode(h_console_handle: *mut c_void, dw_mode: u32) -> i32;
        }

        unsafe {
            let handle = GetStdHandle(STD_OUTPUT_HANDLE);
            let mut mode: u32 = 0;
            if GetConsoleMode(handle, &mut mode) != 0 {
                SetConsoleMode(handle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
            }
        }
    }
}

/// Clear the screen and park the cursor at the top-left.
pub fn clear() {
    print!("\x1b[2J\x1b[H");
    let _ = io::stdout().flush();
}

/// Set the window title, so a menu left open in a taskbar is identifiable.
pub fn set_title(title: &str) {
    print!("\x1b]0;{title}\x07");
    let _ = io::stdout().flush();
}

/// Block until one key is pressed and return it, without requiring Enter.
///
/// Returns `None` at end of input — a piped or closed stdin, where blocking
/// forever would hang a script instead of letting the caller exit.
pub fn read_key() -> Option<char> {
    #[cfg(target_os = "windows")]
    {
        #[link(name = "msvcrt")]
        extern "C" {
            fn _getch() -> i32;
            fn _kbhit() -> i32;
        }

        // Console input only. With stdin redirected, `_getch` reads from the
        // console device anyway and would ignore the pipe, so fall through to
        // line-reading when there is no console attached.
        if console_attached() {
            unsafe {
                let c = _getch();
                // 0 or 0xE0 introduces a two-byte extended scancode (arrows,
                // function keys). Consume the second byte so it is not read as
                // a separate selection.
                if c == 0 || c == 0xE0 {
                    let _ = _getch();
                    let _ = _kbhit();
                    return Some('\0');
                }
                if c < 0 {
                    return None;
                }
                return char::from_u32(c as u32);
            }
        }
    }

    read_key_fallback()
}

/// Whether a real console is attached, as opposed to redirected stdin.
#[cfg(target_os = "windows")]
fn console_attached() -> bool {
    use std::ffi::c_void;

    const STD_INPUT_HANDLE: u32 = -10i32 as u32;

    #[link(name = "kernel32")]
    extern "system" {
        fn GetStdHandle(n_std_handle: u32) -> *mut c_void;
        fn GetConsoleMode(h_console_handle: *mut c_void, lp_mode: *mut u32) -> i32;
    }

    unsafe {
        let handle = GetStdHandle(STD_INPUT_HANDLE);
        let mut mode: u32 = 0;
        GetConsoleMode(handle, &mut mode) != 0
    }
}

/// Read one byte from stdin, used when no console is attached and on Unix.
///
/// This is the line-buffered path: it takes the first character of whatever
/// was typed, so Enter is needed. Raw-mode termios would avoid that, but the
/// menu's home is a Windows console and the extra `unsafe` is not worth it for
/// the fallback.
fn read_key_fallback() -> Option<char> {
    let mut byte = [0u8; 1];
    loop {
        match io::stdin().read(&mut byte) {
            Ok(0) => return None,
            Ok(_) => {
                let c = byte[0] as char;
                if c != '\n' && c != '\r' {
                    return Some(c);
                }
            }
            Err(_) => return None,
        }
    }
}

/// Print a message and wait for any key, so command output stays on screen
/// instead of being wiped by the next redraw.
pub fn pause(message: &str) {
    println!();
    print!("{message}");
    let _ = io::stdout().flush();
    let _ = read_key();
    println!();
}

/// Read a line of input for prompts that need more than one key (a file path,
/// a hostname). Returns an empty string at end of input.
pub fn read_line(prompt: &str) -> String {
    print!("{prompt}");
    let _ = io::stdout().flush();
    let mut buf = String::new();
    match io::stdin().read_line(&mut buf) {
        Ok(_) => buf.trim().to_string(),
        Err(_) => String::new(),
    }
}
