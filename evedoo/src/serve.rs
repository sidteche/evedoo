//! Lightweight local HTTP server for viewing HTML reports in-browser.
//!
//! Uses only `std::net` — no external web framework. Serves a single
//! HTML page on a random high port, opens the default browser, and
//! keeps running until the user presses Ctrl+C.
//!
//! A random token is appended to the URL so that only the browser
//! opened by evedoo can access the report — other local processes
//! cannot guess it.
//!
//! SPDX-License-Identifier: Apache-2.0

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

/// How long a connected client may take to send its request line.
const READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Start a local HTTP server serving `html` on a random port, open the
/// browser, and serve until the process is interrupted (Ctrl+C).
pub fn serve_and_open(html: &str) -> std::io::Result<()> {
    // Bind to 127.0.0.1 on port 0 (OS picks a free port)
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;

    // Only a client that knows the token gets the report.
    let token = new_token();
    let url = format!("http://{}/?t={}", addr, token);

    println!();
    println!("  Serving report at: {}", url);
    println!("  Press Ctrl+C to stop the server.");
    println!();

    if let Err(e) = open_browser(&url) {
        println!("  Could not open a browser ({e}). Open the address above manually.");
    }

    // Ctrl+C ends the process through the default handler; there is nothing
    // to flush or clean up, so no handler is installed.
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => handle_connection(stream, html.as_bytes(), &token),
            Err(e) => {
                eprintln!("  Server error: {}", e);
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
    Ok(())
}

fn handle_connection(mut stream: TcpStream, html: &[u8], token: &str) {
    // A client that connects and sends nothing must not hold the server.
    let _ = stream.set_read_timeout(Some(READ_TIMEOUT));
    let _ = stream.set_write_timeout(Some(READ_TIMEOUT));

    let mut buf = [0u8; 2048];
    let n = stream.read(&mut buf).unwrap_or(0);
    let request = String::from_utf8_lossy(&buf[..n]);

    let response = if request_has_token(&request, token) {
        let mut response = response_head("200 OK", html.len()).into_bytes();
        response.extend_from_slice(html);
        response
    } else {
        let body = b"Forbidden";
        let mut response = response_head("403 Forbidden", body.len()).into_bytes();
        response.extend_from_slice(body);
        response
    };
    let _ = stream.write_all(&response);
    let _ = stream.flush();
}

/// Response status line and headers.
///
/// The report holds a vulnerability inventory: it must not be cached, must
/// not leak its tokenised URL through `Referer` when a CVE link is followed,
/// and may not load anything from the network (it is self-contained: inline
/// styles and scripts only).
fn response_head(status: &str, content_length: usize) -> String {
    format!(
        "HTTP/1.1 {status}\r\n\
         Content-Type: text/html; charset=utf-8\r\n\
         Content-Length: {content_length}\r\n\
         Connection: close\r\n\
         Cache-Control: no-store\r\n\
         Referrer-Policy: no-referrer\r\n\
         X-Content-Type-Options: nosniff\r\n\
         Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'\r\n\
         \r\n"
    )
}

/// Whether the request is exactly `GET /?t=<token>`.
///
/// The request line is parsed: the method must be GET, the path must be `/`,
/// and the query must carry a `t` parameter equal to the token. The token is
/// compared in constant time.
fn request_has_token(request: &str, token: &str) -> bool {
    let mut parts = request.lines().next().unwrap_or("").split(' ');
    let (Some(method), Some(target), Some(version)) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    if method != "GET" || !version.starts_with("HTTP/") || parts.next().is_some() {
        return false;
    }
    let Some((path, query)) = target.split_once('?') else {
        return false;
    };
    if path != "/" {
        return false;
    }
    let mut supplied = query.split('&').filter_map(|pair| pair.strip_prefix("t="));
    match (supplied.next(), supplied.next()) {
        (Some(value), None) => constant_time_eq(value.as_bytes(), token.as_bytes()),
        _ => false,
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// A fresh access token: a version-4 UUID (122 random bits from the OS
/// generator) as 32 hex characters.
fn new_token() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}

/// Open a URL in the default browser, without going through a shell.
fn open_browser(url: &str) -> std::io::Result<()> {
    browser_command(url).spawn().map(|_| ())
}

#[cfg(target_os = "windows")]
fn browser_command(url: &str) -> std::process::Command {
    // Resolved from the system directory, not PATH. The URL is a single
    // argument and is never interpreted by cmd.exe.
    let system_root = std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into());
    let rundll32 = std::path::Path::new(&system_root).join("System32").join("rundll32.exe");
    let mut command = std::process::Command::new(rundll32);
    command.args(["url.dll,FileProtocolHandler", url]);
    command
}

#[cfg(target_os = "macos")]
fn browser_command(url: &str) -> std::process::Command {
    let mut command = std::process::Command::new("/usr/bin/open");
    command.arg(url);
    command
}

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
fn browser_command(url: &str) -> std::process::Command {
    let mut command = std::process::Command::new("xdg-open");
    command.arg(url);
    command
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: &str = "0123456789abcdef0123456789abcdef";

    fn get(target: &str) -> String {
        format!("GET {target} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
    }

    #[test]
    fn the_exact_token_on_the_root_path_is_accepted() {
        assert!(request_has_token(&get(&format!("/?t={TOKEN}")), TOKEN));
    }

    /// The check used to be "the request line contains `t=<token>`", so the
    /// token was accepted as a substring of anything.
    #[test]
    fn anything_other_than_the_exact_token_parameter_is_refused() {
        for target in [
            format!("/?t={TOKEN}0"),            // longer value
            format!("/?xt={TOKEN}"),            // different parameter name
            format!("/?t=0{TOKEN}"),            // prefixed value
            format!("/other?t={TOKEN}"),        // different path
            format!("/?t=wrong&x=t={TOKEN}"),   // token inside another value
            format!("/#t={TOKEN}"),             // not a query
            "/".to_string(),
            "/?t=".to_string(),
        ] {
            assert!(!request_has_token(&get(&target), TOKEN), "{target} must be refused");
        }
        assert!(!request_has_token(&format!("POST /?t={TOKEN} HTTP/1.1\r\n\r\n"), TOKEN), "only GET");
        assert!(!request_has_token("", TOKEN));
    }

    #[test]
    fn responses_forbid_caching_referrers_and_external_loads() {
        let head = response_head("200 OK", 10);
        assert!(head.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(head.ends_with("\r\n\r\n"));
        for header in [
            "Content-Length: 10\r\n",
            "Cache-Control: no-store\r\n",
            "Referrer-Policy: no-referrer\r\n",
            "X-Content-Type-Options: nosniff\r\n",
            "Content-Security-Policy: default-src 'none';",
        ] {
            assert!(head.contains(header), "missing {header:?}");
        }
    }

    #[test]
    fn duplicate_token_parameters_are_refused() {
        assert!(!request_has_token(&get(&format!("/?t={TOKEN}&t={TOKEN}")), TOKEN));
        assert!(request_has_token(&get(&format!("/?x=1&t={TOKEN}")), TOKEN));
    }

    /// End to end over a real socket: the report is returned for the token
    /// and refused without it.
    #[test]
    fn a_real_connection_gets_the_report_only_with_the_token() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            for stream in listener.incoming().take(2) {
                handle_connection(stream.unwrap(), b"<html>REPORT</html>", TOKEN);
            }
        });

        let fetch = |target: &str| {
            let mut stream = TcpStream::connect(addr).unwrap();
            stream.write_all(get(target).as_bytes()).unwrap();
            let mut response = String::new();
            stream.read_to_string(&mut response).unwrap();
            response
        };
        let ok = fetch(&format!("/?t={TOKEN}"));
        assert!(ok.starts_with("HTTP/1.1 200 OK"), "{ok}");
        assert!(ok.ends_with("<html>REPORT</html>"));
        let refused = fetch("/?t=wrong");
        assert!(refused.starts_with("HTTP/1.1 403 Forbidden"), "{refused}");
        assert!(!refused.contains("REPORT"));
        server.join().unwrap();
    }

    #[test]
    fn token_has_122_random_bits_and_is_url_safe() {
        let a = new_token();
        let b = new_token();
        assert_eq!(a.len(), 32);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b);
    }
}
