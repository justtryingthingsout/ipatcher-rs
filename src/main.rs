mod patchfinder;
extern crate memchr;

use std::{fs, str};
use memchr::memmem;
use patchfinder::*;

fn iboot_ver(buf: &Vec<u8>) -> (usize, bool) {
    let iboot_ver = str::from_utf8(&buf[0x280..0x2A0]).unwrap_or_else(|e| panic!("Unable to get UTF-8 string, err: {}", e));
    let iboot_type = &buf[0x200..0x204];

    if !iboot_ver.contains("iBoot") { panic!("Invalid image. Make sure the image is extracted, iPatcher doesn't support IM4P/IMG4"); }
    println!("Found: {}", iboot_ver);
    let dot = iboot_ver.find('.').unwrap(); //find index of dot, e.g. iBoot-2817., in order to get version, should not fail
    (iboot_ver[6..dot].parse::<usize>().unwrap(), iboot_type == b"iBSS" || iboot_type == b"LLB ")
}

fn get_rsa_patch(buf: &mut Vec<u8>, ver: &usize) {
    println!("getting get_rsa_patch()");
    let find: usize = match *ver {
        // iOS 9.x and later
        2817.. => memmem::find(&buf, b"\x08\x69\x88\x72").expect("[-] Failed to find MOVK W8, #0x4348"),

        // iOS 8.x
        2261.. => memmem::find(&buf, b"\x0A\x69\x88\x72").expect("[-] Failed to find MOVK W10, #0x4348"),

        // iOS 7.x
        1940 => memmem::find(&buf, b"\x0B\x69\x88\x72").expect("[-] Failed to find MOVK W11, #0x4348"),

        //anything other version
        _ => panic!("Version not supported")
    };
    let beg_func = bof64(buf, 0, find);
    buf[range_size!(beg_func, 8)].copy_from_slice(b"\x00\x00\x80\xD2\xC0\x03\x5F\xD6");

    println!("[+] Patched RSA signature checks");
}

fn get_debugenabled_patch(buf: &mut Vec<u8>) {
    println!("getting get_debugenabled_patch()");

    let find = memmem::find(&buf, b"debug-enabled").expect("[-] Failed to find debug-enabled string");

    let beg_func = xref64(buf, 0, buf.len(), find) + 0x28;
    buf[range_size!(beg_func, 4)].copy_from_slice(b"\x20\x00\x80\xD2");

    println!("[+] Enabled kernel debug");
}

fn get_bootargs_patch(buf: &mut Vec<u8>, args: &String) {
    println!("getting get_bootargs_patch(\"{}\")", args);

    let find = memmem::find(&buf, b"rd=md0 nand-enable-reformat=1").expect("[-] Failed to find debug-enabled string");
    
    let arg = match args.len() {
        x @ 0..=28 => {
            println!("[*] Boot-args length {} is smaller than required, extending", x);
            args.to_owned() + &" ".repeat(29 - x)
        }, 
        29 => args.to_owned(),
        x @ 30.. => {
            println!("[*] Boot-args length {} is bigger than max length, trimming", x);
            args[..29].to_string()
        },
        val @ _ => panic!("Issue with program, value was {}", val) //should never happen, but Rust needs this wildcard anyways
    };

    buf[range_size!(find, 29)].copy_from_slice(arg.as_bytes());

    println!("[+] Set xnu boot-args to \"{}\"", arg);
}

fn get_secrom_patch(buf: &mut Vec<u8>, ver: usize) {
    if ver == 2817 { panic!("iOS 9 iBoots aren't supported by SecureROM patch") }
    println!("getting get_secrom_patch()");

    /* ARM64 ASM:
     *  BL tramp_init
     *  MOV X1, X0
     *  MOV W0, #7 @ BOOT_TARGET = BOOT_SECUREROM
     *  MOV X2, #0x100000000
     *  MOV X3, #0
     *  BL prepare_and_jump
     */

    //find prepare_and_jump()
    let find1 = memmem::find(&buf, b"jumping into image at").expect("[-] Failed to find prepare_and_jump");

    let beg_func1 = xref64(buf, 0, buf.len(), find1);
    
    let prepare_and_jump;
    let tramp_init;

    match ver {
        1940 => {
            prepare_and_jump = follow_call64(buf, beg_func1 + 0x1c);
            tramp_init       = follow_call64(buf, beg_func1 + 0x08);
        },
        2261 => {
            prepare_and_jump = follow_call64(buf, beg_func1 + 0x28);
            tramp_init       = follow_call64(buf, beg_func1 + 0x10);
        },
        _ => panic!("Version not supported")
    }

    //find go cmd
    let find2 = memmem::find(&buf, b"cebilefctmbrtlhptreprmmh").expect("[-] Failed to find go cmd");

    let beg_func2 = xref64(buf, 0, buf.len(), find2) - match ver {
        1940 => 0x44,
        2261 => 0x30,
        val @ _ => panic!("Issue with program, value was {}", val) //should never occur since the last match should've already panicked
    };
    
    // write the payload

    // BL tramp_init
    buf[range_size!(beg_func2, 4)].copy_from_slice(&make_bl(beg_func2, tramp_init)); 
    
    /* Little Endian bytes of ARM64 ASM:
     *  MOV X1, X0
     *  MOV W0, #0x7
     *  MOV X2, #0x100000000
     *  MOV X3, #0x0
     */
    buf[range_size!(beg_func2+4, 16)].copy_from_slice(b"\xE1\x03\x00\xAA\xE0\x00\x80\x52\x22\x00\xC0\xD2\x03\x00\x80\xD2");
    // BL prepare_and_jump
    buf[range_size!(beg_func2+20, 4)].copy_from_slice(&make_bl(beg_func2 + 0x14, prepare_and_jump)); 
    println!("[+] Applied patch to boot SecureROM");
}

fn usage(argv: &str) {
    println!("iPatcher-rs - tool to patch lower versions of iBoot64 in rust by @plzdonthaxme\n\
             Usage: {} iBoot iBoot.pwn [options]\n\
                    -b set custom boot-args\n\
                    -s patch to boot SecureROM", argv);
    std::process::exit(0);
}

fn main() {
    let argv: Vec<String> = std::env::args().collect();
    let argc = argv.len();
    
    if argc < 3 {
        println!("[!] Not enough arguments");
   	    usage(&argv[0])
    }

    println!("main: Starting...");

    let filein  = &argv[1];
    let fileout = &argv[2];

    let mut filevec: Vec<u8> = fs::read(filein).expect("[-] Failed to open iBoot, err"); //will append error message after err with colon

    let (ibootver, ibss) = iboot_ver(&filevec);

    get_rsa_patch(&mut filevec, &ibootver);

    if !ibss {
        get_debugenabled_patch(&mut filevec);
        let mut i = 1;
        while i < argc {
            match argv[i].as_str() {
                "-b" => {
                    get_bootargs_patch(&mut filevec, &argv[i+1]);
                    i += 1;
                },
                "-s" => get_secrom_patch(&mut filevec, ibootver),
                _ => panic!("Invalid argument: {}", argv[i]) //TODO: find invalid arguments
            }
        }
    }

    println!("[*] Writing out patched file to {}", fileout);
    fs::write(fileout, filevec).expect("[-] Failed to write iBoot to file, err");

    println!("main: Quitting...");
}