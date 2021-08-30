mod patchfinder;

extern crate libc;
extern crate memchr;

use std::fs;
use memchr::memmem;
use patchfinder::xref64;
use patchfinder::bof64;

fn iboot_ver(buf: &Vec<u8>) -> usize {
    let iboot_ver = match std::str::from_utf8(&buf[0x280..0x2A0]) {
        Ok(ver) => ver,
        Err(e) => panic!("Unable to get UTF-8 string!\nerr: {}", e),
    };

    if iboot_ver.contains("iBoot") {
        print!("inputted: {}\n", iboot_ver);
        let dot: usize = iboot_ver.find('.').unwrap(); //find index of dot, e.g. iBoot-2817., in order to get version
        let iboot_ver = iboot_ver[6..dot].parse::<usize>().unwrap();
        return iboot_ver;
    } else {
        panic!("Invalid image. Make sure image is extracted, iPatcher doesn't support IM4P/IMG4");
    }
}

fn get_rsa_patch(buf: &mut Vec<u8>, ver: &usize) {
	println!("getting get_rsa_patch()");
    let find: usize =
        // iOS 9.x and later
        if ver >= &2817 {
            memmem::find(&buf, b"\x08\x69\x88\x72").unwrap_or_else(|| 
                panic!("[-] Failed to find MOVK W8, #0x4348")
            )
        }

        // iOS 8.x
        else if ver >= &2261 {
            memmem::find(&buf, b"\x0A\x69\x88\x72").unwrap_or_else(|| 
                panic!("[-] Failed to find MOVK W10, #0x4348")
            )
        }

        // iOS 7.x
        else if ver == &1940 {
            memmem::find(&buf, b"\x0B\x69\x88\x72").unwrap_or_else(|| 
                panic!("[-] Failed to find MOVK W11, #0x4348")
            )
        }

        //anything other version
        else {
            panic!("Version not supported");
        };
    let beg_func: usize = bof64(buf, 0, find as u64) as usize;
    buf[beg_func..=(beg_func+7)].copy_from_slice(b"\x00\x00\x80\xD2\xC0\x03\x5F\xD6");

    println!("[+] Patched RSA signature checks");
}

fn get_debugenabled_patch(buf: &mut Vec<u8>) {
	println!("getting get_debugenabled_patch()");
    let find = memmem::find(&buf, b"debug-enabled").unwrap_or_else(|| 
        panic!("[-] Failed to find debug-enabled string")
    );

    let beg_func: usize = (xref64(buf, 0, buf.len() as u64, find as u64) + 0x28) as usize;
    buf[beg_func..=(beg_func+3)].copy_from_slice(b"\x20\x00\x80\xD2");

    println!("[+] Enabled kernel debug");
}

fn get_bootargs_patch(buf: &mut Vec<u8>, args: &String) {
	println!("getting get_bootargs_patch(\"{}\")", *args);

    let find = memmem::find(&buf, b"rd=md0 nand-enable-reformat=1").unwrap_or_else(|| 
        panic!("[-] Failed to find debug-enabled string")
    );
    
    let arg = if args.len() < 29 {
        println!("[*] Boot-args length {} is smaller than required, extending", args.len());
        let needed = 29 - args.len();
        args.to_owned() + &" ".repeat(needed)  
    } else if args.len() > 29 {
        println!("[*] Boot-args length {} is bigger than max length, trimming", args.len());
        args[..29].to_string()
    } else {
        args.to_owned()
    };

    assert_eq!(arg.len(), 29);
    buf[find..(find+29)].copy_from_slice(arg.as_bytes());

    println!("[+] Set xnu boot-args to \"{}\"", arg);
}

fn main() {
    let argv: Vec<String> = std::env::args().collect();
    let argc: usize = argv.len();
    if argc < 3 {
   	    println!("iPatcher-rs - tool to patch lower versions of iBoot64 in rust by @plzdonthaxme");
        println!("Usage: {} iBoot iBoot.pwn [-b]", &argv[0]);
        println!("       -b set custom boot-args");
        std::process::exit(0);
    }

    println!("main: Starting...");

    let filein = &argv[1];
	let fileout = &argv[2];

    let mut filevec: Vec<u8> = fs::read(filein).expect("[-] Failed to open iBoot, err"); //will append error message after err with colon

    let ibootver = iboot_ver(&filevec);

    get_rsa_patch(&mut filevec, &ibootver);
    get_debugenabled_patch(&mut filevec);

    for i in 0..argv.len() {
        if argv[i] == "-b" {
            get_bootargs_patch(&mut filevec, &argv[i+1]);
        }
    }

    fs::write(fileout, filevec).expect("[-] Failed to write iBoot to file, err");

    println!("[*] Writing out patched file to {}", fileout);
    println!("main: Quitting...");
}