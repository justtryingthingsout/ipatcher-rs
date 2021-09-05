mod patchfinder;
extern crate memchr;

use std::fs;
use memchr::memmem;
use patchfinder::*;

fn iboot_ver(buf: &Vec<u8>) -> (usize, bool) {
    let iboot_ver = match std::str::from_utf8(&buf[0x280..0x2A0]) {
        Ok(ver) => ver,
        Err(e) => panic!("Unable to get UTF-8 string!\nerr: {}", e),
    };

    let iboot_type = match std::str::from_utf8(&buf[0x200..=0x204]) {
        Ok(ver) => ver,
        Err(e) => panic!("Unable to get UTF-8 string!\nerr: {}", e),
    };

    if iboot_ver.contains("iBoot") {
        println!("inputted: {}", iboot_ver);
        let dot: usize = iboot_ver.find('.').unwrap(); //find index of dot, e.g. iBoot-2817., in order to get version
        let iboot_ver = iboot_ver[6..dot].parse::<usize>().unwrap();
        if iboot_type.contains("iBSS") || iboot_type.contains("LLB ") {
            return (iboot_ver, true);
        } else {
            return (iboot_ver, false);
        }
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
    let beg_func = bof64(buf, 0, find);
    buf[beg_func..(beg_func+8)].copy_from_slice(b"\x00\x00\x80\xD2\xC0\x03\x5F\xD6");

    println!("[+] Patched RSA signature checks");
}

fn get_debugenabled_patch(buf: &mut Vec<u8>) {
    println!("getting get_debugenabled_patch()");

    let find = memmem::find(&buf, b"debug-enabled").unwrap_or_else(|| 
        panic!("[-] Failed to find debug-enabled string")
    );

    let beg_func = xref64(buf, 0, buf.len(), find) + 0x28;
    buf[beg_func..(beg_func+4)].copy_from_slice(b"\x20\x00\x80\xD2");

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

fn get_secrom_patch(buf: &mut Vec<u8>, ver: &usize) {
    if ver == &2817 { panic!("iOS 9 iBoots aren't supported by SecureROM patch"); }
    println!("getting get_secrom_patch()");

    /* ARM64 ASM:
        BL tramp_init
        MOV X1, X0
        MOV W0, #7 @ BOOT_TARGET = BOOT_SECUREROM
        MOV X2, #0x100000000
        MOV X3, #0
        BL prepare_and_jump
    */

    let prepare_and_jump;
    let tramp_init;

    //find prepare_and_jump()
    let find1 = memmem::find(&buf, b"jumping into image at").unwrap_or_else(|| 
        panic!("[-] Failed to find prepare_and_jump")
    );

    let beg_func1 = xref64(buf, 0, buf.len(), find1);
    
    if ver == &1940 {
        prepare_and_jump = follow_call64(buf, beg_func1 + 0x1c);
        tramp_init = follow_call64(buf, beg_func1 + 0x8);
    } else if ver == &2261 {
        prepare_and_jump = follow_call64(buf, beg_func1 + 0x28);
        tramp_init = follow_call64(buf, beg_func1 + 0x10);
    } else {
        panic!("Version not supported")
    }

    //find go cmd
    let find2 = memmem::find(&buf, b"cebilefctmbrtlhptreprmmh").unwrap_or_else(|| 
        panic!("[-] Failed to find go cmd")
    );

    let beg_func2: usize;

    if ver == &1940 {
        beg_func2 = xref64(buf, 0, buf.len(), find2) - 0x44;
    } else if ver == &2261 {
        beg_func2 = xref64(buf, 0, buf.len(), find2) - 0x30; 
    } else {
        panic!("Version not supported")
    }
    
    // write the payload
    buf[beg_func2..(beg_func2+4)].copy_from_slice(&make_bl(beg_func2, tramp_init).to_le_bytes()); // BL tramp_init
    /* Little Endian bytes of ARM64 ASM:
        MOV X1, X0
        MOV W0, #7
        MOV X2, #100000000
        MOV X3, #0
    */
    buf[(beg_func2+4)..(beg_func2+20)].copy_from_slice(b"\xE1\x03\x00\xAA\xE0\x00\x80\x52\x22\x00\xC0\xD2\x03\x00\x80\xD2");
    buf[(beg_func2+20)..(beg_func2+24)].copy_from_slice(&make_bl(beg_func2 + 0x14, prepare_and_jump).to_le_bytes()); // BL prepare_and_jump
    println!("[+] Applied patch to boot SecureROM");
}

fn usage(argv: &str) {
    println!("iPatcher-rs - tool to patch lower versions of iBoot64 in rust by @plzdonthaxme");
    println!("Usage: {} iBoot iBoot.pwn [options]", argv);
    println!("       -b set custom boot-args");
    println!("       -s patch to boot SecureROM");
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

    let filein = &argv[1];
    let fileout = &argv[2];

    let mut filevec: Vec<u8> = fs::read(filein).expect("[-] Failed to open iBoot, err"); //will append error message after err with colon

    let (ibootver, ibss) = iboot_ver(&filevec);

    get_rsa_patch(&mut filevec, &ibootver);

    if !ibss {
        get_debugenabled_patch(&mut filevec);
        for i in 0..(argv.len()-1) {
            match &argv[i][..] {
                "-b" => get_bootargs_patch(&mut filevec, &argv[i+1]),
                "-s" => get_secrom_patch(&mut filevec, &ibootver),
                _ => (), //TODO: find invalid arguments
            } //end match
        } //endfor
    } //endif

    println!("[*] Writing out patched file to {}", fileout);
    fs::write(fileout, filevec).expect("[-] Failed to write iBoot to file, err");

    println!("main: Quitting...");
}