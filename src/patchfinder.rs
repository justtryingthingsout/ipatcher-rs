use std::convert::TryInto;

//make a u32 from bytes, and use it as a usize
#[macro_export]
macro_rules! u32cast {
    ($buf:expr, $var:expr) => ({
        u32::from_le_bytes($buf[$var..($var+4)].try_into().expect("Invalid slice length")) as usize
    });
}

//create a range from the start and size
#[macro_export]
macro_rules! range_size {
    ($start: expr, $size:expr) => {
        $start..$start+$size
    }
}

macro_rules! range {
    ($start: expr, $end: expr, $step: expr) => {
        ($start..$end).step_by($step)
    }
}

pub fn bof64(buf: &[u8], start: usize, mut loc: usize) -> usize {
    while loc >= start {
        loc -= 4;
        let op = u32cast!(buf, loc);
        if op & 0xFFC003FF == 0x910003FD {
            let delta = (op >> 10) & 0xFFF;
            //println!("%x: ADD X29, SP, #0x%x\n", where, delta);
            if (delta & 0xF) == 0 {
                let prev = loc - (((delta >> 4) + 1) * 4) as usize;
                let mut au = u32cast!(buf, prev);
                if au & 0xFFC003E0 == 0xA98003E0 { 
                    /* print!("%x: STP x, y, [SP,#-imm]!\n", prev); */ 
                    return prev
                } 
                // try something else
                while loc > start {
                    loc -= 4;
                    au = u32cast!(buf, loc);
                    // SUB SP, SP, #imm
                    if (au & 0xFFC003FF) == 0xD10003FF && ((au >> 10) & 0xFFF) == delta + 0x10 { 
                        return loc
                    }
                    // STP x, y, [SP,#imm]
                    else if (au & 0xFFC003E0) != 0xA90003E0 { 
                        loc += 4;
                        break
                    }
                } //end while
            } //endif
        } //endif
    } panic!("Did not find offset"); //endfor
}

pub fn xref64(buf: &[u8], start: usize, end: usize, what: usize) -> usize {
    let mut value: [usize; 32] = [0; 32];
    for i in range!(start & !3, end & !3, 4) {
        let op = u32cast!(buf, i);
        let reg = op & 0x1F;
        if op & 0x9F000000 == 0x90000000 {
            let adr = ((op & 0x60000000) >> 18) | ((op & 0xFFFFE0) << 8);
            //print!("%llx: ADRP X%d, 0x%llx\n", i, reg, ((long long)adr << 1) + (i & ~0xFFF));
            value[reg] = (adr << 1) + (i & !0xFFF);
            continue;				// XXX should not XREF on its own?
        /*} else if op & 0xFFE0FFE0 == 0xAA0003E0 {
            let rd: usize = op & 0x1F;
            let rm: usize = (op >> 16) & 0x1F;
            //println!("%llx: MOV X%d, X%d", i, rd, rm);
            value[rd] = value[rm];
        */
        } else if op & 0xFF000000 == 0x91000000 {
            let rn = (op >> 5) & 0x1F;
            let shift = (op >> 22) & 0x3;
            let mut imm = (op >> 10) & 0xFFF;
            if shift == 1 { 
                imm <<= 12; 
            } else {
                //assert_eq!(shift, 0); 
                if shift > 1 { continue } 
            }
            //println!("%llx: ADD X%d, X%d, 0x%x", i, reg, rn, imm);
            value[reg] = value[rn] + imm;
        } else if op & 0xF9C00000 == 0xF9400000 {
            let rn = (op >> 5) & 0x1F;
            let imm = ((op >> 10) & 0xFFF) << 3;
            //println!("%llx: LDR X%d, [X%d, 0x%x]", i, reg, rn, imm);
            if imm == 0 { continue }			// XXX not counted as true xref
            value[reg] = value[rn] + imm;	// XXX address, not actual value
        /*} else if (op & 0xF9C00000) == 0xF9000000 {
            let rn: usize = (op >> 5) & 0x1F;
            let imm: usize = ((op >> 10) & 0xFFF) << 3;
            //println!("%llx: STR X%d, [X%d, 0x%x]", i, reg, rn, imm);
            if imm == 0 { continue };			// XXX not counted as true xref
            value[rn as usize] = value[rn as usize] + (imm as u64);	// XXX address, not actual value
        */
        } else if op & 0x9F000000 == 0x10000000 {
            let adr = ((op & 0x60000000) >> 18) | ((op & 0xFFFFE0) << 8);
            //println!("%llx: ADR X%d, 0x%llx", i, reg, ((long long)adr >> 11) + i);
            value[reg] = (adr >> 11) + i;
        } else if op & 0xFF000000 == 0x58000000 {
            let adr = (op & 0xFFFFE0) >> 3;
            //println!("%llx: LDR X%d, =0x%llx", i, reg, adr + i);
            value[reg] = adr + i;		// XXX address, not actual value
        } //endif

        if value[reg] == what { return i }
    } //end for
    panic!("Did not find offset")
}

pub fn make_bl(from: usize, to: usize) -> [u8; 8] {
    if from > to {
        0x18000000 - (from - to) / 4
    } else {
        0x94000000 + (to - from) / 4
    }.to_le_bytes()
}

pub fn follow_call64(buf: &[u8], call: usize) -> usize {
    let mut w = u32cast!(buf, call) & 0x3FFFFFF;
    w <<= 64 - 26;
    w >>= 64 - 26 - 2;
    call + w
}  