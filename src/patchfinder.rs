use std::convert::TryInto;

#[macro_export]
macro_rules! u32cast {
    ($buf:expr, $var:expr) => ({
        u32::from_le_bytes($buf[$var as usize..($var+4) as usize].try_into().expect("Invalid slice length"))
    });
}

type AddrT = u64;

pub fn bof64(buf: &Vec<u8>, start: AddrT, where_: AddrT) -> AddrT {
    let mut _where = where_;
    for _ in buf[start as usize..where_ as usize].chunks(4).step_by(4) {
        _where -= 4;
        let op: u32 = u32cast!(buf, _where);
        if (op & 0xFFC003FF) == 0x910003FD {
            let delta: u32 = (op >> 10) & 0xFFF;
            //print!("%x: ADD X29, SP, #0x%x\n", where, delta);
            if (delta & 0xF) == 0 {
                let prev: AddrT = _where - (((delta >> 4) + 1) * 4) as u64;
                let mut au: u32 = u32cast!(buf, prev);
                if (au & 0xFFC003E0) == 0xA98003E0 { /* print!("%x: STP x, y, [SP,#-imm]!\n", prev); */ return prev; } 
                // try something else
                while _where > start {
                    _where -= 4;
                    au = u32cast!(buf, _where);
                    // SUB SP, SP, #imm
                    if (au & 0xFFC003FF) == 0xD10003FF && ((au >> 10) & 0xFFF) == delta + 0x10 { return _where; }
                    // STP x, y, [SP,#imm]
                    if (au & 0xFFC003E0) != 0xA90003E0 { _where += 4; break; }
                } //endwhile
            } //endif
        } //endif
    } panic!("Did not find offset"); //endfor
}

pub fn xref64(buf: &Vec<u8>, start: AddrT, end: AddrT, what: AddrT) -> AddrT {
    let mut value: [u64; 32] = [0; 32];
    for i in ((start & !3)..(end & !3)).step_by(4) {
        let op: u32 = u32cast!(buf, i);
        let reg: u32 = op & 0x1F;
        if (op & 0x9F000000) == 0x90000000 {
            let adr: u32 = ((op & 0x60000000) >> 18) | ((op & 0xFFFFE0) << 8);
            //print!("%llx: ADRP X%d, 0x%llx\n", i, reg, ((long long)adr << 1) + (i & ~0xFFF));
            value[reg as usize] = ((adr as u64) << 1) + (i & !0xFFF);
            continue;				// XXX should not XREF on its own?
        /*} else if (op & 0xFFE0FFE0) == 0xAA0003E0 {
            unsigned rd = op & 0x1F;
            unsigned rm = (op >> 16) & 0x1F;
            //print!("%llx: MOV X%d, X%d\n", i, rd, rm);
            value[rd] = value[rm];
        */
        } else if (op & 0xFF000000) == 0x91000000 {
            let rn: u32 = (op >> 5) & 0x1F;
            let shift: u32 = (op >> 22) & 0x3;
            let mut imm: u32 = (op >> 10) & 0xFFF;
            if shift == 1 { imm <<= 12; } else { /* assert(shift == 0); */ if shift > 1 { continue }; } 
            //print!("%llx: ADD X%d, X%d, 0x%x\n", i, reg, rn, imm);
            value[reg as usize] = value[rn as usize] + (imm as u64);
        } else if (op & 0xF9C00000) == 0xF9400000 {
            let rn: u32 = (op >> 5) & 0x1F;
            let imm: u32 = ((op >> 10) & 0xFFF) << 3;
            //print!("%llx: LDR X%d, [X%d, 0x%x]\n", i, reg, rn, imm);
            if imm == 0 { continue };			// XXX not counted as true xref
            value[reg as usize] = value[rn as usize] + (imm as u64);	// XXX address, not actual value
        /*} else if (op & 0xF9C00000) == 0xF9000000 {
            let rn: u32 = (op >> 5) & 0x1F;
            let imm: u32 = ((op >> 10) & 0xFFF) << 3;
            //print!("%llx: STR X%d, [X%d, 0x%x]\n", i, reg, rn, imm);
            if imm == 0 { continue };			// XXX not counted as true xref
            value[rn as usize] = value[rn as usize] + (imm as u64);	// XXX address, not actual value
        */
        } else if (op & 0x9F000000) == 0x10000000 {
            let adr: u32 = ((op & 0x60000000) >> 18) | ((op & 0xFFFFE0) << 8);
            //print!("%llx: ADR X%d, 0x%llx\n", i, reg, ((long long)adr >> 11) + i);
            value[reg as usize] = ((adr as u64) >> 11) + i;
        } else if (op & 0xFF000000) == 0x58000000 {
            let adr: u32 = (op & 0xFFFFE0) >> 3;
            //print!("%llx: LDR X%d, =0x%llx\n", i, reg, adr + i);
            value[reg as usize] = (adr as u64) + i;		// XXX address, not actual value
        } //endif

        if value[reg as usize] == what { return i; }
    } panic!("Did not find offset"); //endfor
}

pub fn make_bl(from: u32, to: u32) -> u32 {
    if from > to { 
        (0x18000000 - (from - to) / 4) as u32
    } else {
        (0x94000000 + (to - from) / 4) as u32
    }
}

pub fn follow_call64(buf: &Vec<u8>, call: AddrT) -> AddrT {
    let mut w: u64;
    w = (u32cast!(buf, call) & 0x3FFFFFF) as u64;
    w <<= 64 - 26;
    w >>= 64 - 26 - 2;
    call + w
}  