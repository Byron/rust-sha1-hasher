//! A minimal implementation of SHA1 for rust.
//!
//! Example:
//!
//! ```rust
//! extern crate "sha1-hasher" as sha1;
//! use std::hash::Writer;
//!
//! # fn main() {
//!
//! let mut m = sha1::Sha1::new();
//! m.write("Hello World!".as_bytes());
//! assert_eq!(&*m.hexdigest(), "2ef7bde608ce5404e97d5f042f95f89f1c232871");
//! # }
//! ```

#![feature(slicing_syntax)]
#![allow(unstable)]

#![experimental]

mod tests;

extern crate serialize;

use std::num::Int;
use std::default::Default;
use std::hash::{self, Hasher, Writer};
use std::slice::bytes::copy_memory;

/// Represents a Sha1 hash object in memory.
pub struct Sha1 {
    state: Sha1State,
    buffer: [u8; CHUNK_SIZE],
    length_bits: u64,
    nx: usize
}

#[derive(Clone)]
struct Sha1State {
    pub h0: u32,
    pub h1: u32,
    pub h2: u32,
    pub h3: u32,
    pub h4: u32,

}

const CHUNK_SIZE: usize = 64;

/// Write a u32 into a vector, which must be 4 bytes long. The value is written in big-endian
/// format.
fn write_u32_be(dst: &mut[u8], input: u32) {
    dst[0] = (input >> 24) as u8;
    dst[1] = (input >> 16) as u8;
    dst[2] = (input >> 8) as u8;
    dst[3] = input as u8;
}

/// Adds the specified number of bytes to the bit count. panic!() if this would cause numeric
/// overflow.
fn add_bytes_to_bits(bits: u64, bytes: u64) -> u64 {
    let (new_high_bits, new_low_bits) = (bytes >> 61, bytes << 3);

    if new_high_bits > Int::zero() {
        panic!("numeric overflow occurred.")
    }

    match bits.checked_add(new_low_bits) {
        Some(x) => return x,
        None => panic!("numeric overflow occurred.")
    }
}

impl Sha1State {
    fn new() -> Sha1State {
        return Sha1State { 
            h0: 0x67452301, 
            h1: 0xefcdab89, 
            h2: 0x98badcfe, 
            h3: 0x10325476,
            h4: 0xc3d2e1f0,
        }
    }

    fn process_block(&mut self, block: &[u8]) {
        const BS: usize = 64;
        const WS: usize = 4;

        const K0: u32 = 0x5A827999;
        const K1: u32 = 0x6ED9EBA1;
        const K2: u32 = 0x8F1BBCDC;
        const K3: u32 = 0xCA62C1D6;

        let mut words = [0u32; 16];

        assert!(block.len() % CHUNK_SIZE == 0);

        for chunk in block.chunks(CHUNK_SIZE) {
            let wp: *mut u32 =  &mut words[0];
            let bp: *const u8 = &chunk[0];

            // process all u8 in block, we use the words as an index (16 with 4 bytes each)
            unsafe {
                for wi in range(0, BS / WS) {
                    // ptr::write(words.offse)
                    let bi = (wi * WS) as isize;
                    *wp.offset(wi as isize) = ( *bp.offset(bi + 3) as u32) |
                                              ((*bp.offset(bi + 2) as u32) << 8) |
                                              ((*bp.offset(bi + 1) as u32) << 16) |
                                              ((*bp.offset(bi + 0) as u32) << 24);
                }
            }

            let mut a = self.h0;
            let mut b = self.h1;
            let mut c = self.h2;
            let mut d = self.h3;
            let mut e = self.h4;

            unsafe {
                for i in range(0, 16) {
                    let f = b&c | (!b)&d;
                    let a5 = a<<5 | a>>(32-5);
                    let b30 = b<<30 | b>>(32-30);
                    let t = a5 + f + e + *wp.offset(i&0xf) + K0;
                    a = t;
                    b = a;
                    c = b30;
                    d = c;
                    e = d;
                }
                for i in range(16, 20) {
                    let tmp = *wp.offset((i-3)&0xf) ^
                              *wp.offset((i-8)&0xf) ^ 
                              *wp.offset((i-14)&0xf) ^ 
                              *wp.offset(i&0xf);
                    *wp.offset(i&0xf) = tmp<<1 | tmp>>(32-1);

                    let f = b&c | (!b)&d;
                    let a5 = a<<5 | a>>(32-5);
                    let b30 = b<<30 | b>>(32-30);
                    let t = a5 + f + e + *wp.offset(i&0xf) + K0;
                    a = t;
                    b = a;
                    c = b30;
                    d = c;
                    e = d;
                }
                for i in range(20, 40) {
                    let tmp = *wp.offset((i-3)&0xf) ^
                              *wp.offset((i-8)&0xf) ^
                              *wp.offset((i-14)&0xf) ^
                              *wp.offset(i&0xf);
                    *wp.offset(i&0xf) = tmp<<1 | tmp>>(32-1);
                    let f = b ^ c ^ d;
                    let a5 = a<<5 | a>>(32-5);
                    let b30 = b<<30 | b>>(32-30);
                    let t = a5 + f + e + *wp.offset(i&0xf) + K1;
                    a = t;
                    b = a;
                    c = b30;
                    d = c;
                    e = d;
                }
                for i in range(40, 60) {
                    let tmp = *wp.offset((i-3)&0xf) ^ 
                              *wp.offset((i-8)&0xf) ^ 
                              *wp.offset((i-14)&0xf) ^ 
                              *wp.offset(i&0xf);
                    *wp.offset(i&0xf) = tmp<<1 | tmp>>(32-1);
                    let f = ((b | c) & d) | (b & c);

                    let a5 = a<<5 | a>>(32-5);
                    let b30 = b<<30 | b>>(32-30);
                    let t = a5 + f + e + *wp.offset(i&0xf) + K2;
                    a = t;
                    b = a;
                    c = b30;
                    d = c;
                    e = d;
                }
                for i in range(60, 80) {
                    let tmp = *wp.offset((i-3)&0xf) ^ 
                              *wp.offset((i-8)&0xf) ^ 
                              *wp.offset((i-14)&0xf) ^ 
                              *wp.offset(i&0xf);
                    *wp.offset(i&0xf) = tmp<<1 | tmp>>(32-1);
                    let f = b ^ c ^ d;
                    let a5 = a<<5 | a>>(32-5);
                    let b30 = b<<30 | b>>(32-30);
                    let t = a5 + f + e + *wp.offset(i&0xf) + K3;
                    a = t;
                    b = a;
                    c = b30;
                    d = c;
                    e = d;
                }
            }// end unsafe

            self.h0 += a;
            self.h1 += b;
            self.h2 += c;
            self.h3 += d;
            self.h4 += e;
        }
    }

}

fn to_hex(input: &[u8]) -> String {
    let mut s = String::new();
    for b in input.iter() {
        s.push_str(&*format!("{:02x}", *b));
    }
    return s;
}

impl hash::Hasher for Sha1 {
    type Output = Vec<u8>;
    fn reset(&mut self) {
        self.state = Sha1State::new();
        self.buffer = [0u8; CHUNK_SIZE];
        self.length_bits = 0;
        self.nx = 0;
    }
    fn finish(&self) -> Vec<u8> {
        let mut buf = [0u8; 20].to_vec();
        self.output(&mut *buf);
        buf
    }
}

impl Default for Sha1 {
    #[inline]
    fn default() -> Sha1 {
        Sha1::new()
    }
}

    fn copy_slice(dst: &mut [u8], src: &[u8]) -> usize {
        let mut c = 0;
        for (d, s) in dst.iter_mut().zip(src.iter()) {
            *d = *s;
            c += 1;
        }
        c 
    }

impl hash::Writer for Sha1 {
    fn write(&mut self, bytes: &[u8]) {
        let nn = bytes.len();
        self.length_bits = add_bytes_to_bits(self.length_bits, nn as u64);
        let mut b = bytes;

        if self.nx > 0 {
            let n = copy_slice(&mut self.buffer[self.nx .. ], b);
            self.nx += n;
            if self.nx == CHUNK_SIZE {
                self.state.process_block(&self.buffer[]);
                self.nx = 0;
            }
            b = &bytes[n .. ]
        }
        if b.len() >= CHUNK_SIZE {
            let n = b.len() & !(CHUNK_SIZE-1);
            self.state.process_block(&b[ .. n]);
            b = &bytes[n .. ];
        }
        if b.len() > 0 {
            self.nx = copy_slice(&mut self.buffer[], b);
        }
    }
}


impl Sha1 {

    /// Creates an fresh sha1 hash object.
    pub fn new() -> Sha1 {
        Sha1 {
            state: Sha1State::new(),
            buffer: [0u8; CHUNK_SIZE],
            length_bits: 0,
            nx: 0,
        }
    }

    /// Retrieve digest result.  The output must be large enough to
    /// contain result (20 bytes).
    /// Can be called any amount of times
    /// TODO: make sure we don't do that
    pub fn output(&self, out: &mut [u8]) {
        let mut m = Sha1 {
            state: self.state.clone(),
            buffer: self.buffer,
            length_bits: self.length_bits,
            nx: self.nx
        };

        let mut tmp = [0u8; CHUNK_SIZE];
        tmp[0] = 0x80u8;
        let mut len = m.length_bits;

        if len % CHUNK_SIZE as u64 > 56 {
            m.write(&tmp[0 .. 56-(len%CHUNK_SIZE as u64) as usize]);
        } else {
            m.write(&tmp[0 .. CHUNK_SIZE+56-(len%CHUNK_SIZE as u64) as usize])
        }

        len = len<<3;
        for i in range(0, 8) {
            tmp[i] = (len >> (56 - 8*i)) as u8;
        }
        m.write(&tmp[ .. 8]);
        assert!(m.nx == 0, "Should have processed chunk by now");

        let m = m;
        write_u32_be(&mut out[  ..4],  m.state.h0);
        write_u32_be(&mut out[4 ..8],  m.state.h1);
        write_u32_be(&mut out[8 ..12], m.state.h2);
        write_u32_be(&mut out[12..16], m.state.h3);
        write_u32_be(&mut out[16..  ], m.state.h4);
    }

    pub fn hexdigest(&self) -> String {
        to_hex(&*self.finish())
    }
}
