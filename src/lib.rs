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

#![allow(unstable)]
#![unstable]

mod tests;
mod util;

extern crate serialize;

use std::default::Default;
use std::hash::{self, Hasher};
use util::{to_hex, add_bytes_to_bits, write_u32_be, FixedBuffer64};

/// Represents a Sha1 hash object in memory.
pub struct Sha1 {
    state: Sha1State,
    buffer: FixedBuffer64,
    length_bits: u64,
}

#[derive(Clone)]
struct Sha1State {
    h0: u32,
    h1: u32,
    h2: u32,
    h3: u32,
    h4: u32,

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
        debug_assert!(block.len() == BS);

        let mut words = [0u32; 80];
        let wp: *mut u32 =  &mut words[0];
        let bp: *const u8 = &block[0];

        // process all u8 in block, we use the words as an index (16 with 4 bytes each)
        unsafe {
            for wi in range(0, BS / WS) {
                let bi = (wi * WS) as isize;
                *wp.offset(wi as isize) = ( *bp.offset(bi + 3) as u32) |
                                          ((*bp.offset(bi + 2) as u32) << 8) |
                                          ((*bp.offset(bi + 1) as u32) << 16) |
                                          ((*bp.offset(bi + 0) as u32) << 24);
            }
        }

        // NOTE: These functions are automatically inlined. Making this explicit 
        // changes nothing, nor does using macros
        fn ff(b: u32, c: u32, d: u32) -> u32 { d ^ (b & (c ^ d)) }
        fn gg(b: u32, c: u32, d: u32) -> u32 { b ^ c ^ d }
        fn hh(b: u32, c: u32, d: u32) -> u32 { (b & c) | (d & (b | c)) }
        fn ii(b: u32, c: u32, d: u32) -> u32 { b ^ c ^ d }
        fn left_rotate(x: u32, n: u32) -> u32 { (x << n) | (x >> (32 - n)) }

        unsafe {
            for i in range(16, 80) {
                let n = *wp.offset(i -  3) ^ 
                        *wp.offset(i -  8) ^
                        *wp.offset(i - 14) ^ 
                        *wp.offset(i - 16);
                *wp.offset(i) = left_rotate(n, 1);
            }
        }

        let mut a = self.h0;
        let mut b = self.h1;
        let mut c = self.h2;
        let mut d = self.h3;
        let mut e = self.h4;

        unsafe {
            for i in range(0, 20) {
                let tmp = left_rotate(a, 5) + ff(b, c, d) + e + 0x5a827999 + *wp.offset(i);
                e = d;
                d = c;
                c = left_rotate(b, 30);
                b = a;
                a = tmp;
            }

            for i in range(20, 40) {
                    
                let tmp = left_rotate(a, 5) + gg(b, c, d) + e + 0x6ed9eba1 + *wp.offset(i);
                e = d;
                d = c;
                c = left_rotate(b, 30);
                b = a;
                a = tmp;
            }

            for i in range(40, 60) {
                let tmp = left_rotate(a, 5) + hh(b, c, d) + e + 0x8f1bbcdc + *wp.offset(i);
                e = d;
                d = c;
                c = left_rotate(b, 30);
                b = a;
                a = tmp;
            }

            for i in range(60, 80) {
                let tmp = left_rotate(a, 5) + ii(b, c, d) + e + 0xca62c1d6 + *wp.offset(i);
                e = d;
                d = c;
                c = left_rotate(b, 30);
                b = a;
                a = tmp;
            }
        }




        self.h0 += a;
        self.h1 += b;
        self.h2 += c;
        self.h3 += d;
        self.h4 += e;
    }

}

impl hash::Hasher for Sha1 {
    type Output = Vec<u8>;

    fn reset(&mut self) {
        self.state = Sha1State::new();
        self.buffer.reset();
        self.length_bits = 0;
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

impl hash::Writer for Sha1 {
    fn write(&mut self, bytes: &[u8]) {
        self.length_bits = add_bytes_to_bits(self.length_bits, bytes.len() as u64);
        let own_state = &mut self.state;
        self.buffer.input(bytes, |input: &[u8]| { own_state.process_block(input) });
    }
}


impl Sha1 {

    /// Creates an fresh sha1 hash object.
    pub fn new() -> Sha1 {
        Sha1 {
            state: Sha1State::new(),
            buffer: FixedBuffer64::new(),
            length_bits: 0,
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
        };

        {    
            let own_state = &mut m.state;
            m.buffer.standard_padding(8, |input: &[u8]| { own_state.process_block(input) });
            write_u32_be(m.buffer.next(4), (m.length_bits >> 32) as u32 );
            write_u32_be(m.buffer.next(4), m.length_bits as u32);
            own_state.process_block(m.buffer.full_buffer());
        }

        let m = m;
        write_u32_be(&mut out[  ..4], m.state.h0);
        write_u32_be(&mut out[4 ..8], m.state.h1);
        write_u32_be(&mut out[8 ..12], m.state.h2);
        write_u32_be(&mut out[12..16], m.state.h3);
        write_u32_be(&mut out[16..  ], m.state.h4);

    }

    pub fn hexdigest(&self) -> String {
        to_hex(&*self.finish())
    }
}
