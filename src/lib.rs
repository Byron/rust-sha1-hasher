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

use std::io::{Writer, BufWriter};
use std::default::Default;
use std::hash::{self, Hasher};

/// Represents a Sha1 hash object in memory.
#[derive(Clone)]
pub struct Sha1 {
    state: [u32; 5],
    data: Vec<u8>,
    len: u64,
}

const DEFAULT_STATE : [u32; 5] =
    [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];


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
        self.state = DEFAULT_STATE;
        self.data.clear();
        self.len = 0;
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
        let mut d = self.data.clone();
        self.data.clear();

        d.push_all(bytes);

        for chunk in d[].chunks(64) {
            if chunk.len() == 64 {
                self.len += 64;
                self.process_block(chunk);
            } else {
                self.data.push_all(chunk);
            }
        }
    }
}


impl Sha1 {

    /// Creates an fresh sha1 hash object.
    pub fn new() -> Sha1 {
        Sha1 {
            state: DEFAULT_STATE,
            data: Vec::new(),
            len: 0,
        }
    }

    fn process_block(&mut self, block: &[u8]) {
        assert_eq!(block.len(), 64);

        let mut words = [0u32; 80];
        for (i, chunk) in block.chunks(4).enumerate() {
            words[i] = (chunk[3] as u32) |
                       ((chunk[2] as u32) << 8) |
                       ((chunk[1] as u32) << 16) |
                       ((chunk[0] as u32) << 24);
        }

        fn ff(b: u32, c: u32, d: u32) -> u32 { d ^ (b & (c ^ d)) }
        fn gg(b: u32, c: u32, d: u32) -> u32 { b ^ c ^ d }
        fn hh(b: u32, c: u32, d: u32) -> u32 { (b & c) | (d & (b | c)) }
        fn ii(b: u32, c: u32, d: u32) -> u32 { b ^ c ^ d }

        fn left_rotate(x: u32, n: u32) -> u32 { (x << n) | (x >> (32 - n)) }

        for i in range(16, 80) {
            let n = words[i - 3] ^ words[i - 8] ^ words[i - 14] ^ words[i - 16];
            words[i] = left_rotate(n, 1);
        }

        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];

        for i in range(0, 80) {
            let (f, k) = match i {
                0 ... 19 => (ff(b, c, d), 0x5a827999),
                20 ... 39 => (gg(b, c, d), 0x6ed9eba1),
                40 ... 59 => (hh(b, c, d), 0x8f1bbcdc),
                60 ... 79 => (ii(b, c, d), 0xca62c1d6),
                _ => (0, 0),
            };

            let tmp = left_rotate(a, 5) + f + e + k + words[i];
            e = d;
            d = c;
            c = left_rotate(b, 30);
            b = a;
            a = tmp;
        }

        self.state[0] += a;
        self.state[1] += b;
        self.state[2] += c;
        self.state[3] += d;
        self.state[4] += e;
    }

    /// Retrieve digest result.  The output must be large enough to
    /// contain result (20 bytes).
    pub fn output(&self, out: &mut [u8]) {
        // these are unlikely to fail, since we're writing to memory
        #![allow(unused_must_use)]

        let mut m = Sha1 {
            state: self.state.clone(),
            data: Vec::new(),
            len: 0,
        };

        let mut w = Vec::<u8>::new();
        w.write(&*self.data);
        w.write_u8(0x80u8);
        let padding = 64 - ((self.data.len() + 9) % 64);
        for _ in range(0, padding) {
            w.write_u8(0u8);
        }
        w.write_be_u64((self.data.len() as u64 + self.len) * 8);
        for chunk in w[].chunks(64) {
            m.process_block(chunk);
        }

        let mut w = BufWriter::new(out);
        for &n in m.state.iter() {
            w.write_be_u32(n);
        }
    }

    pub fn hexdigest(&self) -> String {
        to_hex(&*self.finish())
    }
}
