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
use std::io::Writer;
use std::iter;
use std::default::Default;
use std::hash::{self, Hasher};
use std::slice::bytes::copy_memory;

/// Represents a Sha1 hash object in memory.
pub struct Sha1 {
    state: Sha1State,
    buffer: FixedBuffer64,
    length_bits: u64,
}

#[derive(Clone)]
struct Sha1State {
    pub h0: u32,
    pub h1: u32,
    pub h2: u32,
    pub h3: u32,
    pub h4: u32,

}

/// A FixedBuffer of 64 bytes useful for implementing Sha256 which has a 64 byte blocksize.
struct FixedBuffer64 {
    buffer: [u8; 64],
    buffer_idx: usize,
}

impl Copy for FixedBuffer64 {}

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
        debug_assert!(block.len() == 64);

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

        let mut a = self.h0;
        let mut b = self.h1;
        let mut c = self.h2;
        let mut d = self.h3;
        let mut e = self.h4;

        for i in range(0, 20) {
            let tmp = left_rotate(a, 5) + ff(b, c, d) + e + 0x5a827999 + words[i];
            e = d;
            d = c;
            c = left_rotate(b, 30);
            b = a;
            a = tmp;
        }

        for i in range(20, 40) {
                
            let tmp = left_rotate(a, 5) + gg(b, c, d) + e + 0x6ed9eba1 + words[i];
            e = d;
            d = c;
            c = left_rotate(b, 30);
            b = a;
            a = tmp;
        }

        for i in range(40, 60) {
            let tmp = left_rotate(a, 5) + hh(b, c, d) + e + 0x8f1bbcdc + words[i];
            e = d;
            d = c;
            c = left_rotate(b, 30);
            b = a;
            a = tmp;
        }

        for i in range(60, 80) {
            let tmp = left_rotate(a, 5) + ii(b, c, d) + e + 0xca62c1d6 + words[i];
            e = d;
            d = c;
            c = left_rotate(b, 30);
            b = a;
            a = tmp;
        }




        self.h0 += a;
        self.h1 += b;
        self.h2 += c;
        self.h3 += d;
        self.h4 += e;
    }

}

impl FixedBuffer64 {
    /// Create a new FixedBuffer64
    fn new() -> FixedBuffer64 {
        return FixedBuffer64 {
            buffer: [0u8; 64],
            buffer_idx: 0
        };
    }

       fn input<F>(&mut self, input: &[u8], mut func: F) where
        F: FnMut(&[u8]),
    {
        let mut i = 0;

        let size = self.size();

        // If there is already data in the buffer, copy as much as we can into it and process
        // the data if the buffer becomes full.
        if self.buffer_idx != 0 {
            let buffer_remaining = size - self.buffer_idx;
            if input.len() >= buffer_remaining {
                    copy_memory(
                        &mut self.buffer[self.buffer_idx .. size],
                        &input[..buffer_remaining]);
                self.buffer_idx = 0;
                func(&self.buffer);
                i += buffer_remaining;
            } else {
                copy_memory(
                    &mut self.buffer[self.buffer_idx .. self.buffer_idx + input.len()],
                    input);
                self.buffer_idx += input.len();
                return;
            }
        }

        // While we have at least a full buffer size chunk's worth of data, process that data
        // without copying it into the buffer
        while input.len() - i >= size {
            func(&input[i..(i + size)]);
            i += size;
        }

        // Copy any input data into the buffer. At this point in the method, the amount of
        // data left in the input vector will be less than the buffer size and the buffer will
        // be empty.
        let input_remaining = input.len() - i;
        copy_memory(&mut self.buffer[..input_remaining], &input[i..]);
        self.buffer_idx += input_remaining;
    }

    fn reset(&mut self) {
        self.buffer_idx = 0;
    }

    fn zero_until(&mut self, idx: usize) {
        assert!(idx >= self.buffer_idx);
        for vp in (&mut self.buffer[self.buffer_idx .. idx]).iter_mut() {
            *vp = 0;
        }
        self.buffer_idx = idx;
    }

    fn next<'s>(&'s mut self, len: usize) -> &'s mut [u8] {
        self.buffer_idx += len;
        return &mut self.buffer[self.buffer_idx - len .. self.buffer_idx];
    }

    fn full_buffer<'s>(&'s mut self) -> &'s [u8] {
        assert!(self.buffer_idx == 64);
        self.buffer_idx = 0;
        return &self.buffer[..64];
    }

    fn position(&self) -> usize { self.buffer_idx }

    fn remaining(&self) -> usize { 64 - self.buffer_idx }

    fn size(&self) -> usize { 64 }

    fn standard_padding<F>(&mut self, rem: usize, mut func: F) where F: FnMut(&[u8]) {
        let size = self.size();

        self.next(1)[0] = 128;

        if self.remaining() < rem {
            self.zero_until(size);
            func(self.full_buffer());
        }

        self.zero_until(size - rem);
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
