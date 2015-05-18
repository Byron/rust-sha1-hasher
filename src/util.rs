use std::slice::bytes::copy_memory;

/// A FixedBuffer of 64 bytes useful for implementing Sha256 which has a 64 byte blocksize.
#[derive(Copy)]
pub struct FixedBuffer64 {
    buffer: [u8; 64],
    buffer_idx: usize,
}

impl Clone  for FixedBuffer64 {
    fn clone(&self) -> FixedBuffer64 {
        FixedBuffer64 {
            buffer: self.buffer,
            buffer_idx: self.buffer_idx
        }
    }
}

impl FixedBuffer64 {
    /// Create a new FixedBuffer64
    pub fn new() -> FixedBuffer64 {
        return FixedBuffer64 {
            buffer: [0u8; 64],
            buffer_idx: 0
        };
    }

   pub fn input<F>(&mut self, input: &[u8], mut func: F) where
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
                        &input[..buffer_remaining],
                        &mut self.buffer[self.buffer_idx .. size]);
                self.buffer_idx = 0;
                func(&self.buffer);
                i += buffer_remaining;
            } else {
                copy_memory(
                    input,
                    &mut self.buffer[self.buffer_idx .. self.buffer_idx + input.len()]);
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
        copy_memory(&input[i..], &mut self.buffer[..input_remaining]);
        self.buffer_idx += input_remaining;
    }

    pub fn reset(&mut self) {
        self.buffer_idx = 0;
    }

    pub fn zero_until(&mut self, idx: usize) {
        assert!(idx >= self.buffer_idx);
        for vp in (&mut self.buffer[self.buffer_idx .. idx]).iter_mut() {
            *vp = 0;
        }
        self.buffer_idx = idx;
    }

    pub fn next<'s>(&'s mut self, len: usize) -> &'s mut [u8] {
        self.buffer_idx += len;
        return &mut self.buffer[self.buffer_idx - len .. self.buffer_idx];
    }

    pub fn full_buffer<'s>(&'s mut self) -> &'s [u8] {
        assert!(self.buffer_idx == 64);
        self.buffer_idx = 0;
        return &self.buffer[..64];
    }

    pub fn remaining(&self) -> usize { 64 - self.buffer_idx }

    pub fn size(&self) -> usize { 64 }

    pub fn standard_padding<F>(&mut self, rem: usize, mut func: F) where F: FnMut(&[u8]) {
        let size = self.size();

        self.next(1)[0] = 128;

        if self.remaining() < rem {
            self.zero_until(size);
            func(self.full_buffer());
        }

        self.zero_until(size - rem);
    }
}


/// Adds the specified number of bytes to the bit count. panic!() if this would cause numeric
/// overflow.
pub fn add_bytes_to_bits(bits: u64, bytes: u64) -> u64 {
    let (new_high_bits, new_low_bits) = (bytes >> 61, bytes << 3);

    if new_high_bits > 0 {
        panic!("numeric overflow occurred.")
    }

    match bits.checked_add(new_low_bits) {
        Some(x) => return x,
        None => panic!("numeric overflow occurred.")
    }
}

/// **TODO**: This implementation is very inefficient, there should be better ways
/// that pre-allocate the required memory.
pub fn to_hex(input: &[u8]) -> String {
    let mut s = String::new();
    for b in input.iter() {
        s.push_str(&*format!("{:02x}", *b));
    }
    return s;
}

/// Write a u32 into a vector, which must be 4 bytes long. The value is written in big-endian
/// format.
pub fn write_u32_be(dst: &mut[u8], input: u32) {
    dst[0] = (input >> 24) as u8;
    dst[1] = (input >> 16) as u8;
    dst[2] = (input >> 8) as u8;
    dst[3] = input as u8;
}