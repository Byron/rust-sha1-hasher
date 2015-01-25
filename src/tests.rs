#![cfg(test)]

extern crate test;

use self::test::Bencher;
use super::{Sha1, to_hex};
use std::hash::{Writer, Hasher};
use std::iter;

#[test]
fn test_simple() {
    let mut m = Sha1::new();

    let tests = [
        ("The quick brown fox jumps over the lazy dog",
        "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"),
        ("The quick brown fox jumps over the lazy cog",
        "de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3"),
        ("", "da39a3ee5e6b4b0d3255bfef95601890afd80709"),
        ("testing\n", "9801739daae44ec5293d4e1f53d3f4d2d426d91c"),
        ("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        "025ecbd5d70f8fb3c5457cd96bab13fda305dc59"),
    ];

    for &(s, ref h) in tests.iter() {
        let data = s.as_bytes();

        m.reset();
        m.write(data);
        let hh = m.hexdigest();

        assert_eq!(hh.len(), h.len());
        assert_eq!(&*hh, *h);
    }
}

#[test]
fn test_dirty_run() {
    let mut m = Sha1::new();

    m.write(b"123");
    let out1 = m.finish();

    m.write(b"123");
    let out2 = m.finish();

    assert!(out1 != out2);
    assert_eq!(&*to_hex(&*out1), "40bd001563085fc35165329ea1ff5c5ecbdbbeef");
    assert_eq!(&*to_hex(&*out2), "601f1889667efaebb33b8c12572835da3f027f78");
}

#[bench]
fn sha1_text_digest_with_assertion(b: &mut Bencher) {
    let mut m = Sha1::new();
    let s = "The quick brown fox jumps over the lazy dog.";
    let n = 1000u64;

    b.bytes = n * s.len() as u64;
    b.iter(|| {
        m.reset();
        for _ in range(0, n) {
            m.write(s.as_bytes());
        }
        assert_eq!(m.hexdigest(), "7ca27655f67fceaa78ed2e645a81c7f1d6e249d2");
    });
}

#[bench]
pub fn sha160_10B_static_input(b: &mut Bencher) {
    let mut sh = Sha1::new();
    const COUNT: usize = 1000;
    let bytes = [1u8; 10];

    b.iter(|| {
        for _ in range(1, COUNT) {
            sh.write(&bytes);
        }
    });
    b.bytes = (COUNT * bytes.len()) as u64;
}

#[bench]
pub fn sha160_64k_static_input(b: &mut Bencher) {
    let mut sh = Sha1::new();
    let bytes = [1u8; 65536];
    b.iter(|| {
        sh.write(&bytes);
    });
    b.bytes = bytes.len() as u64;
}

#[bench]
pub fn sha160_static_input_changing_slice_size(b: &mut Bencher) {
    let mut sh = Sha1::new();
    const BUF_SIZE: usize = 128;
    let bytes = [1u8; BUF_SIZE];

    let mut total = 0;
    b.iter(|| {
        total = 0;
        iter::range_step(1, BUF_SIZE, 1).map(|x| {
            sh.write(&bytes[0 .. x]);
            total += x;
        }).count();
    });
    b.bytes = total as u64;
}

// macro_rules! bench {
//     ($name:ident, $chunk_size:expr) => {
//         #[bench]
//         fn $name(b: &mut Bencher) {
//             // let mut x: Vec<_> = iter::repeat(1.0f32)
//             //                          .take(BENCH_SIZE)
//             //                          .collect();
//             // let y: Vec<_> = iter::repeat(1.0f32)
//             //                      .take(BENCH_SIZE)
//             //                      .collect();
//             // b.iter(|| {
//             //     $func(&mut x, &y);
//             // });
//             // b.bytes += BENCH_SIZE as u64;
//         }
//     }
// }

// bench!(sha160_10, 10);
