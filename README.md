[![title-image](https://raw.githubusercontent.com/Byron/rust-sha1-hasher/master/src/png/title-image.png)](http://www.youtube.com/playlist?list=PLMHbQxe1e9MnDKy7FKXZwMJ6t_RCxpHqD)
[![Build Status](https://travis-ci.org/Byron/rust-sha1-hasher.svg?branch=master)](https://travis-ci.org/Byron/rust-sha1-hasher)
[![Version](https://img.shields.io/crates/v/sha1-hasher-faster.svg)](https://travis-ci.org/Byron/https://crates.io/crates/sha1-hasher-faster)

# The SHA1 Performance Quest

Follow me on my quest to bring the performance of this implementation up 
to comparable speeds with respective versions in Go and C !

At [Episode 1](#1) we start out at *just 180MB/s*, whereas C clocks in at
*400MB/s*, and Go at a whopping *450MB/s* (using hand-optimized assembly). It actually produces only 140MB/s with actual Go code.

Watch [all Episodes](http://www.youtube.com/playlist?list=PLMHbQxe1e9MnDKy7FKXZwMJ6t_RCxpHqD) to learn
what can be done to make it faster.

But ... will it be comparable or even out-pace the competition ?

[![thumb](http://img.youtube.com/vi/JeAYzOLYugQ/0.jpg)](http://www.youtube.com/playlist?list=PLMHbQxe1e9MnDKy7FKXZwMJ6t_RCxpHqD)

# Conclusion

It didn't quite work out as I hoped, as I would have been content only when reaching at least the 400MB/s mark
delivered by the highly optimized C implementation. However, after re-implementing the Go version
of the SHA-1 hashing algorithm, we turn out to process only ~320MB/s - far away from the 450MB/s that Go produces.

Unfortunately, due to the added complexity and lack of understanding the entire implementation, a bug or two have slipped
into our Go-implementation clone, causing it to malfunction. Maybe it's an easy fix ... maybe.

For me it will be best to not spend more time on this, in an attempt to be happy with the working 280MB/s I achieved
by myself.

**After all, I am content that the fantastic Rust community will at some point produce the SHA1 implementation I always dreamed of**.

**However, [most recent findings](http://youtu.be/RcfJUcGCmWM) clearly show that Rust was compared to a hand-optimized assembly version**, that even C can't compete with. Thus, Rust is actually doing quite well, and *only* 20% behind C after all, which is fully unrolled and hand-optimized as well.

**Second Amendment**: The current version of [rust-crypto](https://github.com/DaGenix/rust-crypto) clocks in at 360MB/s, using an implementation comparable to the fully optimized/unrolled one of C. This also means Rust is just 10% away from C performance, making it truly deliver on its promises ! Totally awesome, the SHA-1 quest for performance got a happy end, finally !

# rust-sha1-hasher

Minimal implementation of SHA1 for Rust. This might go away in the future
if rust-crypto or some libraries like that split into smaller parts.

Right now SHA1 is quite frequently used and many things want to have an
implementation of it, that does not pull in too much other stuff.

This is largely based on the hash code in crypto-rs by Koka El Kiwi.

This fork also adds some fixes for long data hashing (original version
has bug with hashing data built with several `update()` calls)
and reimplements functionality using `Hash` and `Hasher` traits
from Rust's standard lib, making it more composable.
