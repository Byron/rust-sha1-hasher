![title-image](https://raw.githubusercontent.com/Byron/rust-sha1-hasher/master/src/png/title-image.png)

# The SHA1 Performance Quest

Follow me on my quest to bring the performance of this implementation up 
to comparable speeds with respective versions in Go and C !

At [Episode 1](#1) we start out at *just 180MB/s*, whereas C clocks in at
*400MB/s*, and Go at a whopping *450MB/s* .

Watch [all Episodes](http://www.youtube.com/playlist?list=PLMHbQxe1e9MnDKy7FKXZwMJ6t_RCxpHqD) to learn
what can be done to make it faster.

But ... will it be comparable or even out-pace the competition ?

[![thumb](http://img.youtube.com/vi/JeAYzOLYugQ/0.jpg)](http://www.youtube.com/playlist?list=PLMHbQxe1e9MnDKy7FKXZwMJ6t_RCxpHqD)


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
