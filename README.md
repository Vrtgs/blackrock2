A port of the Blackrock2 cipher used in [Masscan](https://github.com/robertdavidgraham/masscan) to Rust.
Its original purpose is efficiently randomizing the order of port scans
without having to put every possible target in memory and shuffling.
[Original code](https://github.com/robertdavidgraham/masscan/blob/master/src/crypto-blackrock2.c).


# Examples
```rs
use blackrock2::BlackRockIpGenerator;

for ip in BlackRockIpGenerator::new() {
    println!("{ip}")
}
```
