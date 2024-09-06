//! A port of the Blackrock2 cipher used in [Masscan](https://github.com/robertdavidgraham/masscan) to Rust.
//!
//! Its original purpose is efficiently randomizing the order of port scans
//! without having to put every possible target in memory and shuffling.
//!
//! [Original code](https://github.com/robertdavidgraham/masscan/blob/master/src/crypto-blackrock2.c).

use std::iter::FusedIterator;
use std::net::Ipv4Addr;
use std::ops::Range;
use crate::generator::BlackRockGenerator;

pub mod generator;


pub struct BlackRockIter {
    range: Range<u64>,
    generator: BlackRockGenerator
}

impl Default for BlackRockIter {
    fn default() -> Self {
        // the iter is empty do anything :P
        Self::with_seed_and_rounds(0, 0, 0)
    }
}

impl BlackRockIter {
    /// Create a new `BlackRockIter` with a specific range, seed, and rounds.
    /// See [`BlackRockGenerator::new`] for more details
    pub const fn with_seed_and_rounds(range: u64, seed: u64, rounds: usize) -> Self {
        Self {
            range: 0..range,
            generator: BlackRockGenerator::with_seed_and_rounds(range, seed, rounds),
        }
    }

    /// Create a new `BlackRockIter` with the provided seed and default rounds.
    pub fn with_seed(range: u64, seed: u64) -> Self {
        Self {
            range: 0..range,
            generator: BlackRockGenerator::with_seed(range, seed),
        }
    }

    /// Create a new `BlackRockIter` with a random seed and the provided rounds.
    pub fn with_rounds(range: u64, rounds: usize) -> Self {
        Self {
            range: 0..range,
            generator: BlackRockGenerator::with_rounds(range, rounds),
        }
    }

    /// Create a new `BlackRockIter` with a random seed and default rounds.
    pub fn new(range: u64) -> Self {
        Self {
            range: 0..range,
            generator: BlackRockGenerator::new(range),
        }
    }
}

impl Iterator for BlackRockIter {
    type Item = u64;

    fn next(&mut self) -> Option<Self::Item> {
        self.range.next().map(|x| self.generator.shuffle(x))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.range.size_hint()
    }

    fn count(self) -> usize
    where
        Self: Sized,
    {
        self.range.count()
    }
    
    fn nth(&mut self, n: usize) -> Option<Self::Item> {
        self.range.nth(n).map(|x| self.generator.shuffle(x))
    }
}

impl DoubleEndedIterator for BlackRockIter {
    fn next_back(&mut self) -> Option<Self::Item> {
        self.range.next_back().map(|x| self.generator.shuffle(x))
    }

    fn nth_back(&mut self, n: usize) -> Option<Self::Item> {
        self.range.nth_back(n).map(|x| self.generator.shuffle(x))
    }
}

impl FusedIterator for BlackRockIter {}

pub struct BlackRockIpGenerator(BlackRockIter);

impl Default for BlackRockIpGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl BlackRockIpGenerator {
    pub fn new() -> Self {
        Self(BlackRockIter::new(1 << 32))
    }
}

const fn to_ip(x: u64) -> Ipv4Addr {
    debug_assert!(x < u32::MAX as u64);
    Ipv4Addr::from_bits(x as u32)
}

impl Iterator for BlackRockIpGenerator {
    type Item = Ipv4Addr;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().map(to_ip)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.0.size_hint()
    }

    fn count(self) -> usize
    where
        Self: Sized,
    {
        self.0.count()
    }

    fn nth(&mut self, n: usize) -> Option<Self::Item> {
        self.0.nth(n).map(to_ip)
    }
}

impl DoubleEndedIterator for BlackRockIpGenerator {
    fn next_back(&mut self) -> Option<Self::Item> {
        self.0.next_back().map(to_ip)
    }

    fn nth_back(&mut self, n: usize) -> Option<Self::Item> {
        self.0.nth_back(n).map(to_ip)
    }
}

impl FusedIterator for BlackRockIpGenerator {}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_on_zero() {
        assert!(BlackRockIter::new(0).next().is_none());
    }
    
    #[test]
    fn test_ranges() {
        for range in 0..100 {
            let mut cnt = vec![false; range as usize];
            for rnd in BlackRockIter::new(range) {
                if std::mem::replace(&mut cnt[rnd as usize], true) { 
                    panic!("Duplicate range!")
                }
            }
        }
    }
}