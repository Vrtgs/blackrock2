// https://en.wikipedia.org/wiki/Integer_square_root
const fn int_sqrt(n: u64) -> u64 {
    if n <= 1 {
        return n;
    }

    let mut x0 = n / 2;
    let mut x1 = (x0 + n / x0) / 2;

    while x1 < x0 {
        x0 = x1;
        x1 = (x0 + n / x0) / 2;
    }

    x0
}

#[derive(Debug)]
#[must_use = "this generator does nothing unless driven"]
pub struct BlackRockGenerator {
    range: u64,
    seed: u64,
    rounds: usize,
    a_bits: u32,
    a_mask: u64,
    b_mask: u64,
}

impl Default for BlackRockGenerator {
    fn default() -> Self {
        Self::new(0)
    }
}

impl BlackRockGenerator {
    /// Create a new blackrock cipher with a specific range, seed, and rounds.
    /// Use [`BlackRockGenerator::new`] to use the default seed and rounds.
    ///
    /// - `range`: The highest value you will try to shuffle. For example, this
    ///    would be 2<sup>32</sup> for an IPv4 address.
    /// - `seed`: The seed used for randomization.
    /// - `rounds`: The amount of times the randomization is done, to make it more random. Default is 3.
    ///
    /// ```
    /// # use blackrock2::generator::BlackRockGenerator;
    /// let perfect_rng = BlackRockGenerator::with_seed_and_rounds(10, rand::random(), 3);
    /// ```
    pub const fn with_seed_and_rounds(range: u64, seed: u64, rounds: usize) -> Self {
        let a = (int_sqrt(range) + 1).next_power_of_two();
        let b = ((range / a) + 1).next_power_of_two();

        #[inline]
        const fn bit_count(x: u64) -> u32 {
            match x.checked_ilog2() {
                Some(x) => x,
                None => 0
            }
        }

        Self {
            range,
            seed,
            rounds,
            a_bits: bit_count(a),
            a_mask: a - 1,
            b_mask: b - 1,
        }
    }


    /// Create a new `BlackRockGenerator` with the provided seed and default rounds.
    pub fn with_seed(range: u64, seed: u64) -> Self {
        Self::with_seed_and_rounds(range, seed, 3)
    }

    /// Create a new `BlackRockGenerator` with a random seed and the provided rounds.
    pub fn with_rounds(range: u64, rounds: usize) -> Self {
        Self::with_seed_and_rounds(range, rand::random(), rounds)
    }

    /// Create a new `BlackRockGenerator` with a random seed and default rounds.
    pub fn new(range: u64) -> Self {
        Self::with_seed_and_rounds(range, rand::random(), 3)
    }


    // https://github.com/mat-1/perfect_rand
    #[inline]
    fn sipround(&self, (mut v0, mut v1, mut v2, mut v3): (u64, u64, u64, u64)) -> (u64, u64, u64, u64) {
        v0 = v0.wrapping_add(v1);
        v2 = v2.wrapping_add(v3);
        v1 = v1.rotate_left(13) ^ v0;
        v3 = v3.rotate_left(16) ^ v2;
        v0 = v0.rotate_left(32);

        v2 = v2.wrapping_add(v1);
        v0 = v0.wrapping_add(v3);
        v1 = v1.rotate_left(17) ^ v2;
        v3 = v3.rotate_left(21) ^ v0;
        v2 = v2.rotate_left(32);

        (v0, v1, v2, v3)
    }

    #[inline]
    fn round(&self, j: usize, right: u64) -> u64 {
        let v0 = j as u64;
        let v1 = right;
        let v2 = self.seed;
        // all zeroes will lead to an all-zero output,
        // this adds some randomness for that case.
        let v3: u64 = 0xf3016d19bc9ad940;

        let v = self.sipround((v0, v1, v2, v3));
        let v = self.sipround(v);
        let v = self.sipround(v);

        self.sipround(v).0
    }

    #[inline]
    fn encrypt(&self, m: u64) -> u64 {
        let mut left = m & self.a_mask;
        let mut right = m >> self.a_bits;

        let mut j = 1;
        while j <= self.rounds {
            if j & 1 == 1 {
                let tmp = (left + self.round(j, right)) & self.a_mask;
                left = right;
                right = tmp;
                j += 1;
            } else {
                let tmp = (left + self.round(j, right)) & self.b_mask;
                left = right;
                right = tmp;
                j += 1;
            }
        }

        if j % 2 == 0 {
            (left << self.a_bits) + right
        } else {
            (right << self.a_bits) + left
        }
    }

    pub fn shuffle(&self, m: u64) -> u64 {
        let mut c = self.encrypt(m);
        while c >= self.range {
            c = self.encrypt(c);
        }
        c
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn verify(range: u64, seed: u64, rounds: usize) {
        let randomizer = BlackRockGenerator::with_seed_and_rounds(range, seed, rounds);
        println!("randomizer: {randomizer:?}");

        // make sure every number gets added exactly once
        let mut list = vec![0; range as usize];
        for i in 0..range {
            let x = randomizer.shuffle(i) as usize;
            list[x] += 1;
        }

        for (i, number) in list.into_iter().enumerate() {
            assert_eq!(number, 1, "Index: {i}, range: {range:?}");
        }
    }

    #[test]
    fn verify_ranges() {
        let mut range = 3015 * 3;

        for i in 0..5 {
            range += 11 + i;
            range *= 1 + i;

            verify(range, 0, 6);
        }

        verify(10, 0, 3);
        verify(100, 0, 3);
    }

    #[test]
    fn dont_get_stuck() {
        for range in [10, 100] {
            for seed in 0..100 {
                let randomizer = BlackRockGenerator::with_seed_and_rounds(range, seed, 3);

                for i in 0..range {
                    let _ = randomizer.shuffle(i);
                }
            }
        }
    }
}
