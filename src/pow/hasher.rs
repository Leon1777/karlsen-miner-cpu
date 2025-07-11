#![allow(clippy::unreadable_literal)]
use crate::Hash;
use blake2b_simd::State as Blake2bState;
use lazy_static::lazy_static;
use std::ops::BitXor;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;
use tiny_keccak::Hasher as OtherHasher;

const BLOCK_HASH_DOMAIN: &[u8] = b"BlockHash";

#[derive(Clone)]
pub struct PowB3Hash {
    pub hasher: blake3::Hasher,
}

#[derive(Clone)]
pub struct PowFishHash;

// fishhash const
const FNV_PRIME: u32 = 0x01000193;
const FULL_DATASET_ITEM_PARENTS: u32 = 512;
const NUM_DATASET_ACCESSES: u32 = 32;
const LIGHT_CACHE_ROUNDS: i32 = 3;
const LIGHT_CACHE_NUM_ITEMS: u32 = 1179641;
const FULL_DATASET_NUM_ITEMS: u32 = 37748717;

#[rustfmt::skip]
const SEED: Hash256 = Hash256([
    0xeb, 0x01, 0x63, 0xae, 0xf2, 0xab, 0x1c, 0x5a, 
    0x66, 0x31, 0x0c, 0x1c, 0x14, 0xd6, 0x0f, 0x42, 
    0x55, 0xa9, 0xb3, 0x9b, 0x0e, 0xdf, 0x26, 0x53, 
    0x98, 0x44, 0xf1, 0x17, 0xad, 0x67, 0x21, 0x19,
]);

const SIZE_U32: usize = std::mem::size_of::<u32>();
const SIZE_U64: usize = std::mem::size_of::<u64>();

pub static FISHHASH_FULL_DATASET: AtomicBool = AtomicBool::new(true);
static FULL_DATASET: OnceLock<Box<[OnceLock<Hash1024>]>> = OnceLock::new();

lazy_static! {
    static ref LIGHT_CACHE: Box<[Hash512]> = {
        let mut light_cache = vec![Hash512::new(); LIGHT_CACHE_NUM_ITEMS as usize].into_boxed_slice();
        PowFishHash::build_light_cache(&mut light_cache);
        light_cache
    };
}

#[derive(Clone)]
pub struct HeaderHasher(Blake2bState);

#[derive(Copy, Clone, Debug)]
pub struct Hash1024([u8; 128]);

impl HashData for Hash1024 {
    #[inline(always)]
    fn new() -> Self {
        Self([0; 128])
    }

    #[inline(always)]
    fn from_hash(hash: &Hash) -> Self {
        let mut result = Self::new();
        let (first_half, _) = result.0.split_at_mut(hash.to_le_bytes().len());
        first_half.copy_from_slice(&hash.to_le_bytes());
        result
    }

    #[inline(always)]
    fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    #[inline(always)]
    fn as_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl Hash1024 {
    #[inline(always)]
    fn from_512s(first: &Hash512, second: &Hash512) -> Self {
        let mut hash = Self::new();
        let (first_half, second_half) = hash.0.split_at_mut(first.0.len());
        first_half.copy_from_slice(&first.0);
        second_half.copy_from_slice(&second.0);
        hash
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Hash512([u8; 64]);

impl HashData for Hash512 {
    #[inline(always)]
    fn new() -> Self {
        Self([0; 64])
    }

    #[inline(always)]
    fn from_hash(hash: &Hash) -> Self {
        let mut result = Self::new();
        let (first_half, _) = result.0.split_at_mut(hash.to_le_bytes().len());
        first_half.copy_from_slice(&hash.to_le_bytes());
        result
    }

    #[inline(always)]
    fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    #[inline(always)]
    fn as_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl BitXor<&Hash512> for &Hash512 {
    type Output = Hash512;

    #[inline(always)]
    fn bitxor(self, rhs: &Hash512) -> Self::Output {
        let mut hash = Hash512::new();
        for i in 0..64 {
            hash.0[i] = self.0[i] ^ rhs.0[i]
        }
        hash
    }
}

pub trait HashData {
    fn new() -> Self;
    fn from_hash(hash: &Hash) -> Self;
    fn as_bytes(&self) -> &[u8];
    fn as_bytes_mut(&mut self) -> &mut [u8];

    #[inline(always)]
    fn get_as_u32(&self, index: usize) -> u32 {
        u32::from_le_bytes(self.as_bytes()[index * SIZE_U32..index * SIZE_U32 + SIZE_U32].try_into().unwrap())
    }

    #[inline(always)]
    fn set_as_u32(&mut self, index: usize, value: u32) {
        self.as_bytes_mut()[index * SIZE_U32..index * SIZE_U32 + SIZE_U32].copy_from_slice(&value.to_le_bytes())
    }

    #[inline(always)]
    fn get_as_u64(&self, index: usize) -> u64 {
        u64::from_le_bytes(self.as_bytes()[index * SIZE_U64..index * SIZE_U64 + SIZE_U64].try_into().unwrap())
    }

    #[inline(always)]
    fn set_as_u64(&mut self, index: usize, value: u64) {
        self.as_bytes_mut()[index * SIZE_U64..index * SIZE_U64 + SIZE_U64].copy_from_slice(&value.to_le_bytes())
    }
}

#[derive(Debug)]
pub struct Hash256([u8; 32]);

impl HashData for Hash256 {
    #[inline(always)]
    fn new() -> Self {
        Self([0; 32])
    }

    #[inline(always)]
    fn from_hash(hash: &Hash) -> Self {
        Self(hash.to_le_bytes())
    }

    #[inline(always)]
    fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    #[inline(always)]
    fn as_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

#[inline(always)]
fn lookup(index: usize) -> Hash1024 {
    match FISHHASH_FULL_DATASET.load(Ordering::Relaxed) {
        true => {
            let dataset =
                FULL_DATASET.get_or_init(|| (0..FULL_DATASET_NUM_ITEMS as usize).map(|_| OnceLock::new()).collect());
            *dataset[index].get_or_init(|| PowFishHash::calculate_dataset_item_1024(&LIGHT_CACHE, index))
        }
        false => PowFishHash::calculate_dataset_item_1024(&LIGHT_CACHE, index),
    }
}

/*
#[inline(always)]
fn lookup(index: usize) -> Hash1024 {
    if FISHHASH_FULL_DATASET.load(Ordering::Relaxed) {
        let dataset = FULL_DATASET.get_or_init(|| {
            println!("init {} items", FULL_DATASET_NUM_ITEMS);
            (0..FULL_DATASET_NUM_ITEMS as usize)
                .map(|_| OnceLock::new())
                .collect::<Vec<_>>()
                .into_boxed_slice()
        });

        let was_cached = dataset[index].get().is_some();
        let result = *dataset[index].get_or_init(|| {
            println!("compute {}", index);
            PowFishHash::calculate_dataset_item_1024(&LIGHT_CACHE, index)
        });

        if was_cached {
            println!("hit {}", index);
        }

        result
    } else {
        println!("direct {}", index);
        PowFishHash::calculate_dataset_item_1024(&LIGHT_CACHE, index)
    }
}
*/

impl PowFishHash {
    #[inline(always)]
    pub fn fishhashplus_kernel(seed: &Hash) -> Hash {
        let seed_hash512 = Hash512::from_hash(seed);
        let mut mix = Hash1024::from_512s(&seed_hash512, &seed_hash512);

        for i in 0..NUM_DATASET_ACCESSES {
            let mut mix_group: [u32; 8] = [0; 8];

            for (c, mix_group_elem) in mix_group.iter_mut().enumerate() {
                *mix_group_elem = mix.get_as_u32(4 * c)
                    ^ mix.get_as_u32(4 * c + 1)
                    ^ mix.get_as_u32(4 * c + 2)
                    ^ mix.get_as_u32(4 * c + 3);
            }

            let p0 = (mix_group[0] ^ mix_group[3] ^ mix_group[6]) % FULL_DATASET_NUM_ITEMS;
            let p1 = (mix_group[1] ^ mix_group[4] ^ mix_group[7]) % FULL_DATASET_NUM_ITEMS;
            let p2 = (mix_group[2] ^ mix_group[5] ^ i) % FULL_DATASET_NUM_ITEMS;

            let fetch0 = lookup(p0 as usize);
            let mut fetch1 = lookup(p1 as usize);
            let mut fetch2 = lookup(p2 as usize);

            // Modify fetch1 and fetch2
            for j in 0..32 {
                fetch1.set_as_u32(j, PowFishHash::fnv1(mix.get_as_u32(j), fetch1.get_as_u32(j)));
                fetch2.set_as_u32(j, mix.get_as_u32(j) ^ fetch2.get_as_u32(j));
            }

            // Final computation of new mix
            for j in 0..16 {
                mix.set_as_u64(
                    j,
                    fetch0.get_as_u64(j).wrapping_mul(fetch1.get_as_u64(j)).wrapping_add(fetch2.get_as_u64(j)),
                );
            }
        }

        // Collapse the result into 32 bytes
        let mut mix_hash = Hash256::new();
        let num_words = std::mem::size_of_val(&mix) / SIZE_U32;

        for i in (0..num_words).step_by(4) {
            let h1 = PowFishHash::fnv1(mix.get_as_u32(i), mix.get_as_u32(i + 1));
            let h2 = PowFishHash::fnv1(h1, mix.get_as_u32(i + 2));
            let h3 = PowFishHash::fnv1(h2, mix.get_as_u32(i + 3));
            mix_hash.set_as_u32(i / 4, h3);
        }

        Hash::from_le_bytes(mix_hash.0)
    }

    #[inline(always)]
    fn build_light_cache(cache: &mut [Hash512]) {
        let mut item: Hash512 = Hash512::new();
        PowFishHash::keccak(&mut item.0, &SEED.0);
        cache[0] = item;

        for cache_item in cache.iter_mut().take(LIGHT_CACHE_NUM_ITEMS as usize).skip(1) {
            PowFishHash::keccak_in_place(&mut item.0);
            *cache_item = item;
        }

        for _ in 0..LIGHT_CACHE_ROUNDS {
            for i in 0..LIGHT_CACHE_NUM_ITEMS {
                let t: u32 = cache[i as usize].get_as_u32(0);
                let v: u32 = t % LIGHT_CACHE_NUM_ITEMS;
                let w: u32 = (LIGHT_CACHE_NUM_ITEMS.wrapping_add(i.wrapping_sub(1))) % LIGHT_CACHE_NUM_ITEMS;

                let x = &cache[v as usize] ^ &cache[w as usize];
                PowFishHash::keccak(&mut cache[i as usize].0, &x.0);
            }
        }
    }

    #[inline(always)]
    pub fn keccak(out: &mut [u8], data: &[u8]) {
        let mut hasher = tiny_keccak::Keccak::v512();
        hasher.update(data);
        hasher.finalize(out);
    }

    #[inline(always)]
    fn keccak_in_place(data: &mut [u8]) {
        let mut hasher = tiny_keccak::Keccak::v512();
        hasher.update(data);
        hasher.finalize(data);
    }

    #[inline(always)]
    fn fnv1(u: u32, v: u32) -> u32 {
        u.wrapping_mul(FNV_PRIME) ^ v
    }

    #[inline(always)]
    fn fnv1_512(u: Hash512, v: Hash512) -> Hash512 {
        let mut r = Hash512::new();
        for i in 0..r.0.len() / SIZE_U32 {
            r.set_as_u32(i, PowFishHash::fnv1(u.get_as_u32(i), v.get_as_u32(i)));
        }
        r
    }

    #[inline(always)]
    pub fn calculate_dataset_item_1024(light_cache: &[Hash512], index: usize) -> Hash1024 {
        let seed0 = (index * 2) as u32;
        let seed1 = seed0 + 1;

        let mut mix0 = light_cache[(seed0 % LIGHT_CACHE_NUM_ITEMS) as usize];
        let mut mix1 = light_cache[(seed1 % LIGHT_CACHE_NUM_ITEMS) as usize];

        let mix0_seed = mix0.get_as_u32(0) ^ seed0;
        let mix1_seed = mix1.get_as_u32(0) ^ seed1;

        mix0.set_as_u32(0, mix0_seed);
        mix1.set_as_u32(0, mix1_seed);

        PowFishHash::keccak_in_place(&mut mix0.0);
        PowFishHash::keccak_in_place(&mut mix1.0);

        let num_words: u32 = (std::mem::size_of_val(&mix0) / SIZE_U32) as u32;
        for j in 0..FULL_DATASET_ITEM_PARENTS {
            let t0 = PowFishHash::fnv1(seed0 ^ j, mix0.get_as_u32((j % num_words) as usize));
            let t1 = PowFishHash::fnv1(seed1 ^ j, mix1.get_as_u32((j % num_words) as usize));
            mix0 = PowFishHash::fnv1_512(mix0, light_cache[(t0 % LIGHT_CACHE_NUM_ITEMS) as usize]);
            mix1 = PowFishHash::fnv1_512(mix1, light_cache[(t1 % LIGHT_CACHE_NUM_ITEMS) as usize]);
        }

        PowFishHash::keccak_in_place(&mut mix0.0);
        PowFishHash::keccak_in_place(&mut mix1.0);

        Hash1024::from_512s(&mix0, &mix1)
    }
}

impl PowB3Hash {
    #[inline(always)]
    pub fn new(pre_pow_hash: Hash, timestamp: u64) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&pre_pow_hash.to_le_bytes());
        hasher.update(&timestamp.to_le_bytes());
        hasher.update(&[0u8; 32]);
        Self { hasher }
    }

    #[inline(always)]
    pub fn finalize_with_nonce(mut self, nonce: u64) -> Hash {
        self.hasher.update(&nonce.to_le_bytes());
        let result = self.hasher.finalize();
        Hash::from_le_bytes(*result.as_bytes())
    }

    #[inline(always)]
    pub fn hash(input_hash: Hash) -> Hash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&input_hash.to_le_bytes());
        let result = hasher.finalize();
        Hash::from_le_bytes(*result.as_bytes())
    }
}

impl HeaderHasher {
    #[inline(always)]
    pub fn new() -> Self {
        Self(blake2b_simd::Params::new().hash_length(32).key(BLOCK_HASH_DOMAIN).to_state())
    }

    pub fn write<A: AsRef<[u8]>>(&mut self, data: A) {
        self.0.update(data.as_ref());
    }

    #[inline(always)]
    pub fn finalize(self) -> Hash {
        Hash::from_le_bytes(self.0.finalize().as_bytes().try_into().expect("this is 32 bytes"))
    }
}

pub trait Hasher {
    fn update<A: AsRef<[u8]>>(&mut self, data: A) -> &mut Self;
}

impl Hasher for HeaderHasher {
    fn update<A: AsRef<[u8]>>(&mut self, data: A) -> &mut Self {
        self.write(data);
        self
    }
}

#[cfg(test)]
mod tests {
    use crate::pow::hasher::FISHHASH_FULL_DATASET;
    use crate::pow::hasher::{PowB3Hash, PowFishHash};
    use crate::Hash;
    use std::sync::atomic::Ordering;

    #[test]
    fn test_powb3hash() {
        let timestamp: u64 = 5435345234;
        let nonce: u64 = 432432432;
        let pre_pow_hash = Hash::from_le_bytes([42; 32]);

        let hasher = PowB3Hash::new(pre_pow_hash, timestamp);
        let hash1 = hasher.finalize_with_nonce(nonce);

        let expected_hash1 = "f0afbcd9401f24cf8374418e391e1458a6df7645441dd5dc9cfe8dc9e761e67d";
        assert_eq!(format!("{:x}", hash1), expected_hash1, "PowB3Hash output changed!");
    }

    /*
    #[test]
    fn test_lazy_lookup() {
        FISHHASH_FULL_DATASET.store(true, Ordering::Relaxed);

        let timestamp: u64 = 5435345234;
        let nonce: u64 = 432432432;
        let pre_pow_hash = Hash::from_le_bytes([42; 32]);

        println!("Running same hash twice to test caching...");

        // should compute
        println!("\nFirst run:");
        let hasher1 = PowB3Hash::new(pre_pow_hash, timestamp);
        let hash1 = hasher1.finalize_with_nonce(nonce);
        let _result1 = PowFishHash::fishhashplus_kernel(&hash1);

        // should hit cache
        println!("\nSecond run (same inputs):");
        let hasher2 = PowB3Hash::new(pre_pow_hash, timestamp);
        let hash2 = hasher2.finalize_with_nonce(nonce);
        let _result2 = PowFishHash::fishhashplus_kernel(&hash2);

        println!("\nExpected: Second run should show cache hits");
    }
    */

    #[test]
    #[ignore] // this is expensive to run
    fn test_khashv2() {
        // avoid dataset building
        FISHHASH_FULL_DATASET.store(false, Ordering::Relaxed);

        let timestamp: u64 = 5435345234;
        let nonce: u64 = 432432432;
        let pre_pow_hash = Hash::from_le_bytes([42; 32]);

        // Step 1: PowB3Hash (PRE_POW_HASH || TIME || 32 zero padding || NONCE)
        let hasher = PowB3Hash::new(pre_pow_hash, timestamp);
        let hash1 = hasher.finalize_with_nonce(nonce);
        println!("hash-1 : {:x}", hash1);

        let expected_hash1 = "f0afbcd9401f24cf8374418e391e1458a6df7645441dd5dc9cfe8dc9e761e67d";
        assert_eq!(format!("{:x}", hash1), expected_hash1, "Step 1 PowB3Hash output changed!");

        // Step 2: PowFishHash
        let hash2 = PowFishHash::fishhashplus_kernel(&hash1);
        println!("hash-2 : {:x}", hash2);

        let expected_hash2 = "f57e96fd7fef6accc5daacc9eaa1d012f9145da61488d884a8fa4ce6b57288be";
        assert_eq!(format!("{:x}", hash2), expected_hash2, "Step 2 FishHash output changed!");

        // Step 3: Final B3 hash
        let hash3 = PowB3Hash::hash(hash2);
        println!("hash-3 : {:x}", hash3);

        let expected_hash3 = "71e8a7ff50f4eba67fbf00af449c12e6e74b1edfc1577b59c41c77922e546f87";
        assert_eq!(format!("{:x}", hash3), expected_hash3, "Step 3 final PowB3Hash output changed!");
    }
}
