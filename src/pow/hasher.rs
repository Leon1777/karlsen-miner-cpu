#![allow(clippy::unreadable_literal)]
use crate::Hash;
use blake2b_simd::State as Blake2bState;
use log::info;
use std::ops::BitXor;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tiny_keccak::Hasher as OtherHasher;

const BLOCK_HASH_DOMAIN: &[u8] = b"BlockHash";

// fishhash const
const FNV_PRIME: u32 = 0x01000193;
const FULL_DATASET_ITEM_PARENTS: u32 = 512;
const NUM_DATASET_ACCESSES: u32 = 32;
const LIGHT_CACHE_ROUNDS: i32 = 3;
const LIGHT_CACHE_NUM_ITEMS: u32 = 1179641;
const FULL_DATASET_NUM_ITEMS: u32 = 37748717;

#[rustfmt::skip]
const SEED: [u8; 32] = [
    0xeb, 0x01, 0x63, 0xae, 0xf2, 0xab, 0x1c, 0x5a, 
    0x66, 0x31, 0x0c, 0x1c, 0x14, 0xd6, 0x0f, 0x42, 
    0x55, 0xa9, 0xb3, 0x9b, 0x0e, 0xdf, 0x26, 0x53, 
    0x98, 0x44, 0xf1, 0x17, 0xad, 0x67, 0x21, 0x19,
];

const SIZE_U32: usize = std::mem::size_of::<u32>();
const SIZE_U64: usize = std::mem::size_of::<u64>();

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

pub struct FishHashContext {
    light_cache: Box<[Hash512]>,
    full_dataset: Option<Box<[Hash1024]>>,
}

impl FishHashContext {
    /// Create a new cache context for the FishHash algorithm. Light cache is ~75MB and full
    /// cache is ~4.6GB.
    ///
    /// # Arguments
    ///
    /// * `full` - whether to build the full dataset or just the light cache
    /// * `seed` - the seed to use for the light cache. If None, the default seed is used.
    ///   The FishHash specification is to always use the default seed but the option is
    ///   still provided for potential future use cases like rotating the cache.
    pub fn new(full: bool, seed: Option<[u8; 32]>) -> Self {
        // Vec into boxed sliced, because you can't allocate an array directly on
        // the heap in rust
        // https://stackoverflow.com/questions/25805174/creating-a-fixed-size-array-on-heap-in-rust/68122278#68122278
        let mut light_cache = vec![Hash512::new(); LIGHT_CACHE_NUM_ITEMS as usize].into_boxed_slice();

        build_light_cache(&mut light_cache, seed.unwrap_or(SEED));

        let full_dataset = if full {
            let mut dataset = vec![Hash1024::new(); FULL_DATASET_NUM_ITEMS as usize].into_boxed_slice();
            Self::prebuild_full_dataset(&mut dataset, &light_cache, num_cpus::get());
            Some(dataset)
        } else {
            None
        };

        FishHashContext { light_cache, full_dataset }
    }

    pub fn prebuild_full_dataset(full_dataset: &mut Box<[Hash1024]>, light_cache: &[Hash512], num_threads: usize) {
        info!("prebuilding dataset using {} threads", num_threads);
        let start = std::time::Instant::now();

        let total_items = full_dataset.len();
        let progress = Arc::new(AtomicUsize::new(0));

        std::thread::scope(|scope| {
            let batch_size = full_dataset.len() / num_threads;
            let mut threads = Vec::with_capacity(num_threads);

            for (index, chunk) in full_dataset.chunks_mut(batch_size).enumerate() {
                let start = index * batch_size;
                let progress = Arc::clone(&progress);

                let thread_handle = scope.spawn(move || {
                    build_dataset_segment(chunk, light_cache, start, progress, total_items);
                });

                threads.push(thread_handle);
            }

            for handle in threads {
                handle.join().unwrap();
            }
        });

        info!("prebuilding full dataset done in {:.1}s", start.elapsed().as_secs_f64());
    }
}

fn build_dataset_segment(
    dataset_slice: &mut [Hash1024],
    light_cache: &[Hash512],
    start: usize,
    progress: Arc<AtomicUsize>,
    total_items: usize,
) {
    for (index, item) in dataset_slice.iter_mut().enumerate() {
        *item = calculate_dataset_item_1024(light_cache, start + index);

        let done = progress.fetch_add(1, Ordering::Relaxed) + 1;
        if done.is_multiple_of(4_000_000) {
            let percent = done * 100 / total_items;
            info!("prebuilding full dataset: {}% ({}/{})", percent, done, total_items);
        }
    }
}

#[inline(always)]
fn fnv1(u: u32, v: u32) -> u32 {
    u.wrapping_mul(FNV_PRIME) ^ v
}

#[inline(always)]
fn fnv1_512(u: Hash512, v: Hash512) -> Hash512 {
    let mut r = Hash512::new();
    for i in 0..r.0.len() / SIZE_U32 {
        r.set_as_u32(i, fnv1(u.get_as_u32(i), v.get_as_u32(i)));
    }
    r
}

#[inline]
pub fn calculate_dataset_item_1024(light_cache: &[Hash512], index: usize) -> Hash1024 {
    let seed0 = (index * 2) as u32;
    let seed1 = seed0 + 1;

    let mut mix0 = light_cache[(seed0 % LIGHT_CACHE_NUM_ITEMS) as usize];
    let mut mix1 = light_cache[(seed1 % LIGHT_CACHE_NUM_ITEMS) as usize];

    let mix0_seed = mix0.get_as_u32(0) ^ seed0;
    let mix1_seed = mix1.get_as_u32(0) ^ seed1;

    mix0.set_as_u32(0, mix0_seed);
    mix1.set_as_u32(0, mix1_seed);

    keccak_in_place(&mut mix0.0);
    keccak_in_place(&mut mix1.0);

    let num_words: u32 = (std::mem::size_of_val(&mix0) / SIZE_U32) as u32;
    for j in 0..FULL_DATASET_ITEM_PARENTS {
        let t0 = fnv1(seed0 ^ j, mix0.get_as_u32((j % num_words) as usize));
        let t1 = fnv1(seed1 ^ j, mix1.get_as_u32((j % num_words) as usize));
        mix0 = fnv1_512(mix0, light_cache[(t0 % LIGHT_CACHE_NUM_ITEMS) as usize]);
        mix1 = fnv1_512(mix1, light_cache[(t1 % LIGHT_CACHE_NUM_ITEMS) as usize]);
    }

    keccak_in_place(&mut mix0.0);
    keccak_in_place(&mut mix1.0);

    Hash1024::from_512s(&mix0, &mix1)
}

#[derive(Clone)]
pub struct PowFishHash;

impl PowFishHash {
    pub fn fishhashplus_kernel(seed: &Hash, context: &FishHashContext) -> Hash {
        let seed_hash512 = Hash512::from_hash(seed);
        let mut mix = Hash1024::from_512s(&seed_hash512, &seed_hash512);

        for i in 0..NUM_DATASET_ACCESSES {
            // Calculate new fetching indexes
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

            let fetch0 = lookup(context, p0 as usize);
            let mut fetch1 = lookup(context, p1 as usize);
            let mut fetch2 = lookup(context, p2 as usize);

            // Modify fetch1 and fetch2
            for j in 0..32 {
                fetch1.set_as_u32(j, fnv1(mix.get_as_u32(j), fetch1.get_as_u32(j)));
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
            let h1 = fnv1(mix.get_as_u32(i), mix.get_as_u32(i + 1));
            let h2 = fnv1(h1, mix.get_as_u32(i + 2));
            let h3 = fnv1(h2, mix.get_as_u32(i + 3));
            mix_hash.set_as_u32(i / 4, h3);
        }

        Hash::from_le_bytes(mix_hash.0)
    }
}

#[inline]
fn lookup(context: &FishHashContext, index: usize) -> Hash1024 {
    // removed lazy lookup for now if item.get_as_u64(0) == 0 {
    match &context.full_dataset {
        Some(dataset) => dataset[index],
        None => calculate_dataset_item_1024(&context.light_cache, index),
    }
}

fn build_light_cache(cache: &mut [Hash512], seed: [u8; 32]) {
    info!("light cache processing started");
    let mut item: Hash512 = Hash512::new();
    keccak(&mut item.0, &seed);
    cache[0] = item;

    for cache_item in cache.iter_mut().take(LIGHT_CACHE_NUM_ITEMS as usize).skip(1) {
        keccak_in_place(&mut item.0);
        *cache_item = item;
    }

    for _ in 0..LIGHT_CACHE_ROUNDS {
        for i in 0..LIGHT_CACHE_NUM_ITEMS {
            // First index: 4 first bytes of the item as little-endian integer
            let t: u32 = cache[i as usize].get_as_u32(0);
            let v: u32 = t % LIGHT_CACHE_NUM_ITEMS;

            // Second index
            let w: u32 = (LIGHT_CACHE_NUM_ITEMS.wrapping_add(i.wrapping_sub(1))) % LIGHT_CACHE_NUM_ITEMS;

            let x = &cache[v as usize] ^ &cache[w as usize];
            keccak(&mut cache[i as usize].0, &x.0);
        }
    }
    info!("light_cache[10] : {:?}", cache[10]);
    info!("light_cache[42] : {:?}", cache[42]);
    info!("light cache processing done");
}

#[inline(always)]
pub fn keccak(out: &mut [u8], data: &[u8]) {
    let mut hasher = tiny_keccak::Keccak::v512();
    hasher.update(data);
    hasher.finalize(out);
}

#[inline(always)]
pub fn keccak_in_place(data: &mut [u8]) {
    let mut hasher = tiny_keccak::Keccak::v512();
    hasher.update(data);
    hasher.finalize(data);
}

#[derive(Clone)]
pub struct PowB3Hash {
    pub hasher: blake3::Hasher,
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

#[derive(Clone)]
pub struct HeaderHasher(Blake2bState);

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
    use crate::pow::hasher::{FishHashContext, PowB3Hash, PowFishHash};
    use crate::Hash;

    #[test]
    fn test_powb3hash() {
        let timestamp: u64 = 5435345234;
        let nonce: u64 = 432432432;
        let pre_pow_hash = Hash::from_le_bytes([42; 32]);

        let hasher = PowB3Hash::new(pre_pow_hash, timestamp);
        let hash1 = hasher.finalize_with_nonce(nonce);

        #[rustfmt::skip]
        let expected_hash1 = [
            0xf0, 0xaf, 0xbc, 0xd9, 0x40, 0x1f, 0x24, 0xcf,
            0x83, 0x74, 0x41, 0x8e, 0x39, 0x1e, 0x14, 0x58,
            0xa6, 0xdf, 0x76, 0x45, 0x44, 0x1d, 0xd5, 0xdc,
            0x9c, 0xfe, 0x8d, 0xc9, 0xe7, 0x61, 0xe6, 0x7d
        ];

        println!("hash1: {:?}", hash1.to_le_bytes());
        assert_eq!(hash1.to_le_bytes(), expected_hash1, "PowB3Hash output changed!");
    }

    #[test]
    fn test_powfishhash() {
        let context = FishHashContext::new(false, None);
        // B3 hash as input to PowFishHash
        #[rustfmt::skip]
        let input_hash = Hash::from_le_bytes([
            0xf0, 0xaf, 0xbc, 0xd9, 0x40, 0x1f, 0x24, 0xcf,
            0x83, 0x74, 0x41, 0x8e, 0x39, 0x1e, 0x14, 0x58,
            0xa6, 0xdf, 0x76, 0x45, 0x44, 0x1d, 0xd5, 0xdc,
            0x9c, 0xfe, 0x8d, 0xc9, 0xe7, 0x61, 0xe6, 0x7d,
        ]);

        let fishhash_output = PowFishHash::fishhashplus_kernel(&input_hash, &context);

        #[rustfmt::skip]
        let expected_fishhash = [
            0xf5, 0x7e, 0x96, 0xfd, 0x7f, 0xef, 0x6a, 0xcc,
            0xc5, 0xda, 0xac, 0xc9, 0xea, 0xa1, 0xd0, 0x12,
            0xf9, 0x14, 0x5d, 0xa6, 0x14, 0x88, 0xd8, 0x84,
            0xa8, 0xfa, 0x4c, 0xe6, 0xb5, 0x72, 0x88, 0xbe
        ];

        println!("fishhash output: {:?}", fishhash_output.to_le_bytes());
        assert_eq!(fishhash_output.to_le_bytes(), expected_fishhash, "FishHash output changed!");
    }

    #[test]
    #[ignore] // this is expensive to run
    fn test_khashv2() {
        // avoid dataset building
        let context = FishHashContext::new(false, None);

        let timestamp: u64 = 5435345234;
        let nonce: u64 = 432432432;
        let pre_pow_hash = Hash::from_le_bytes([42; 32]);

        // Step 1: PowB3Hash (PRE_POW_HASH || TIME || 32 zero padding || NONCE)
        let hasher = PowB3Hash::new(pre_pow_hash, timestamp);
        let hash1 = hasher.finalize_with_nonce(nonce);

        #[rustfmt::skip]
        let expected_hash1 = [
            0xf0, 0xaf, 0xbc, 0xd9, 0x40, 0x1f, 0x24, 0xcf,
            0x83, 0x74, 0x41, 0x8e, 0x39, 0x1e, 0x14, 0x58,
            0xa6, 0xdf, 0x76, 0x45, 0x44, 0x1d, 0xd5, 0xdc,
            0x9c, 0xfe, 0x8d, 0xc9, 0xe7, 0x61, 0xe6, 0x7d
        ];

        println!("hash1: {:?}", hash1.to_le_bytes());
        assert_eq!(hash1.to_le_bytes(), expected_hash1, "Step 1 PowB3Hash output changed!");

        // Step 2: PowFishHash
        let hash2 = PowFishHash::fishhashplus_kernel(&hash1, &context);

        #[rustfmt::skip]
        let expected_hash2 = [
            0xf5, 0x7e, 0x96, 0xfd, 0x7f, 0xef, 0x6a, 0xcc,
            0xc5, 0xda, 0xac, 0xc9, 0xea, 0xa1, 0xd0, 0x12,
            0xf9, 0x14, 0x5d, 0xa6, 0x14, 0x88, 0xd8, 0x84,
            0xa8, 0xfa, 0x4c, 0xe6, 0xb5, 0x72, 0x88, 0xbe
        ];

        println!("hash2: {:?}", hash2.to_le_bytes());
        assert_eq!(hash2.to_le_bytes(), expected_hash2, "Step 2 FishHash output changed!");

        // Step 3: Final B3 hash
        let hash3 = PowB3Hash::hash(hash2);

        #[rustfmt::skip]
        let expected_hash3 = [
            0x71, 0xe8, 0xa7, 0xff, 0x50, 0xf4, 0xeb, 0xa6,
            0x7f, 0xbf, 0x00, 0xaf, 0x44, 0x9c, 0x12, 0xe6,
            0xe7, 0x4b, 0x1e, 0xdf, 0xc1, 0x57, 0x7b, 0x59,
            0xc4, 0x1c, 0x77, 0x92, 0x2e, 0x54, 0x6f, 0x87
        ];

        println!("hash3: {:?}", hash3.to_le_bytes());
        assert_eq!(hash3.to_le_bytes(), expected_hash3, "Step 3 final PowB3Hash output changed!");
    }
}
