use blake2b_rs::{Blake2b, Blake2bBuilder};

const CKB_HASH_PERSONALIZATION: &[u8] = b"ckb-default-hash";
const BLANK_HASH: [u8; 32] = [
    68, 244, 198, 151, 68, 213, 248, 197, 93, 100, 32, 98, 148, 157, 202, 228, 155, 196, 231, 239,
    67, 211, 136, 197, 161, 47, 66, 181, 99, 61, 22, 62,
];

#[macro_export]
macro_rules! blake2b {
    ($($field: expr), *) => {{
        let mut res = [0u8; 32];
        let mut blake2b = utils::new_blake2b();

        $( blake2b.update($field.as_ref()); )*

        blake2b.finalize(&mut res);
        res
    }}
}

pub fn new_blake2b() -> Blake2b {
    Blake2bBuilder::new(32)
        .personal(CKB_HASH_PERSONALIZATION)
        .build()
}

fn inner_blake2b_256<T: AsRef<[u8]>>(s: T) -> [u8; 32] {
    let mut result = [0u8; 32];
    let mut blake2b = new_blake2b();
    blake2b.update(s.as_ref());
    blake2b.finalize(&mut result);
    result
}

pub fn blake2b_256<T: AsRef<[u8]>>(s: T) -> [u8; 32] {
    if s.as_ref().is_empty() {
        return BLANK_HASH;
    }
    inner_blake2b_256(s)
}

pub fn blake2b_vec<T: AsRef<[u8]> + Ord>(s: &mut [T]) -> [u8; 32] {
    s.sort();
    let mut res = [0u8; 32];
    let mut blake2b = new_blake2b();

    for i in s.iter_mut() {
        blake2b.update(i.as_ref());
    }

    blake2b.finalize(&mut res);
    res
}
