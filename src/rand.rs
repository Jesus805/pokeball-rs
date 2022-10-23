pub trait Random {
    fn gen_random(&self) -> usize;
}

pub fn generate_nonce<T: Random>(randomizer: &T, nonce: &mut [u8; 16]) {
    for element in nonce {
        *element = (randomizer.gen_random() & 0xff) as u8;
    }
}
