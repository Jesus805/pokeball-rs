pub mod default;

pub trait AesContext {
    fn pgp_aes_encrypt(&self, inp: &[u8; 16], out: &mut [u8; 16]);

    fn aes_set_key(&mut self, key: &[u8; 16]);
}
