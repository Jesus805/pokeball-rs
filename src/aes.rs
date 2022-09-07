pub trait AesContext {
    fn pgp_aes_encrypt(&self, inp: &[u8; 16], out: &mut [u8; 16]);

    fn aes_set_key(&self, key: &[u8; 16]);
}

pub struct DefaultAesContext {

}

impl AesContext for DefaultAesContext
{
    fn pgp_aes_encrypt(&self, inp: &[u8; 16], out: &mut [u8; 16])
    {

    }

    fn aes_set_key(&self, key: &[u8; 16])
    {

    }
}
