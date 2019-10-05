pub fn xor_in_place(to: &mut [u8], from: &[u8]) {
    let from_len = from.len();
    for i in 0..to.len() {
        to[i] ^= from[i % from_len];
    }
}

pub fn xor(v1: &Vec<u8>, v2: &Vec<u8>) -> Vec<u8> {
    v1.iter().zip(v2.iter().cycle()).map(|(&x, &y)| x^y).collect()
}

pub mod metrics {
    pub fn humming_distance(v1: &Vec<u8>, v2: &Vec<u8>) -> usize {
        v1.iter().zip(v2.iter())
            .map(|(&x, &y)| x^y)
            .map(|b| b.count_ones())
            .fold(0 as usize, |a, b| a + (b as usize))
    }

    pub fn coincidence(v: &Vec<u8>, size: usize) -> usize {
        let mut chunks = v.chunks(size);
        let base = Vec::from(chunks.next().unwrap());

        let mut result = 0;

        loop {
            match chunks.next() {
                Some(s) => result += humming_distance(&base, &Vec::from(s)),
                None => break,
            }
        }

        return result;
    }

    #[cfg(test)]
    mod test {
        use super::*;

        #[test]
        fn test_humming() {
            let v1: Vec<u8> = "this is a test".bytes().collect();
            let v2: Vec<u8> = "wokka wokka!!!".bytes().collect();
            assert_eq!(humming_distance(&v1, &v2), 37);
        }
    }
}


pub mod pkcs7 {
    pub fn pad(data: &mut Vec<u8>, block_size: usize) {
        let len = data.len();
        let rem = len % block_size;
        let pad = block_size - rem;
        data.resize(len + pad, pad as u8);
    }

    pub fn unpad(data: &mut Vec<u8>) {
        let last = data[data.len() - 1];
        data.resize(data.len() - (last as usize), 0);
    }

    #[cfg(test)]
    pub mod tests {
        #[test]
        fn pad_empty() {
            let mut v = vec![];
            super::pad(&mut v, 4);
            assert_eq!(v, [4, 4, 4, 4]);
        }

        #[test]
        fn pad_normal() {
            let mut v = vec![1, 2, 3];
            super::pad(&mut v, 5);
            assert_eq!(v, [1, 2, 3, 2, 2]);
        }

        #[test]
        fn pad_longer() {
            let mut v = vec![1, 2, 3];
            super::pad(&mut v, 2);
            assert_eq!(v, [1, 2, 3, 1]);
        }

        #[test]
        fn pad_block_size() {
            let mut v = vec![1, 2, 3, 4];
            super::pad(&mut v, 4);
            assert_eq!(v, [1, 2, 3, 4, 4, 4, 4, 4]);
        }

        #[test]
        fn unpad_empty() {
            let mut v = vec![4, 4, 4, 4];
            super::unpad(&mut v);
            assert_eq!(v, []);
        }

        #[test]
        fn unpad_normal() {
            let mut v = vec![1, 2, 3, 2, 2];
            super::unpad(&mut v);
            assert_eq!(v, [1, 2, 3]);
        }
    }
}

pub mod block {
    use aes::block_cipher_trait::BlockCipher;
    use aes::block_cipher_trait::generic_array::GenericArray;
    use typenum::marker_traits::Unsigned;

    pub trait CipherMode {
        fn block_size() -> usize;
        fn encrypt_block(self: &mut Self, data: &mut [u8]);
        fn decrypt_block(self: &mut Self, data: &mut [u8]);

        fn encrypt(self: &mut Self, data: &mut Vec<u8>) {
            let block_size = Self::block_size();
            super::pkcs7::pad(data, block_size);

            for chunk in data.chunks_mut(Self::block_size()) {
                self.encrypt_block(chunk);
            }
        }

        fn decrypt(self: &mut Self, data: &mut Vec<u8>) {
            for chunk in data.chunks_mut(Self::block_size()) {
                self.decrypt_block(chunk);
            }

            super::pkcs7::unpad(data);
        }
    }

    pub struct ECBMode<C: BlockCipher> {
        cipher: C,
    }

    impl<C: BlockCipher> ECBMode<C> {
        pub fn new(key: &[u8]) -> Self {
            let key_arr = GenericArray::from_slice(key);
            return ECBMode{ cipher: C::new(key_arr) };
        }
    }

    impl<C: BlockCipher> CipherMode for ECBMode<C> {
        fn block_size() -> usize {
            C::BlockSize::to_usize()
        }

        fn encrypt_block(self: &mut Self, block: &mut [u8]) {
            let block_arr = GenericArray::from_mut_slice(block);
            self.cipher.encrypt_block(block_arr);
        }

        fn decrypt_block(self: &mut Self, block: &mut [u8]) {
            let block_arr = GenericArray::from_mut_slice(block);
            self.cipher.decrypt_block(block_arr);
        }
    }

    pub struct CBCMode<C: BlockCipher> {
        ecb: ECBMode<C>,
        masks: [Vec<u8>; 2],
        mask_i: usize,
    }

    impl <C: BlockCipher> CBCMode<C> {
        pub fn new(key: &[u8], iv: &[u8]) -> Self {
            CBCMode{
                ecb: ECBMode::new(key),
                masks: [Vec::from(iv), vec![0; C::BlockSize::to_usize()]],
                mask_i: 0,
            }
        }
    }

    impl <C: BlockCipher> CipherMode for CBCMode<C> {
        fn block_size() -> usize {
            C::BlockSize::to_usize()
        }

        fn encrypt_block(self: &mut Self, block: &mut [u8]) {
            super::xor_in_place(block, self.masks[0].as_slice());
            self.ecb.encrypt_block(block);
            self.masks[0].clone_from_slice(block);
        }

        fn decrypt_block(self: &mut Self, block: &mut [u8]) {
            let next_mask_i = 1 - self.mask_i;
            self.masks[next_mask_i].clone_from_slice(block);
            self.ecb.decrypt_block(block);
            super::xor_in_place(block, self.masks[self.mask_i].as_slice());
            self.mask_i = next_mask_i;
        }
    }

    #[cfg(test)]
    pub mod tests {
        use super::{CipherMode, CBCMode};

        #[test]
        pub fn test_cbc() {
            let mut data = vec![123; 33];
            let key = vec![22; 16];
            let iv = vec![33; 16];

            super::CBCMode::<aes::Aes128>::new(key.as_slice(), iv.as_slice()).encrypt(&mut data);
            assert_eq!(data.len(), 48);

            super::CBCMode::<aes::Aes128>::new(key.as_slice(), iv.as_slice()).decrypt(&mut data);
            assert_eq!(data, vec![123; 33]);
        }
    }
}