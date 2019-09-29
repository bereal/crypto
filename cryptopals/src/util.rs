
pub mod io {
    use std::fs::File;
    use std::io::{ BufReader, BufRead };


    pub fn read_file_lines(name: &str) -> impl Iterator<Item=String> {
        BufReader::new(File::open(name).unwrap())
            .lines()
            .filter_map(|line| line.ok())
    }

    pub fn read_file_base64(name: &str) -> Vec<u8> {
        let content = read_file_lines(name).fold(String::new(), |acc, v| acc + &v);
        base64::decode(content.as_str()).unwrap()
    }

}

pub mod crypto {
    use aes::Aes128;
    use aes::block_cipher_trait::generic_array::GenericArray;
    use aes::block_cipher_trait::BlockCipher;

    pub fn xor(v1: &Vec<u8>, v2: &Vec<u8>) -> Vec<u8> {
        v1.iter().zip(v2.iter().cycle()).map(|(&x, &y)| x^y).collect()
    }

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

    pub fn decrypt_aes(cipher: &Vec<u8>, key: &Vec<u8>) -> Vec<u8> {
        let key_data = GenericArray::from_slice(key);
        let aes = Aes128::new(key_data);
        let mut plaintext = Vec::new();

        cipher.chunks(16).for_each(|block| {
            let mut b = GenericArray::clone_from_slice(block);
            aes.decrypt_block(&mut b);
            let mut vec = b.to_vec();
            plaintext.append(&mut vec);
        });
        return plaintext;
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