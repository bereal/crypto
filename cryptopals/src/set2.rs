
use rand::random;
use aes;
use crate::crypto::block::{CBCMode, ECBMode, CipherMode};
use crate::crypto::xor;

fn generate_block(size: usize) -> Vec<u8> {
    (0..size).map(|_| { random::<u8>() }).collect()
}

struct Oracle {
    key: Vec<u8>,
    prefix: Vec<u8>,
    suffix: Vec<u8>,
}

macro_rules! create_function {
    ($func_name:ident) => {
        fn $func_name() {
            print!("{:?}()", stringify!($func_name))
        }
    };
}

create_function!(xyz);


impl Oracle {
    // pub fn generate() -> Vec<u8> {

    // }
}

fn generate_challenge(data: &mut Vec<u8>) -> bool {
    xyz();
    let key = generate_block(16);
    if random::<bool>() {
        let iv = generate_block(16);
        CBCMode::<aes::Aes128>::new(key.as_slice(), iv.as_slice()).encrypt(data);
        return true;
    }
    ECBMode::<aes::Aes128>::new(key.as_slice()).encrypt(data);
    false
}

fn ecb_oracle(cipher: fn(&mut Vec<u8>)) -> bool {
    let mut data = vec![b'a'; 256];
    cipher(&mut data);

    //let vec = data.chunks(16).fold(vec![0; 16], |v1, v2| { xor(&v1, &v2) });
    //let vec = data.chunks(16).pa
    let mut count = 0;
    for i in (0..256-32).step_by(16) {
        let vec1 = data[i..i+16];
    }
}

#[cfg(test)]
mod test {
    use crate::util::io::read_file_base64;
    use crate::crypto::pkcs7;
    use crate::crypto::block::{CBCMode, CipherMode};

    #[test]
    fn test_challenge_9() {
        let mut vec: Vec<u8> = b"YELLOW SUBMARINE".to_vec();
        pkcs7::pad(&mut vec, 20);
        assert_eq!(vec, b"YELLOW SUBMARINE\x04\x04\x04\x04");
    }

    #[test]
    fn test_challenge_10() {
        let mut data = read_file_base64("10.txt");
        let key = "YELLOW SUBMARINE".as_bytes();
        let iv = vec![0; 16];

        CBCMode::<aes::Aes128>::new(key, iv.as_slice()).decrypt(&mut data);
        let text = String::from_utf8(data).unwrap();
        assert!(text.starts_with("I'm back and I'm ringin"));
    }

    #[test]
    fn test_challenge_11() {
        for i in (1..100) {

        }
    }
}