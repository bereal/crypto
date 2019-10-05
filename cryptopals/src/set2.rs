
#[cfg(test)]
mod test {
    use crate::util::io::read_file_base64;
    use crate::crypto::pkcs7;
    use crate::crypto::block::{CBCMode, CipherMode};

    #[test()]
    fn test_challenge_9() {
        let mut vec: Vec<u8> = b"YELLOW SUBMARINE".to_vec();
        pkcs7::pad(&mut vec, 20);
        assert_eq!(vec, b"YELLOW SUBMARINE\x04\x04\x04\x04");
    }

    #[test()]
    fn test_challenge_10() {
        let mut data = read_file_base64("10.txt");
        let key = "YELLOW SUBMARINE".as_bytes();
        let iv = vec![0; 16];

        CBCMode::<aes::Aes128>::new(key, iv.as_slice()).decrypt(&mut data);
        let text = String::from_utf8(data).unwrap();
        assert!(text.starts_with("I'm back and I'm ringin"));
    }
}