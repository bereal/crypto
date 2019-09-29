use std::collections::HashMap;
use lazy_static::{lazy_static};
use ordered_float::{OrderedFloat};
use maplit;

use crate::util::crypto;

lazy_static! {
    static ref ENGLISH_FREQ: HashMap<char, f64> = maplit::hashmap! {
        ' ' => 0.1223,
        'e' => 0.1027,
        't' => 0.0752,
        'a' => 0.0653,
        'o' => 0.0616,
        'n' => 0.0571,
        'i' => 0.0567,
        's' => 0.0572,
        'r' => 0.0499,
        'h' => 0.4979,
        'l' => 0.0332,
        'd' => 0.0328,
        'u' => 0.0228,
        'c' => 0.0223,
        'm' => 0.0203,
        'f' => 0.0198,
        'w' => 0.0170,
        'g' => 0.0162,
        'p' => 0.1504,
        'y' => 0.1428,
        'b' => 0.1259,
        'v' => 0.0796,
        'k' => 0.0561,
        'x' => 0.0141,
        'j' => 0.0098,
        'q' => 0.0084,
        'z' => 0.0051,
    };
}

fn frequencies(s: &String) -> HashMap<char, f64> {
    let mut m: HashMap<char, f64> = HashMap::new();
    for c in s.chars() {
        *m.entry(c).or_insert(0.) += 1.;
    }

    let len = s.len() as f64;
    for v in m.values_mut() {
        *v /= len;
    }

    return m;
}

fn freq_distance(s: &String) -> f64 {
    let freq = frequencies(&s);

    ENGLISH_FREQ.iter()
        .map(|(&c, &v)| (v - freq.get(&c).unwrap_or(&0.).powf(2.)))
        .fold(0., |acc, x| acc+x)
}

pub struct XorSolution {
    key: u8,
    message: String,
    score: f64,
}

// Attempt to decrypt a single-byte-xor encrypted message
pub fn crack_xor(cipher: &Vec<u8>) -> Option<XorSolution> {
    (0..255).filter_map(|key| {
        String::from_utf8(crypto::xor(cipher, &vec![key])).map(|message| {
            let score = freq_distance(&message);
            XorSolution{ key, message, score }
        }).ok()
    }).min_by_key(|s| OrderedFloat(s.score))
}

pub fn find_and_crack_xor<T: Iterator<Item=String>>(lines: T) -> Option<XorSolution> {
    lines.filter_map(|line| crack_xor(&hex::decode(line).unwrap()))
        .min_by_key(|s| OrderedFloat(s.score))
}

fn transpose_blocks(v: &Vec<u8>, size: usize) -> Vec<Vec<u8>> {
    let mut blocks: Vec<Vec<u8>> = (0..size).map(|_| Vec::with_capacity(v.len() / size)).collect();
    for chunk in v.chunks(size) {
        for (i, &b) in chunk.iter().enumerate() {
            blocks[i].push(b);
        }
    }

    return blocks;
}

fn guess_key_length(v: &Vec<u8>) -> usize {
    (2..40).min_by_key(|i| crypto::coincidence(v, *i)).unwrap()
}

pub fn decrypt_vigenere(cipher: &Vec<u8>, key_size: usize) -> Option<String> {
    let blocks = transpose_blocks(cipher, key_size);
    let key = blocks.iter().filter_map(crack_xor).map(|s| s.key).collect();
    String::from_utf8(crypto::xor(cipher, &key)).ok()
}

#[cfg(test)]
mod tests {
    use hex::FromHex;
    use crate::util::io;
    use crate::util::crypto;
    use super::*;

    #[test]
    fn challenge_1_1() {
        let input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        let expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
        let bytes = Vec::from_hex(input).unwrap();
        assert_eq!(expected, base64::encode(&bytes));
    }

    #[test]
    fn challenge_1_2() {
        use crate::util::crypto;

        let a = Vec::from_hex("1c0111001f010100061a024b53535009181c").unwrap();
        let b = Vec::from_hex("686974207468652062756c6c277320657965").unwrap();
        let c = crypto::xor(&a, &b);
        let expected = "746865206b696420646f6e277420706c6179";
        assert_eq!(expected, hex::encode(&c));
    }

    #[test]
    fn challenge_1_3() {
        let cipher = hex::decode("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736").unwrap();
        match crack_xor(&cipher) {
            Some(sol) => assert_eq!(sol.message, "Cooking MC's like a pound of bacon"),
            None => assert!(false),
        }
    }

    #[test]
    fn challenge_1_4() {
        let solution = find_and_crack_xor(io::read_file_lines("4.txt")).unwrap();
        assert_eq!(solution.message, "Now that the party is jumping\n");
    }

    #[test]
    fn challenge_1_5() {
        let plain: Vec<u8> = "Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal".bytes().collect();
        let key: Vec<u8> = "ICE".bytes().collect();
        let cipher = crypto::xor(&plain, &key);
        assert_eq!(hex::encode(cipher),
            "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f");
    }

    #[test]
    fn test_transpose() {
        let input = "ABCDEFGHIJK";
        let output = transpose_blocks(&input.bytes().collect(), 3);
        let as_str: Vec<String> = output.iter().map(|v| v.iter().map(|&c| c as char).collect()).collect();
        assert_eq!(as_str, ["ADGJ", "BEHK", "CFI"]);
    }

    #[test]
    fn challenge_1_6() {
        let data = io::read_file_base64("6.txt");
        let key_length = guess_key_length(&data);
        assert_eq!(key_length, 29);

        let solution = decrypt_vigenere(&data, key_length);
        assert!(solution.unwrap().starts_with("I'm back and I'm ringin'"));
    }

    #[test]
    fn challenge_1_7() {
        let data = io::read_file_base64("7.txt");
        let message = crypto::decrypt_aes(&data, &Vec::from("YELLOW SUBMARINE"));
        assert!(String::from_utf8(message).unwrap().starts_with("I'm back and I'm ringin'"));
    }


}