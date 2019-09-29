#![allow(dead_code)]

// use std::io::prelude::*;
use hex::{FromHex};
use base64;
use maplit;
use ordered_float::{OrderedFloat};
use lazy_static::{lazy_static};
use std::fs::File;
use std::io::{ BufReader, BufRead };
use std::collections::HashMap;
use aes::Aes128;
use aes::block_cipher_trait::generic_array::GenericArray;
use aes::block_cipher_trait::BlockCipher;

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

fn xor(v1: &Vec<u8>, v2: &Vec<u8>) -> Vec<u8> {
    v1.iter().zip(v2.iter().cycle()).map(|(&x, &y)| x^y).collect()
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

struct XorSolution {
    key: u8,
    message: String,
    score: f64,
}

// Attempt to decrypt a single-byte-xor encrypted message
fn decrypt_xor(cipher: &Vec<u8>) -> Option<XorSolution> {
    (0..255).filter_map(|key| {
        String::from_utf8(xor(cipher, &vec![key])).map(|message| {
            let score = freq_distance(&message);
            XorSolution{ key, message, score }
        }).ok()
    }).min_by_key(|s| OrderedFloat(s.score))
}

fn find_and_decrypt_xor<T: Iterator<Item=String>>(lines: T) -> Option<XorSolution> {
    lines.filter_map(|line| decrypt_xor(&hex::decode(line).unwrap()))
        .min_by_key(|s| OrderedFloat(s.score))
}

fn decrypt_vigenere(cipher: &Vec<u8>, key_size: usize) -> Option<String> {
    let blocks = transpose_blocks(cipher, key_size);
    let key = blocks.iter().filter_map(decrypt_xor).map(|s| s.key).collect();
    String::from_utf8(xor(cipher, &key)).ok()
}

fn humming_distance(v1: &Vec<u8>, v2: &Vec<u8>) -> usize {
    v1.iter().zip(v2.iter())
        .map(|(&x, &y)| x^y)
        .map(|b| b.count_ones())
        .fold(0 as usize, |a, b| a + (b as usize))
}

fn guess_key_length(v: &Vec<u8>) -> usize {
    (2..40).min_by_key(|i| coincidence(v, *i)).unwrap()
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

fn coincidence(v: &Vec<u8>, size: usize) -> usize {
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

fn decrypt_aes(cipher: &Vec<u8>, key: &Vec<u8>) -> Vec<u8> {
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

fn read_file_lines(name: &str) -> impl Iterator<Item=String> {
    BufReader::new(File::open(name).unwrap())
        .lines()
        .filter_map(|line| line.ok())
}

fn read_file_base64(name: &str) -> Vec<u8> {
    let content = read_file_lines(name).fold(String::new(), |acc, v| acc + &v);
    base64::decode(content.as_str()).unwrap()
}

#[cfg(test)]
mod tests {
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
        let a = Vec::from_hex("1c0111001f010100061a024b53535009181c").unwrap();
        let b = Vec::from_hex("686974207468652062756c6c277320657965").unwrap();
        let c = xor(&a, &b);
        let expected = "746865206b696420646f6e277420706c6179";
        assert_eq!(expected, hex::encode(&c));
    }

    #[test]
    fn challenge_1_3() {
        let cipher = hex::decode("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736").unwrap();
        match decrypt_xor(&cipher) {
            Some(sol) => assert_eq!(sol.message, "Cooking MC's like a pound of bacon"),
            None => assert!(false),
        }
    }

    #[test]
    fn challenge_1_4() {
        let solution = find_and_decrypt_xor(read_file_lines("4.txt")).unwrap();
        assert_eq!(solution.message, "Now that the party is jumping\n");
    }

    #[test]
    fn challenge_1_5() {
        let plain: Vec<u8> = "Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal".bytes().collect();
        let key: Vec<u8> = "ICE".bytes().collect();
        let cipher = xor(&plain, &key);
        assert_eq!(hex::encode(cipher),
            "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f");
    }

    #[test]
    fn challenge_1_6() {
        let data = read_file_base64("6.txt");
        let key_length = guess_key_length(&data);
        assert_eq!(key_length, 29);

        let solution = decrypt_vigenere(&data, key_length);
        assert!(solution.unwrap().starts_with("I'm back and I'm ringin'"));
    }

    #[test]
    fn challenge_1_7() {
        let data = read_file_base64("7.txt");
        let message = decrypt_aes(&data, &Vec::from("YELLOW SUBMARINE"));
        assert!(String::from_utf8(message).unwrap().starts_with("I'm back and I'm ringin'"));
    }

    #[test]
    fn test_humming() {
        let v1: Vec<u8> = "this is a test".bytes().collect();
        let v2: Vec<u8> = "wokka wokka!!!".bytes().collect();
        assert_eq!(humming_distance(&v1, &v2), 37);
    }

    #[test]
    fn test_transpose() {
        let input = "ABCDEFGHIJK";
        let output = transpose_blocks(&input.bytes().collect(), 3);
        let as_str: Vec<String> = output.iter().map(|v| v.iter().map(|&c| c as char).collect()).collect();
        assert_eq!(as_str, ["ADGJ", "BEHK", "CFI"]);
    }
}

fn main() {}
