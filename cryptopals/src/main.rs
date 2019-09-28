#![allow(dead_code)]

use hex::{FromHex};
use base64;
use maplit;
use lazy_static::{lazy_static};
use std::path::{ Path };
use std::fs::File;
use std::io::{ BufReader, BufRead, Lines };
use std::collections::HashMap;

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

struct BufIter<B> {
    br: Lines<B>
}

impl<B: BufRead> Iterator for BufIter<B> {
    type Item = String;

    fn next(&mut self) -> Option<String> {
        let v = self.br.next();
        match v {
            Some(l) => return Some(l.unwrap()),
            None => return None,
        }
    }
}

fn read_file(name: &String) -> BufIter<BufReader<File>> {
    let path = Path::new(name.as_str());
    let file = match File::open(&path) {
        Err(why) => panic!("couldn't open {}: {}", path.display(), why),
        Ok(file) => file
    };

    let buf = BufReader::new(file);
    return BufIter{br: buf.lines()};
}

fn xor(v1: &Vec<u8>, v2: &Vec<u8>) -> Vec<u8> {
    return v1.iter().zip(v2.iter().cycle()).map(|(&x, &y)| x^y).collect();
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

    return ENGLISH_FREQ.iter()
        .map(|(&c, &v)| (v - freq.get(&c).unwrap_or(&0.).powf(2.)))
        .fold(0., |acc, x| acc+x);
}

fn decrypt_xor(cipher: &Vec<u8>) -> (String, f64) {
    let mut best: String = "".to_string();
    let mut best_score: f64 = -1.;

    for v in 0..255 {
        let attempt = xor(cipher, &vec![v]);
        match String::from_utf8(attempt) {
            Ok(s) => {
                let freq = freq_distance(&s);
                if best_score < 0. || freq < best_score {
                    best = s;
                    best_score = freq;
                }
            },
            Err(_) => {}
        }
    }

    return (best, best_score);
}

fn challenge_1_5() {
    let text: Vec<u8> = "Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal".bytes().collect();
    let key: Vec<u8> = "ICE".bytes().collect();
    let cipher = xor(&text, &key);
    println!("{}", hex::encode(cipher));
}

fn count_bits(b: u8) -> u8 {
    let mut n = b;
    let mut c: u8 = 0;
    while n > 0 {
        c += (n & 1) as u8;
        n >>= 1;
    }
    return c;
}

fn humming_distance(v1: &Vec<u8>, v2: &Vec<u8>) -> usize {
    return v1.iter().zip(v2.iter()).map(|(&x, &y)| x^y).map(count_bits).fold(0 as usize, |a, b| a + (b as usize));
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
        let (result, _) = decrypt_xor(&cipher);
        assert_eq!(result, "Cooking MC's like a pound of bacon");
    }

    #[test]
    fn challenge_1_4() {
        let result = read_file(&"4.txt".to_string())
            .map(|line| decrypt_xor(&hex::decode(line).unwrap()))
            .filter(|(_, score)| *score >= 0.)
            .min_by_key(|(_, score)| (10000000. * *score).ceil() as i64)
            .unwrap().0;
        assert_eq!(result, "Now that the party is jumping\n");
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

fn relative_humming(v: &Vec<u8>, size: usize) -> usize {
    let mut chunks = v.chunks(size);
    let c1 = chunks.next().unwrap();
    let c2 = chunks.next().unwrap();
    return humming_distance(&Vec::from(c1), &Vec::from(c2));
}

fn main() {
    //challenge_1_4();
    challenge_1_5();
}
