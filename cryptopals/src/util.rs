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