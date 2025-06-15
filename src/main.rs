use aes::Aes128;
use fpe::ff1::{BinaryNumeralString, FF1};
use rand::{Rng, rng};
use std::{env::args, fs, io::Write, process::exit};

static ALPHABET: [char; 32] = [
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's',
    't', 'u', 'v', 'w', 'x', 'y', 'z', ' ', ',', '.', ':', '\n', '#',
];

fn bytes_to_base64url(bytes: &[u8]) -> String {
    base64_url::encode(bytes)
}

fn base64url_to_bytes(code: &str) -> Option<Vec<u8>> {
    base64_url::decode(code).ok()
}

fn gen_key() -> String {
    let mut rng = rng();
    bytes_to_base64url(
        (0..16)
            .map(|_| rng.random())
            .collect::<Vec<u8>>()
            .as_slice(),
    )
}

fn decrypt(cipher: &[u8], key: &str) -> Option<Vec<u8>> {
    let byte_key = base64url_to_bytes(key)?;
    let ff1 = FF1::<Aes128>::new(byte_key.as_slice(), 2).expect("key error");
    Some(
        ff1.decrypt(&[], &BinaryNumeralString::from_bytes_le(cipher))
            .expect("decrypt error")
            .to_bytes_le(),
    )
}

fn encrypt(bytes: &[u8], key: &str) -> Option<Vec<u8>> {
    let byte_key = base64url_to_bytes(key)?;
    let ff1 = FF1::<Aes128>::new(byte_key.as_slice(), 2).unwrap();
    Some(
        ff1.encrypt(&[], &BinaryNumeralString::from_bytes_le(bytes))
            .unwrap()
            .to_bytes_le(),
    )
}

fn decode(bytes: &[u8]) -> String {
    let mut buffer: u16 = 0;
    let mut bit_count = 0;
    let mut output = Vec::new();
    for &byte in bytes {
        buffer |= (byte as u16) << bit_count;
        bit_count += 8;

        while bit_count >= 5 {
            let val = buffer & 0x1F;
            buffer >>= 5;
            bit_count -= 5;

            output.push(ALPHABET[val as usize]);
        }
    }
    String::from_iter(output)
}

fn encode(string: &str) -> Vec<u8> {
    let mut text = string.to_lowercase();
    if text.contains("_") {
        text = text.replace("_", " ");
        text = text.replace("@", "\n");
    }
    let mut buffer: u16 = 0;
    let mut bit_count = 0;
    let mut output = Vec::new();
    for c in text.chars() {
        let val = ALPHABET.iter().position(|&i| i == c).expect("#") as u16;
        buffer |= val << bit_count;
        bit_count += 5;

        if bit_count >= 8 {
            output.push((buffer & 0xFF) as u8);
            buffer >>= 8;
            bit_count -= 8;
        }
    }
    if bit_count > 0 {
        output.push(buffer as u8);
    }
    output
}

fn write_file(bytes: &[u8], name: &str) {
    let mut file = fs::File::create(name).unwrap();
    let _ = file.write_all(bytes);
}

fn do_input(file_read: bool, input: &str) -> Vec<u8> {
    if file_read {
        if let Ok(bytes) = fs::read(input) {
            bytes
        } else {
            eprintln!("Error: File path does not exist");
            exit(1);
        }
    } else {
        input.to_string().into_bytes()
    }
}

fn do_decode(file_read: bool, mut bytes: Vec<u8>, key: Option<&str>) -> String {
    if !file_read {
        if let Some(base64_code) =
            base64url_to_bytes(String::from_utf8(bytes.to_owned()).unwrap().as_str())
        {
            bytes = base64_code;
        } else {
            eprintln!("Error: Invalid key");
            exit(1);
        }
    }
    if let Some(some_key) = key {
        if let Some(decrypted) = decrypt(bytes.as_slice(), some_key) {
            decode(decrypted.as_slice())
        } else {
            eprintln!("Error: Invalid key");
            exit(1)
        }
    } else {
        decode(bytes.as_slice())
    }
}

fn do_encode(text: String, key: Option<&str>) -> Vec<u8> {
    let mut encoded = encode(text.as_str());
    if key.is_some() {
        encoded = if let Some(encrypted) = encrypt(encoded.as_slice(), key.unwrap()) {
            encrypted
        } else {
            eprintln!("Error: Invalid key");
            exit(1);
        }
    }
    encoded
}

//using result as enum for two "Ok()" dtypes
fn do_output(file_output: bool, data: Result<Vec<u8>, String>) -> Option<String> {
    match data {
        Ok(bytes) => {
            if file_output {
                write_file(bytes.as_slice(), "encoded.bin");
                None
            } else {
                Some(bytes_to_base64url(bytes.as_slice()))
            }
        }
        Err(string) => {
            if file_output {
                write_file(string.as_bytes(), "decoded.txt");
                None
            } else {
                Some(string)
            }
        }
    }
}

fn help() {
    println!("Usage: exe [options(as single word)] [file_path | base64url_code | input_string] [base64url_key](opt)

    options:
        - e - encode mode: input - existing [file_path], output - created ./encoded.bin or stderr
        - d - decode mode: input - existing [file_path], output - created ./decoded.txt or stderr
        - ee - encode-encrypt mode: input - existing [file_path] and [base64url_key], output - created ./encoded.bin or stderr
        - dd - decode-decrypt mode: input - existing [file_path] and [base64url_key], output - stdout decode text or stderr
        - sw - string write: replaces output .bin or .txt file of a encoding or decoding operation with a base64url_code stdout or a stdout string correspondingly
        - sr - string read: replaces input .bin or .txt [file_path] for decoding or encoding operation with a [input_string] or a [base64url_code] correspondingly
        - g - 16bytes base64url stdout key gen
")
}

fn main() {
    let args: Vec<String> = args().collect();
    if args.len() == 1 {
        help();
        return;
    } else if args[1] == "g" {
        println!("{}", gen_key());
        return;
    }
    let options = args[1].clone();
    let input_bytes = do_input(!options.contains("sr"), args[2].as_str());
    let key = if options.contains("ee") || options.contains("dd") {
        Some(args[3].as_str())
    } else {
        None
    };
    //using result as enum for two "Ok()" dtypes
    let processed_data = if options.contains("e") {
        Ok(do_encode(
            if let Ok(text) = String::from_utf8(input_bytes) {
                text
            } else {
                println!("Error: input file decoding error");
                return;
            },
            key,
        ))
    } else {
        Err(do_decode(!options.contains("sr"), input_bytes, key))
    };
    if let Some(stdout) = do_output(!options.contains("sw"), processed_data) {
        println!("{}", stdout);
    }
}
