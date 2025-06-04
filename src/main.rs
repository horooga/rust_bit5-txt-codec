use aes::Aes128;
use fpe::ff1::{BinaryNumeralString, FF1};
use once_cell::sync::Lazy;
use rand::{Rng, rng};
use std::{
    collections::HashMap,
    env::args,
    fs::File,
    io::{Read, Write},
};

static ALPHABET: Lazy<Vec<char>> = Lazy::new(|| {
    "abcdefghijklmnopqrstuvwxyz,.:\n #"
        .to_string()
        .chars()
        .collect()
});

static ENCODES: Lazy<HashMap<char, String>> = Lazy::new(|| {
    (0..32)
        .map(|i| (ALPHABET[i as usize], format!("{:05b}", i)))
        .collect()
});

static DECODES: Lazy<HashMap<String, char>> =
    Lazy::new(|| ENCODES.keys().map(|c| (ENCODES[c].clone(), *c)).collect());

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn hex_to_bytes(hex: &str) -> Option<Vec<u8>> {
    if hex.len() % 2 == 0 {
        Some(
            (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
                .collect(),
        )
    } else {
        None
    }
}

fn gen_key() -> String {
    let mut rng = rng();
    bytes_to_hex(
        (0..16)
            .map(|_| rng.random())
            .collect::<Vec<u8>>()
            .as_slice(),
    )
}

fn decrypt(cipher: &[u8], key: String) -> Option<Vec<u8>> {
    let byte_key = hex_to_bytes(key.as_str())?;
    let ff1 = FF1::<Aes128>::new(byte_key.as_slice(), 2).unwrap();
    Some(
        ff1.decrypt(&[], &BinaryNumeralString::from_bytes_le(cipher))
            .unwrap()
            .to_bytes_le(),
    )
}

fn encrypt(bytes: &[u8], key: String) -> Option<Vec<u8>> {
    let byte_key = hex_to_bytes(key.as_str())?;
    let ff1 = FF1::<Aes128>::new(byte_key.as_slice(), 2).unwrap();
    Some(
        ff1.encrypt(&[], &BinaryNumeralString::from_bytes_le(bytes))
            .unwrap()
            .to_bytes_le(),
    )
}

fn decode(bits: Vec<bool>) -> String {
    bits.chunks_exact(5)
        .map(|i| {
            DECODES[&i
                .iter()
                .map(|b| std::char::from_digit(if *b { 1 } else { 0 }, 10).unwrap())
                .collect::<String>()]
        })
        .collect()
}

fn encode(string: String) -> Vec<u8> {
    let bits: Vec<bool> = string
        .to_lowercase()
        .chars()
        .map(|c| ENCODES.get(&c).unwrap_or(&"11111".to_string()).to_owned())
        .collect::<Vec<String>>()
        .join("")
        .chars()
        .map(|c| c == '1')
        .collect();
    bits.chunks(8)
        .map(|chunk| {
            chunk.iter().enumerate().fold(
                0_u8,
                |acc, (i, &bit)| {
                    if bit { acc | (1 << (7 - i)) } else { acc }
                },
            )
        })
        .collect()
}

fn bytes_to_bits(bytes: &[u8]) -> Vec<bool> {
    let mut bits = Vec::with_capacity(bytes.len() * 8);
    for byte in bytes {
        for i in 0..8 {
            bits.push((byte & (1 << (7 - i))) != 0);
        }
    }
    bits
}

fn write_file(bytes: &[u8]) {
    let mut file = File::create("encoded.bin").unwrap();
    let _ = file.write_all(bytes);
}

fn do_input(file_read: bool, input: String) -> Result<Vec<u8>, String> {
    if file_read {
        if let Ok(mut file) = File::open(input) {
            let mut bytes = Vec::new();
            let _ = file.read_to_end(&mut bytes);
            Ok(bytes)
        } else {
            Err("Error: File path does not exist".to_string())
        }
    } else {
        Ok(input.into_bytes())
    }
}

fn do_decode(file_read: bool, mut bytes: Vec<u8>, key: Option<String>) -> Result<String, String> {
    if !file_read {
        if let Some(hex) = hex_to_bytes(String::from_utf8(bytes.to_owned()).unwrap().as_str()) {
            bytes = hex;
        } else {
            return Err("Error: Hex invalid length (one missing or one extra symbol".to_string());
        }
    }
    if let Some(some_key) = key {
        if let Some(decrypted) = decrypt(bytes.as_slice(), some_key) {
            Ok(decode(bytes_to_bits(decrypted.as_slice())))
        } else {
            Err("Error: Hex invalid length (one missing or one extra symbol".to_string())
        }
    } else {
        Ok(decode(bytes_to_bits(bytes.as_slice())))
    }
}

fn do_encode(text: String, key: Option<String>) -> Result<Vec<u8>, String> {
    let mut encoded = encode(text);
    if key.is_some() {
        encoded = if let Some(encrypted) = encrypt(encoded.as_slice(), key.unwrap()) {
            encrypted
        } else {
            return Err("Error: Hex invalid length (one missing or one extra symbol".to_string());
        }
    }
    Ok(encoded)
}

//using result as enum for two "Ok()" dtypes
fn do_output(file_output: bool, data: Result<Vec<u8>, String>) -> String {
    match data {
        Ok(bytes) => {
            if file_output {
                write_file(bytes.as_slice());
                "File saved".to_string()
            } else {
                bytes_to_hex(bytes.as_slice())
            }
        }
        Err(string) => string,
    }
}

fn help() {
    println!("Usage: exe [options(as single word)] [file_path(opt) | hex_string(opt)] [hex_key(opt)]

    options:
        e - encode mode (always first option): input - existing [file_path], output - created ./encoded.bin or stdout error text
        d - decode mode (always first option): input - existing [file_path], output - stdout decode text or stdout error text
        ee - encode-encrypt mode (always first option): input - existing [file_path] and [hex_key], output - created ./encoded.bin or stdout error text
        dd - decode-decrypt mode (always first option): input - existing [file_path] and [hex_key], output - stdout decode text or stdout error text
        sw - hex string write: replaces output .bin file of a decoding operation with a [hex_string]
        sr - hex string read: replaces input .bin or .txt [file_path] for decoding or encoding operation with a [hex_string]
        g - 16bytes hex key gen");
}

fn main() {
    let args: Vec<String> = args().collect();
    if args.len() == 1 {
        help();
    } else if args[1] == "g" {
        println!("{}", gen_key());
        return;
    }
    let options = args[1].clone();
    let input_bytes = match do_input(!options.contains("sr"), args[2].clone()) {
        Ok(bytes) => bytes,
        Err(err) => {
            println!("{}", err);
            return;
        }
    };
    let key = if options.contains("ee") || options.contains("dd") {
        Some(args[3].clone())
    } else {
        None
    };
    //using result as enum for two "Ok()" dtypes
    let processed_data = if options.starts_with("e") {
        Ok(
            match do_encode(
                if let Ok(text) = String::from_utf8(input_bytes) {
                    text
                } else {
                    println!("Error: input file decoding error");
                    return;
                },
                key,
            ) {
                Ok(bytes) => bytes,
                Err(err) => {
                    println!("{}", err);
                    return;
                }
            },
        )
    } else {
        Err(match do_decode(!options.contains("sr"), input_bytes, key) {
            Ok(text) => text,
            Err(err) => {
                println!("{}", err);
                return;
            }
        })
    };
    println!("{}", do_output(!options.contains("sw"), processed_data));
}
