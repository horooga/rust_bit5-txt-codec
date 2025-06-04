Tool for text file encoding and decoding with 5 bits per symbol efficiency

Tool features:
    - 32-symbols alphabet, where besides eng lowercase letters, some punctuation, and space there are also newline symbol and replacement symbol for any character which is not in alphabet
    - 5 bits per symbol encoding due to reduced alphabet
    - AES128 encryption-decryption (length-preserving) available
    - opportunity to use strings of hex symbols as an alternative to encoded binary files (much less efficient)

Usage: exe [options(as single word)] [file_path(opt) | hex_string(opt)] [hex_key(opt)]

    options:
        - e - encode mode (always first option): input - existing [file_path], output - created ./encoded.bin or stdout error text
        - d - decode mode (always first option): input - existing [file_path], output - stdout decode text or stdout error text
        - ee - encode-encrypt mode (always first option): input - existing [file_path] and [hex_key], output - created ./encoded.bin or stdout error text
        - dd - decode-decrypt mode (always first option): input - existing [file_path] and [hex_key], output - stdout decode text or stdout error text
        - sw - hex string write: replaces output .bin file of a decoding operation with a [hex_string]
        - sr - hex string read: replaces input .bin or .txt [file_path] for decoding or encoding operation with a [hex_string]
        - g - 16bytes hex key gen

Some details:
    - do not use spaces when encode with "sr" option to avoid cmd args separation
    - if store encoded bits as hex symbols in ascii string efficiency will be 8.75 bits per symbol at best
    - compiled exe will be named "codec5" as specified in Cargo.toml
