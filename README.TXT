Tool for text file encoding and decoding with 5 bits per symbol efficiency

!!!Warning!!!
during encoding input text is rewritten with a 32-symbols alphabet

Tool features:
    - 32-symbols alphabet, where besides 30 symbols ("abcdefghijklmnopqrstuvwxyz ,.:"), there are also newline symbol and replacement symbol ("#") for any character which is not in alphabet
    - 5 bits per symbol encoding due to reduced alphabet
    - AES128 encryption-decryption (length-preserving) available
    - opportunity to use strings of base64url symbols as an alternative to encoded binary files

Usage:
    exe [options(as single word)] [file_path | base64url_code | input_string] [base64url_key](opt)

    options:
        - e - encode mode: input - existing [file_path], output - created ./encoded.bin or stderr
        - d - decode mode: input - existing [file_path], output - created ./decoded.txt or stderr
        - ee - encode-encrypt mode: input - existing [file_path] and [base64url_key], output - created ./encoded.bin or stderr
        - dd - decode-decrypt mode: input - existing [file_path] and [base64url_key], output - stdout decode text or stderr
        - sw - string write: replaces output .bin or .txt file of a encoding or decoding operation with a base64url_code stdout or a stdout string correspondingly
        - sr - string read: replaces input .bin or .txt [file_path] for decoding or encoding operation with a [input_string] or a [base64url_code] correspondingly
        - g - 16bytes base64url stdout key gen

Examples:
    - codec5 esrsw Hello_world!:
        ORa3as6Kx_A
    - codec5 dsrsw ORa3as6Kxg:
        hello world#

    - codec5 eesrsw Hello_world! LfXs0SyPEYT7qhtqoAcGkw:
        h1F5zZxKHMw
    - codec5 ddsrsw h1F5zZxKHMw LfXs0SyPEYT7qhtqoAcGkw:
        hello world#

Some details:
    - use "_" instead of spaces when encode with "sr" option to avoid cmd args separation
    - compiled exe will be named "codec5" as specified in Cargo.toml

