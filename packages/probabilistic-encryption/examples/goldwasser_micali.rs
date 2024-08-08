extern crate probabilistic_encryption;

use std::str;
use probabilistic_encryption::goldwasser_micali;
use probabilistic_encryption::key::{PublicKey, PrivateKey};

fn main() {
    let plaintext = b"hello world";

    match goldwasser_micali::generate_keys(8) {
        Ok((public_key, private_key)) => {
            let ciphertext = public_key.encrypt(plaintext);
            let decrypted_plaintext = private_key.decrypt(&ciphertext);
            
            println!("{}", str::from_utf8(&decrypted_plaintext).unwrap());
        },
        Err(err) => {
            eprintln!("{}", err);
            panic!(err)
        }
    };
}