extern crate probabilistic_encryption;

use std::str;
use probabilistic_encryption::blum_goldwasser;
use probabilistic_encryption::key::{PublicKey, PrivateKey};

fn main() {
    let plaintext = b"hello world";

    match blum_goldwasser::generate_keys(8) {
        Ok((public_key, private_key)) => {
            let cyphertext = public_key.encrypt(plaintext);
            let decrypted_plaintext = private_key.decrypt(&cyphertext);
            
            println!("{}", str::from_utf8(&decrypted_plaintext).unwrap());
        },
        Err(err) => {
            eprintln!("{}", err);
            panic!(err)
        }
    };
}