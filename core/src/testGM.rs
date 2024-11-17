use rand::{rngs::StdRng, Rng, SeedableRng};
use rug::{Assign, Integer, RandState};
use sha2::{Digest, Sha256};
use std::time::Instant;

mod GM;

use GM::{
    decrypt_bit_and, decrypt_bit_gm, decrypt_gm, dot_mod, embed_and, embed_bit_and,
    encrypt_bit_and, encrypt_bit_gm, encrypt_gm, generate_keys,
};

fn test_gen_keys(iters: usize) {
    println!("test_gen_keys:");
    for _ in 0..iters {
        let keys = generate_keys();

        let n = &keys.pub_key;
        let (p, q) = &keys.priv_key;

        assert_eq!(jacobi(n - 1, n), 1);
    }
    println!("test_gen_keys pass");
}

fn test_gm_enc_dec(iters: usize) {
    println!("test_gm_enc_dec:");

    let keys = generate_keys();
    let n = &keys.pub_key;
    let (p, q) = &keys.priv_key;

    let mut rng = StdRng::from_entropy();

    for _ in 0..iters {
        let num: Integer = rng.gen::<u32>().into();
        let mut cipher = encrypt_gm(&num, n);

        // Re-encryption
        for _ in 0..3 {
            cipher = cipher.iter().map(|c| (c * encrypt_gm(&Integer::from(0), n)[0]) % n).collect();
        }

        let decrypted = decrypt_gm(&cipher, &(p.clone(), q.clone()));

        assert!(decrypted.is_some());
        assert_eq!(decrypted.unwrap(), num);
    }

    println!("test_gm_enc_dec pass");
}

fn test_gm_homo(iters: usize) {
    println!("test_gm_homo:");

    for _ in 0..iters {
        let keys = generate_keys();
        let n = &keys.pub_key;
        let priv_key = &keys.priv_key;

        let c0 = encrypt_bit_gm(0, n);
        let c1 = encrypt_bit_gm(1, n);

        // XOR tests
        assert_eq!(decrypt_gm(&[c0[0] * c1[0] % n], priv_key), Some(1.into()));
        assert_eq!(decrypt_gm(&[c0[0] * c0[0] % n], priv_key), Some(0.into()));
        assert_eq!(decrypt_gm(&[c1[0] * c1[0] % n], priv_key), Some(0.into()));

        // Flip tests
        assert_eq!(decrypt_gm(&[c0[0] * (n - 1) % n], priv_key), Some(1.into()));
        assert_eq!(decrypt_gm(&[c1[0] * (n - 1) % n], priv_key), Some(0.into()));
    }

    println!("test_gm_homo pass");
}

fn test_gm_bit_and() {
    println!("test_gm_bit_and:");

    let keys = generate_keys();
    let n = &keys.pub_key;
    let priv_key = &keys.priv_key;

    let mut enc_times = Vec::new();
    let mut dec_times = Vec::new();

    for _ in 0..10 {
        let start = Instant::now();
        let cipher0 = encrypt_bit_and("0", n);
        enc_times.push(start.elapsed().as_secs_f64());

        let start = Instant::now();
        let cipher1 = encrypt_bit_and("1", n);
        enc_times.push(start.elapsed().as_secs_f64());

        let start = Instant::now();
        let bit0 = decrypt_bit_and(&cipher0, priv_key);
        dec_times.push(start.elapsed().as_secs_f64());

        let start = Instant::now();
        let bit1 = decrypt_bit_and(&cipher1, priv_key);
        dec_times.push(start.elapsed().as_secs_f64());

        assert_eq!(bit0, "0");
        assert_eq!(bit1, "1");

        // AND tests
        assert_eq!(decrypt_bit_and(&dot_mod(&cipher0, &encrypt_bit_and("1", n), n), priv_key), "0");
        assert_eq!(decrypt_bit_and(&dot_mod(&cipher0, &encrypt_bit_and("0", n), n), priv_key), "0");
        assert_eq!(decrypt_bit_and(&dot_mod(&cipher1, &encrypt_bit_and("1", n), n), priv_key), "1");
    }

    let enc_avg = enc_times.iter().sum::<f64>() / enc_times.len() as f64;
    let enc_std_dev = (enc_times.iter().map(|&x| (x - enc_avg).powi(2)).sum::<f64>()
        / enc_times.len() as f64)
        .sqrt()
        / enc_avg
        * 100.0;
    let dec_avg = dec_times.iter().sum::<f64>() / dec_times.len() as f64;
    let dec_std_dev = (dec_times.iter().map(|&x| (x - dec_avg).powi(2)).sum::<f64>()
        / dec_times.len() as f64)
        .sqrt()
        / dec_avg
        * 100.0;

    println!("EncAnd avg: {:.2}s, rel.std.dev.: {:.2}%", 32.0 * enc_avg, enc_std_dev);
    println!("DecAnd avg: {:.2}s, rel.std.dev.: {:.2}%", 32.0 * dec_avg, dec_std_dev);
}

fn test_embed_bit_and(iters: usize) {
    println!("test_embed_bit_and:");

    let keys = generate_keys();
    let n = &keys.pub_key;
    let priv_key = &keys.priv_key;
    let mut rng = StdRng::from_entropy();

    for _ in 0..iters {
        let bit: u8 = rng.gen_range(0..=1);
        let cipher = encrypt_bit_gm(bit as u32, n);

        let cipher_and = embed_bit_and(&cipher, n);
        assert_eq!(decrypt_bit_and(&cipher_and, priv_key), bit.to_string());
    }

    println!("test_embed_bit_and pass");
}

fn test_gm() {
    println!("test_gm");

    test_gen_keys(10);
    test_gm_enc_dec(10);
    test_gm_homo(10);
    test_gm_bit_and();
    test_embed_bit_and(10);

    println!("test_gm pass");
}

// Run all tests
fn main() {
    test_gm();
}
