use crate::number;

use num_bigint::{BigUint, RandBigInt};
use num_integer::Integer;
use num_traits::{One, ToPrimitive};
use rand::thread_rng;

/// Returns `true` if the input unsigned integer is probably prime.
///
/// # Arguments
///
/// * `n` - number to test for primality.
///
/// # Examples
///
/// ```
/// # extern crate num_bigint;
/// # fn main() {
/// use num_bigint::BigUint;
/// use probabilistic_encryption::prime;
///
/// assert_eq!(prime::is_probably_prime(&BigUint::from(128usize)), false);
/// assert_eq!(prime::is_probably_prime(&BigUint::from(2969usize)), true);
/// # }
/// ```
pub fn is_probably_prime(n: &BigUint) -> bool {
    match n.to_usize() {
        Some(_n) if _n < 3000 => PRIMES_UNDER_3000.contains(&_n),
        _ => {
            if is_multiple_of_prime_under_3000(n) {
                false
            } else if fermat_primality_test(50usize, n) {
                miller_rabin_primality_test(30usize, n)
            } else {
                false
            }
        }
    }
}

/// Returns `true` if the input unsigned integer is multiple of any prime under 3000.
///
/// # Examples
///
/// ```rust,ignore
/// assert_eq!(is_multiple_of_prime_under_3000(&BigUint::from(2554usize)), true);
/// assert_eq!(is_multiple_of_prime_under_3000(&BigUint::from(5003usize)), false);
/// ```
fn is_multiple_of_prime_under_3000(n: &BigUint) -> bool {
    PRIMES_UNDER_3000
        .iter()
        .map(|&prime| BigUint::from(prime))
        .filter(|prime| prime.lt(n))
        .any(|prime| n.ne(&prime) && n.is_multiple_of(&prime))
}

/// Fermat primality test.
///
/// # Arguments
///
/// * `n` - number to test for primality.
///
/// # Assumptions:
///
/// `n` is an odd integer `> 3` and `iterations > 0`.
///
/// # Reference
///
/// See algorithm 4.9 in "Handbook of Applied Cryptography" by Alfred J. Menezes et al.
///
/// # Examples
///
/// ```rust,ignore
/// assert_eq!(fermat_primality_test(10, &BigUint::from(6_700_417usize)), true);
/// assert_eq!(fermat_primality_test(10, &BigUint::from(6_700_419usize)), false);
/// ```
///
/// # Panics
///
/// Panics if `n` is an even integer or `< 2`.
fn fermat_primality_test(iterations: usize, n: &BigUint) -> bool {
    let mut rng = thread_rng();

    let low = BigUint::from(2usize);
    let high = n - BigUint::one();

    for _ in 0..iterations {
        let a = rng.gen_biguint_range(&low, &high);
        let r = a.modpow(&high, n);
        if !r.is_one() {
            return false;
        }
    }

    true
}

/// Miller-Rabin probabilistic primality test.
///
/// # Arguments
///
/// * `n` - number to test for primality.
///
/// # Assumptions:
///
/// `n` is an odd integer `> 3` and `iterations > 0`.
///
/// # Reference
///
/// See algorithm 4.24 in "Handbook of Applied Cryptography" by Alfred J. Menezes et al.
///
/// # Examples
///
/// ```rust,ignore
/// assert_eq!(miller_rabin_primality_test(10, &BigUint::from(6_700_417usize)), true);
/// assert_eq!(miller_rabin_primality_test(10, &BigUint::from(6_700_419usize)), false);
/// ```
///
/// # Panics
///
/// Panics if `n` is an even integer or `< 2`.
fn miller_rabin_primality_test(iterations: usize, n: &BigUint) -> bool {
    let mut rng = thread_rng();

    let two = BigUint::from(2u64);
    let low = &two;
    let high = n - BigUint::one();
    let (pw, odd) = number::as_power_of_two_and_odd(&high);

    for _ in 0..iterations {
        let a = rng.gen_biguint_range(low, &high);
        let mut y = a.modpow(&odd, n);

        while !y.is_one() && y != high {
            let mut j = 1u64;
            while j < pw && y != high {
                y = y.modpow(&two, n);
                if y.is_one() {
                    return false;
                } else {
                    j += 1;
                }
            }

            if y != high {
                return false;
            }
        }
    }

    true
}

/// Generates a random prime number of the given bit size.
///
/// # Arguments
///
/// * `bit_size` - number of bits of the generated prime.
///
/// # Assumptions
///
/// `bit_size > 1`.
///
/// # Panics
///
/// Panics if `bit_size < 2`.
pub fn generate_prime(bit_size: u64) -> BigUint {
    let mut n = generate_random_number(bit_size);
    let two = BigUint::from(2usize);

    if n.is_even() {
        n += BigUint::one();
    }

    while !(is_probably_prime(&n)) {
        n += &two;
    }

    n
}

/// Generates a random number of the given bit size with the two most significant bits set to 1.
///
/// # Arguments
///
/// * `bit_size` - number of bits of the generated number.
///
/// # Assumptions
///
/// `bit_size > 1`.
///
/// # Panics
///
/// Panics if `bit_size < 2`.
fn generate_random_number(bit_size: u64) -> BigUint {
    let mut rng = thread_rng();

    let n = rng.gen_biguint(bit_size);
    let mask = BigUint::from(3usize) << (bit_size - 2);
    n | mask
}

const PRIMES_UNDER_3000: [usize; 430] = [
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97,
    101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193,
    197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307,
    311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421,
    431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547,
    557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659,
    661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797,
    809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929,
    937, 941, 947, 953, 967, 971, 977, 983, 991, 997, 1009, 1013, 1019, 1021, 1031, 1033, 1039,
    1049, 1051, 1061, 1063, 1069, 1087, 1091, 1093, 1097, 1103, 1109, 1117, 1123, 1129, 1151, 1153,
    1163, 1171, 1181, 1187, 1193, 1201, 1213, 1217, 1223, 1229, 1231, 1237, 1249, 1259, 1277, 1279,
    1283, 1289, 1291, 1297, 1301, 1303, 1307, 1319, 1321, 1327, 1361, 1367, 1373, 1381, 1399, 1409,
    1423, 1427, 1429, 1433, 1439, 1447, 1451, 1453, 1459, 1471, 1481, 1483, 1487, 1489, 1493, 1499,
    1511, 1523, 1531, 1543, 1549, 1553, 1559, 1567, 1571, 1579, 1583, 1597, 1601, 1607, 1609, 1613,
    1619, 1621, 1627, 1637, 1657, 1663, 1667, 1669, 1693, 1697, 1699, 1709, 1721, 1723, 1733, 1741,
    1747, 1753, 1759, 1777, 1783, 1787, 1789, 1801, 1811, 1823, 1831, 1847, 1861, 1867, 1871, 1873,
    1877, 1879, 1889, 1901, 1907, 1913, 1931, 1933, 1949, 1951, 1973, 1979, 1987, 1993, 1997, 1999,
    2003, 2011, 2017, 2027, 2029, 2039, 2053, 2063, 2069, 2081, 2083, 2087, 2089, 2099, 2111, 2113,
    2129, 2131, 2137, 2141, 2143, 2153, 2161, 2179, 2203, 2207, 2213, 2221, 2237, 2239, 2243, 2251,
    2267, 2269, 2273, 2281, 2287, 2293, 2297, 2309, 2311, 2333, 2339, 2341, 2347, 2351, 2357, 2371,
    2377, 2381, 2383, 2389, 2393, 2399, 2411, 2417, 2423, 2437, 2441, 2447, 2459, 2467, 2473, 2477,
    2503, 2521, 2531, 2539, 2543, 2549, 2551, 2557, 2579, 2591, 2593, 2609, 2617, 2621, 2633, 2647,
    2657, 2659, 2663, 2671, 2677, 2683, 2687, 2689, 2693, 2699, 2707, 2711, 2713, 2719, 2729, 2731,
    2741, 2749, 2753, 2767, 2777, 2789, 2791, 2797, 2801, 2803, 2819, 2833, 2837, 2843, 2851, 2857,
    2861, 2879, 2887, 2897, 2903, 2909, 2917, 2927, 2939, 2953, 2957, 2963, 2969, 2971, 2999,
];

#[cfg(test)]
mod test {
    use super::*;
    use num_traits::Zero;
    use primal;
    use proptest::prelude::*;

    fn strategy_for_odd_integer(upper_bound: usize) -> impl Strategy<Value = (usize, bool)> {
        let sieve = primal::Sieve::new(upper_bound);
        (5..upper_bound)
            .prop_filter("is_odd", move |&n| n.is_odd())
            .prop_map(move |n| (n, sieve.is_prime(n)))
    }

    proptest! {
        #[test]
        fn test_is_probably_prime((n, is_prime) in strategy_for_odd_integer(1_000_000)) {
            prop_assert_eq!(is_probably_prime(&BigUint::from(n)), is_prime);
        }

        #[test]
        fn test_is_multiple_of_prime_under_3000(n in 3usize..3000) {
            prop_assert_eq!(is_multiple_of_prime_under_3000(&BigUint::from(n)), !PRIMES_UNDER_3000.contains(&n));
        }

        #[test]
        fn test_fermat_primality_test(iterations in 1usize..100, (n, is_prime) in strategy_for_odd_integer(1_000_000)) {
            prop_assert_eq!(fermat_primality_test(iterations, &BigUint::from(n)), is_prime);
        }

        #[test]
        fn test_miller_rabin_primality_test(iterations in 1usize..100, (n, is_prime) in strategy_for_odd_integer(1_000_000)) {
            prop_assert_eq!(miller_rabin_primality_test(iterations, &BigUint::from(n)), is_prime);
        }

        #[test]
        fn test_generate_prime(bit_size in 16u64..64) {
            let prime = generate_prime(bit_size);
            prop_assert_eq!(prime.bits(), bit_size);
            prop_assert_eq!(is_probably_prime(&prime), true);
        }

        #[test]
        fn test_generate_random_number(size in 5u64..1024) {
            let shift = size - 2;
            let three = BigUint::from(3u64);
            let mask = &three << shift;

            let n = generate_random_number(size);
            let msb = (&n & &mask) >> shift;

            prop_assert_eq!(n.bits(), size);
            prop_assert_eq!(msb, three);
            prop_assert_eq!(n > BigUint::zero(), true);
        }
    }
}
