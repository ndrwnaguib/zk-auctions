use num_bigint::{BigInt, BigUint, ToBigInt};
use num_integer::Integer;
use num_traits::{One, Zero};

/// Calculates the values needed to represent `n` as the product of a power of 2 and an odd number.
///
/// # Examples
///
/// ```
/// # extern crate num_bigint;
/// # fn main() {
/// use num_bigint::BigUint;
/// use probabilisticpubkey::number;
///
/// assert_eq!(number::as_power_of_two_and_odd(&BigUint::from(256usize)), (8, BigUint::from(1usize)));
/// assert_eq!(number::as_power_of_two_and_odd(&BigUint::from(137usize)), (0, BigUint::from(137usize)));
/// assert_eq!(number::as_power_of_two_and_odd(&BigUint::from(1_1776usize)), (9, BigUint::from(23usize)));
/// # }
/// ```
pub fn as_power_of_two_and_odd(n: &BigUint) -> (u64, BigUint) {
    let zero = BigUint::zero();
    let one = BigUint::one();
    let two = BigUint::from(2usize);

    if n.is_zero() {
        (0, zero)
    } else if n.is_odd() {
        (0, n.clone())
    } else if is_power_of_two(n) {
        (n.bits() - 1, one)
    } else {
        let mut m = n.clone();
        let mut pw = 0u64;

        while m.is_even() {
            m = m.div_floor(&two);
            pw += 1;
        }

        (pw, m)
    }
}

/// Determines whether an unsigned integer is power of 2 or not.
///
/// # Examples
///
/// ```rust,ignore
/// use num_bigint::BigUint;
///
/// assert_eq!(is_power_of_two(&BigUint::from(256usize)), true);
/// assert_eq!(is_power_of_two(&BigUint::from(37usize)), false);
/// ```
fn is_power_of_two(n: &BigUint) -> bool {
    (!n.is_zero()) && (n & (n - BigUint::one())).is_zero()
}

/// Calculates integers `x` and `y` such that `ax + by = d`, where `d = gcd(a, b)`.
///
/// # Reference
///
/// See algorithm 2.107 in "Handbook of Applied Cryptography" by Alfred J. Menezes et al.
///
/// # Examples
///
/// ```
/// # extern crate num_bigint;
/// # fn main() {
/// use num_bigint::{BigUint, BigInt};
/// use probabilisticpubkey::number;
///
/// let a = BigUint::from(73usize);
/// let b = BigUint::from(56usize);
/// let x = BigInt::from(-23isize);
/// let y = BigInt::from(30isize);
///
/// assert_eq!(number::extended_euclidean_algorithm(&a, &b), Some((x, y)));
/// # }
/// ```
pub fn extended_euclidean_algorithm(a: &BigUint, b: &BigUint) -> Option<(BigInt, BigInt)> {
    let zero = BigInt::zero();
    let one = BigInt::one();

    let mut x: BigInt;
    let mut y: BigInt;

    if b.is_zero() {
        x = one.clone();
        y = zero.clone();
        Some((x, y))
    } else {
        let mut _a = a.to_bigint()?;
        let mut _b = b.to_bigint()?;

        let mut q: BigInt;
        let mut r: BigInt;
        let mut x1 = zero.clone();
        let mut x2 = one.clone();
        let mut y1 = one.clone();
        let mut y2 = zero.clone();

        while _b > zero {
            q = _a.div_floor(&_b);
            r = _a - q.clone() * _b.clone();
            x = x2 - q.clone() * x1.clone();
            y = y2 - q.clone() * y1.clone();

            _a = _b;
            _b = r;
            x2 = x1;
            x1 = x;
            y2 = y1;
            y1 = y;
        }

        x = x2;
        y = y2;

        Some((x, y))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JacobiSymbol {
    MinusOne = -1,
    Zero = 0,
    One = 1,
}

/// Jacobi symbol computation. Same as Legendre symbol if `n` is prime.
///
/// # Assumptions
///
/// `n` is an odd integer `≥ 3` and `0 ≤ a < n`.
///
/// # Reference
///
/// See algorithm 2.149 in "Handbook of Applied Cryptography" by Alfred J. Menezes et al.
///
/// # Examples
///
/// ```
/// # extern crate num_bigint;
/// # fn main() {
/// use num_bigint::BigUint;
/// use probabilisticpubkey::number;
///
/// let a = BigUint::from(256usize);
/// let n = BigUint::from(4211usize);
///
/// assert_eq!(number::jacobi_symbol(&a, &n), number::JacobiSymbol::One);
/// # }
/// ```
pub fn jacobi_symbol(a: &BigUint, n: &BigUint) -> JacobiSymbol {
    fn calculate(a: &BigUint, n: &BigUint) -> i8 {
        let three = BigUint::from(3usize);
        let four = BigUint::from(4usize);
        let seven = BigUint::from(7usize);
        let eight = BigUint::from(8usize);

        if a.is_zero() {
            0
        } else if a.is_one() {
            1
        } else {
            let mut s;
            let (e, a1) = as_power_of_two_and_odd(a);
            if e.is_even() {
                s = 1;
            } else {
                let x = n.mod_floor(&eight);
                if x.is_one() || x == seven {
                    s = 1;
                } else {
                    s = -1;
                }
            }

            let y = n.mod_floor(&four);
            let z = a1.mod_floor(&four);
            if y == three && z == three {
                s = -s;
            }

            let n1 = n.mod_floor(&a1);
            if a1.is_one() {
                s
            } else {
                s * calculate(&n1, &a1)
            }
        }
    }

    let result = calculate(a, n);
    match result {
        -1 => JacobiSymbol::MinusOne,
        0 => JacobiSymbol::Zero,
        _ => JacobiSymbol::One,
    }
}

/// Finds solution to the simultaneous congruences in the Chinese remainder theorem.
///
/// # Arguments
///
/// * `ans` - list of tuples with values of `a` and `n` for each congruence in the Chinese remainder theorem.
///
/// # Assumptions
///
/// Each `n` is an odd integer `≥ 3` and each `a` satisfies that `0 ≤ a < n`.
/// All values of `n` are pairwise relatively prime.
///
/// # Reference
///
/// See algorithm 2.121 in "Handbook of Applied Cryptography" by Alfred J. Menezes et al.
///
/// # Examples
///
/// ```
/// # extern crate num_bigint;
/// # fn main() {
/// use num_bigint::BigUint;
/// use probabilisticpubkey::number;
///
/// let a1 = BigUint::from(128usize);
/// let n1 = BigUint::from(3253usize);
/// let a2 = BigUint::from(256usize);
/// let n2 = BigUint::from(4211usize);
///
/// assert_eq!(number::gauss_algorithm_for_crt(&[(&a1, &n1), (&a2, &n2)]), Some(BigUint::from(2173132usize)));
/// # }
/// ```
pub fn gauss_algorithm_for_crt(ans: &[(&BigUint, &BigUint)]) -> Option<BigUint> {
    let mut result = BigUint::zero();
    let n: BigUint = ans.iter().map(|item| item.1).product();

    for ani in ans {
        let ai = ani.0;
        let ni = ani.1;
        let n_div_ni = &n / ni;
        // n_div_ni and ni are coprime, therefore a multiplicative inverse exists in ℤn
        let mi = mod_inv(&n_div_ni, ni);
        result += ai * n_div_ni * mi?;
    }

    Some(result.mod_floor(&n))
}

/// Calculation of multiplicative inverses in ℤn.
/// The multiplicative inverse of `a mod n` is an integer `x` of ℤn such that `ax ≡ 1 (mod n)`.
///
/// # Assumptions
///
/// `a < n`.
///
/// # Reference
///
/// See algorithm 2.142 in "Handbook of Applied Cryptography" by Alfred J. Menezes et al.
///
/// # Examples
///
/// ```rust,ignore
/// use num_bigint::BigUint;
///
/// let a = BigUint::from(256usize);
/// let n = BigUint::from(4211usize);
///
/// assert_eq!(mod_inv(&a, &n), Some(BigUint::from(1135usize)));
/// ```
fn mod_inv(a: &BigUint, n: &BigUint) -> Option<BigUint> {
    let zero = Zero::zero();
    let one = BigUint::one();

    let d = a.gcd(n);
    // A solution exists if and only if gcd(a, n) = 1, that is, a and n must
    // be relatively prime (i.e. coprime). Furthermore, when this condition
    // holds, there is exactly one solution.
    if d > one {
        None
    } else {
        let (x, _) = extended_euclidean_algorithm(a, n)?;
        if x < zero {
            (x + n.to_bigint()?).to_biguint()
        } else {
            x.to_biguint()
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use num_traits::ToPrimitive;
    use primal;
    use proptest::prelude::*;

    fn strategy_for_integer_and_prime(
        lower_bound: usize,
        upper_bound: usize,
    ) -> impl Strategy<Value = (usize, usize)> {
        let sieve = primal::Sieve::new(upper_bound);
        (lower_bound..upper_bound)
            .prop_filter("is_prime", move |&n| sieve.is_prime(n))
            .prop_perturb(|n, mut rng| (rng.gen_range(0, n), n))
    }

    proptest! {
        #[test]
        fn test_is_power_of_two(n in any::<usize>()) {
            prop_assert_eq!(is_power_of_two(&BigUint::from(n)), n.is_power_of_two());
        }

        #[test]
        fn test_as_power_of_two_and_odd(n in any::<usize>()) {
            let (pw, odd) = as_power_of_two_and_odd(&BigUint::from(n));
            prop_assert_eq!(2usize.pow(pw as u32) * odd.to_usize().unwrap(), n);
        }

        #[test]
        fn test_extended_euclidean_algorithm(n1 in any::<usize>(), n2 in any::<usize>()) {
            let a = BigUint::from(n1);
            let b = BigUint::from(n2);

            match extended_euclidean_algorithm(&a, &b) {
                Some((x, y)) => {
                    let d = a.gcd(&b);
                    prop_assert_eq!(a.to_bigint().unwrap() * x + b.to_bigint().unwrap() * y, d.to_bigint().unwrap());
                },
                None => prop_assert_eq!(false, true)
            }
        }

        #[test]
        fn test_jacobi_symbol((a, n) in strategy_for_integer_and_prime(3, 10_000)) {
            // Check if we can find an integer 1 < b < n such that b² ≡ a mod n
            fn is_quadratic_residue_module(a: usize, n: usize) -> bool {
                let mut b = 1usize;
                let mut result = false;
                while !result && b < n {
                    result = b.pow(2).mod_floor(&n) == a;
                    b += 1;
                }
                result
            }

            match jacobi_symbol(&BigUint::from(a), &BigUint::from(n)) {
                JacobiSymbol::MinusOne => prop_assert_eq!(false, is_quadratic_residue_module(a, n)),
                JacobiSymbol::Zero     => prop_assert_eq!(true, if a.is_zero() { true } else { n.is_multiple_of(&a) }),
                JacobiSymbol::One      => prop_assert_eq!(true, is_quadratic_residue_module(a, n))
            }
        }

        #[test]
        fn test_gauss_algorithm_for_crt(
            (_a1, _n1) in strategy_for_integer_and_prime(1_000, 10_000),
            (_a2, _n2) in strategy_for_integer_and_prime(11_000, 20_000)
        ) {
            let a1 = BigUint::from(_a1);
            let n1 = BigUint::from(_n1);
            let a2 = BigUint::from(_a2);
            let n2 = BigUint::from(_n2);
            let ans = vec![(&a1, &n1), (&a2, &n2)];

            match gauss_algorithm_for_crt(&ans) {
                Some(x) => {
                    prop_assert_eq!(x.mod_floor(&n1), a1);
                    prop_assert_eq!(x.mod_floor(&n2), a2)
                }
                None => prop_assert_eq!(false, true)
            }
        }

        #[test]
        fn test_mod_inv((_a, _n) in strategy_for_integer_and_prime(3, 10_000)) {
            let one = BigUint::one();
            let a = BigUint::from(_a);
            let n = BigUint::from(_n);

            let d = a.gcd(&n);
            if d > one {
                prop_assert_eq!(true, true) // if gcd(a, n) > 1, then multiplicative inverse does not exist
            } else {
                match mod_inv(&a, &n) {
                    Some(x) => {
                        // multiplicative inverse x satisfies that n divides ax - 1
                        let y = a * x - one;
                        prop_assert_eq!(y.is_multiple_of(&n), true)
                    },
                    None => prop_assert_eq!(false, true)
                }
            }
        }
    }
}
