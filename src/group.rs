use crate::{DecryptionKey, EncryptionKey};
use serde::{de::Error, Deserialize, Deserializer, Serialize, Serializer};
use std::fmt::{self, Display};
use unknown_order::BigNumber;
use zeroize::Zeroize;

/// Group holds public values for Verifiable Encryption and Decryption
/// `g` and `h` correspond to the symbols with the same name in the paper.
/// `n` = p*q, p = 2p'+1, q = 2q'+1, p, q, p', q' are all prime.
/// `nn` = n*n
/// `n2d2` = nn / 2 integer division
/// `n2d4` = nn / 4 integer division
/// `nd4` = n / 4 integer division
#[derive(Clone, Debug, Zeroize)]
pub struct Group {
    pub(crate) g: BigNumber,
    pub(crate) h: BigNumber,
    pub(crate) n: BigNumber,
    pub(crate) nd4: BigNumber,
    pub(crate) nn: BigNumber,
    pub(crate) n2d2: BigNumber,
    pub(crate) n2d4: BigNumber,
    pub(crate) two_inv_two: BigNumber,
}

impl Display for Group {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Group {{ g: {}, h: {}, n: {}, nd4: {}, nn: {}, n2d2: {}, n2d4: {}, two_inv_two: {} }}",
            self.g, self.h, self.n, self.nd4, self.nn, self.n2d2, self.n2d4, self.two_inv_two
        )
    }
}

impl Serialize for Group {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let serdes = GroupSerdes {
            g: self.g.clone(),
            n: self.n.clone(),
        };
        serdes.serialize(serializer)
    }
}

impl<'a> Deserialize<'a> for Group {
    fn deserialize<D>(deserializer: D) -> Result<Group, D::Error>
    where
        D: Deserializer<'a>,
    {
        let GroupSerdes { g, n } = GroupSerdes::deserialize(deserializer)?;
        let nn = &n * &n;
        BigNumber::from(2)
            .invert(&n)
            .map(|two_inv| {
                let n2d2: BigNumber = &nn >> 1;
                let n2d4: BigNumber = &n2d2 >> 1;
                let nd4: BigNumber = &n >> 2;
                let h = &n + BigNumber::from(1);
                let two_inv_two: BigNumber = two_inv << 1;
                Group {
                    g,
                    h,
                    n,
                    nn,
                    n2d2,
                    n2d4,
                    nd4,
                    two_inv_two,
                }
            })
            .ok_or_else(|| D::Error::custom("Unable to deserialize"))
    }
}

impl Group {
    /// Create new encryption/decryption keys that support up to `max_messages` to encrypt
    pub fn new_keys(&self, max_messages: usize) -> Option<(EncryptionKey, DecryptionKey)> {
        DecryptionKey::random(max_messages, self).map(|dk| {
            let ek = EncryptionKey::from(&dk);
            (ek, dk)
        })
    }

    /// Create a random paillier group
    pub fn random() -> Option<Self> {
        let mut p = BigNumber::safe_prime(1024);
        let mut q = BigNumber::safe_prime(1024);
        let res = Self::with_safe_primes_unchecked(&p, &q);
        // Make sure the primes are zero'd
        p.zeroize();
        q.zeroize();
        res
    }

    /// Create a new group from two safe primes.
    /// `p` and `q` are checked if prime
    pub fn with_safe_primes(p: &BigNumber, q: &BigNumber) -> Option<Self> {
        if !p.is_prime() || !q.is_prime() {
            return None;
        }
        Self::with_safe_primes_unchecked(p, q)
    }

    #[allow(clippy::many_single_char_names)]
    /// Create a new group from two safe primes,
    /// `p` and `q` are not checked to see if they are safe primes
    pub fn with_safe_primes_unchecked(p: &BigNumber, q: &BigNumber) -> Option<Self> {
        // Paillier doesn't work if p == q
        if p == q {
            return None;
        }

        let n = p * q;
        let nn = &n * &n;
        let g_tick = BigNumber::random(&nn);
        BigNumber::from(2).invert(&n).map(|two_inv| {
            let two_n2: BigNumber = &nn << 1;
            let n2d2: BigNumber = &nn >> 1;
            let n2d4: BigNumber = &n2d2 >> 1;
            let nd4: BigNumber = &n >> 2;
            let h = &n + BigNumber::from(1);
            let g = g_tick.modpow(&two_n2, &nn);
            let two_inv_two: BigNumber = two_inv << 1;
            Group {
                g,
                h,
                n,
                nn,
                n2d2,
                n2d4,
                nd4,
                two_inv_two,
            }
        })
    }

    /// Computes a mod nn where 0 < a < nn or
    /// (nn - a) mod nn where a > nn / 2
    /// See section 3.2
    pub fn abs(&self, a: &BigNumber) -> BigNumber {
        let tv = a % &self.nn;

        if tv > self.n2d2 {
            &self.nn - tv
        } else {
            tv
        }
    }

    /// Generate random value < n / 4
    pub fn random_for_encrypt(&self) -> BigNumber {
        let mut r = BigNumber::random(&self.nd4);
        while r.is_zero() {
            r = BigNumber::random(&self.nd4);
        }
        r
    }

    /// Generate random value < n^2 / 4
    pub fn random_value(&self) -> BigNumber {
        let mut r = BigNumber::random(&self.n2d4);
        while r.is_zero() {
            r = BigNumber::random(&self.n2d4);
        }
        r
    }

    /// Computes H(u, e, L) for encryption/decryption
    pub fn hash(&self, u: &BigNumber, e: &[BigNumber], domain: &[u8]) -> BigNumber {
        let mut transcript = merlin::Transcript::new(b"encryption hash generation");
        transcript.append_message(b"u", &u.to_bytes());
        transcript.append_message(
            b"e",
            &e.iter()
                .map(|ee| ee.to_bytes())
                .flatten()
                .collect::<Vec<u8>>(),
        );
        transcript.append_message(b"domain", domain);

        let mut hash = [0u8; 64];
        transcript.challenge_bytes(b"encryption hash output", &mut hash);
        BigNumber::from_slice(&hash)
    }

    /// Compute the modular exponentiation reduced by the group modulus
    pub fn pow(&self, base: &BigNumber, exp: &BigNumber) -> BigNumber {
        base.modpow(exp, &self.nn)
    }

    /// Compute the modular multiplication reduced by the group modulus
    pub fn mul(&self, lhs: &BigNumber, rhs: &BigNumber) -> BigNumber {
        lhs.modmul(rhs, &self.nn)
    }

    /// Compute modular exponentiation with the base as `g`
    pub fn g_pow(&self, exp: &BigNumber) -> BigNumber {
        self.g.modpow(exp, &self.nn)
    }

    /// Compute modular exponentiation with the base as `h`
    pub fn h_pow(&self, exp: &BigNumber) -> BigNumber {
        self.h.modpow(exp, &self.nn)
    }

    /// The random generator for this group
    pub fn g(&self) -> &BigNumber {
        &self.g
    }

    /// The other generator, h = n + 1
    pub fn h(&self) -> &BigNumber {
        &self.h
    }

    /// The product of two primes
    pub fn n(&self) -> &BigNumber {
        &self.n
    }

    /// The group modulus
    pub fn nn(&self) -> &BigNumber {
        &self.nn
    }
}

#[derive(Serialize, Deserialize)]
struct GroupSerdes {
    g: BigNumber,
    n: BigNumber,
}
