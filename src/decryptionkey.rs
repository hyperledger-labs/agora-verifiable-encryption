use crate::{Group, VerifiableCipherText};
use serde::{Deserialize, Serialize};
use unknown_order::BigNumber;
use zeroize::Zeroize;

/// Key for decrypting `VerifiableCipherText`
/// as described in section 3.2 in
/// <https://shoup.net/papers/verenc.pdf>
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DecryptionKey {
    pub(crate) x1: Vec<BigNumber>,
    pub(crate) x2: BigNumber,
    pub(crate) x3: BigNumber,
    pub(crate) group: Group,
}

impl Zeroize for DecryptionKey {
    fn zeroize(&mut self) {
        self.x2.zeroize();
        self.x3.zeroize();
        self.x1.iter_mut().for_each(|x| x.zeroize());
    }
}

impl DecryptionKey {
    /// Create a new random decryption key
    pub fn random(num_messages: usize, group: &Group) -> Option<Self> {
        if num_messages < 1 {
            return None;
        }

        let mut x1 = Vec::with_capacity(num_messages);
        for _ in 0..num_messages {
            let x = BigNumber::random(&group.n2d4);
            x1.push(x);
        }
        let x2 = BigNumber::random(&group.n2d4);
        let x3 = BigNumber::random(&group.n2d4);
        Some(Self {
            x1,
            x2,
            x3,
            group: group.clone(),
        })
    }

    /// Decrypt verifiable ciphertext as described in section 3.2 in
    /// <https://shoup.net/papers/verenc.pdf>
    pub fn decrypt(
        &self,
        domain: &[u8],
        ciphertext: &VerifiableCipherText,
    ) -> Result<Vec<BigNumber>, String> {
        if self.x1.len() < ciphertext.e.len() {
            return Err(format!(
                "Number of messages {} is more than supported by this key {}",
                ciphertext.e.len(),
                self.x1.len()
            ));
        }

        if ciphertext.v != self.group.abs(&ciphertext.v) {
            return Err("Absolute check failed".to_string());
        }

        // H(u, e, L)
        let hash = self.group.hash(&ciphertext.u, &ciphertext.e, domain);
        // 2 * (H(u, e, L) * x3 + x2)
        let exp = (hash * &self.x3 + &self.x2) << 1;

        let two = BigNumber::from(2);
        let u = self.group.pow(&ciphertext.u, &exp);
        let v = self.group.pow(&ciphertext.v, &two);

        if u != v {
            return Err("u^2 != v^2".to_string());
        }
        let mut m = Vec::with_capacity(ciphertext.e.len());

        let one = BigNumber::from(1);
        for (i, (ee, xx)) in ciphertext.e.iter().zip(self.x1.iter()).enumerate() {
            // 1/u^x_1
            let u_x1_inv = self
                .group
                .pow(&ciphertext.u, xx)
                .invert(&self.group.nn)
                .ok_or_else(|| "invalid ciphertext".to_string())?;
            let e = self.group.mul(&u_x1_inv, ee);
            let m_hat = self.group.pow(&e, &self.group.two_inv_two);
            let check = &m_hat % &self.group.n;
            if check != one {
                return Err(format!("decryption failed for message {}", i));
            }

            let m_i: BigNumber = (m_hat - 1) / &self.group.n;
            m.push(m_i);
        }

        Ok(m)
    }
}
