use crate::{DecryptionKey, Group, VerifiableCipherText, VerifiableEncryptionProof};
use serde::{Deserialize, Serialize};
use std::fmt::{self, Display};
use unknown_order::BigNumber;

/// Key for Encrypting `VerifiableCipherText`
/// as described in section 3.2 in
/// <https://shoup.net/papers/verenc.pdf>
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EncryptionKey {
    y1: Vec<BigNumber>,
    y2: BigNumber,
    y3: BigNumber,
    group: Group,
}

impl Display for EncryptionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "EncryptionKey {{ y1: [{}], y2: {}, y3: {}, group: {} }}",
            self.y1
                .iter()
                .map(|y| format!("{}", y))
                .collect::<Vec<String>>()
                .join(", "),
            self.y2,
            self.y3,
            self.group,
        )
    }
}

impl From<&DecryptionKey> for EncryptionKey {
    fn from(dk: &DecryptionKey) -> Self {
        let y1 = dk.x1.iter().map(|x| dk.group.g_pow(x)).collect();
        let y2 = dk.group.g_pow(&dk.x2);
        let y3 = dk.group.g_pow(&dk.x3);
        Self {
            y1,
            y2,
            y3,
            group: dk.group.clone(),
        }
    }
}

impl EncryptionKey {
    /// Encrypt multiple messages as described in
    /// section 3.2 in
    /// <https://shoup.net/papers/verenc.pdf>
    /// `domain` represents a domain separation tag or nonce.
    /// `msgs` values must be less than `self.group.n`
    pub fn encrypt(
        &self,
        domain: &[u8],
        msgs: &[BigNumber],
    ) -> Result<VerifiableCipherText, String> {
        if msgs.len() > self.y1.len() {
            return Err(format!(
                "Number of messages {} is more than supported by this key {}",
                msgs.len(),
                self.y1.len()
            ));
        }
        for (i, m) in msgs.iter().enumerate() {
            if m > &self.group.n {
                return Err(format!("message {} is not valid", i));
            }
        }

        let r = self.group.random_for_encrypt();

        Ok(self.encrypt_with_blinding_factor(domain, msgs, &r))
    }

    /// Encrypts and returns a NIZK where the ciphertext and commitments are computed (t values).
    /// The blindings are generated as part of calling this function.
    /// "The protocol" from section 5.2 in <https://shoup.net/papers/verenc.pdf>
    /// Not using t = g^m*h^s as the Idemix protocol does not use it,
    /// possibly because the knowledge of `m` is proved in the credential attribute protocol.
    /// Use this if the proof is by itself and not part of another protocol.
    pub fn encrypt_and_prove(
        &self,
        nonce: &[u8],
        msgs: &[BigNumber],
    ) -> Result<(VerifiableCipherText, VerifiableEncryptionProof), String> {
        let group = &self.group;
        let blindings = (0..msgs.len())
            .map(|_| group.random_for_encrypt())
            .collect::<Vec<BigNumber>>();
        self.encrypt_and_prove_blindings(nonce, msgs, blindings.as_slice())
    }

    /// Encrypts and returns a NIZK where the ciphertext and commitments are computed (t values).
    /// The blindings are generated as part of calling this function.
    /// "The protocol" from section 5.2 in <https://shoup.net/papers/verenc.pdf>
    /// Not using t = g^m*h^s as the Idemix protocol does not use it,
    /// possibly because the knowledge of `m` is proved in the credential attribute protocol.
    /// Use this if the proof is part of other ZKPs.
    pub fn encrypt_and_prove_blindings(
        &self,
        nonce: &[u8],
        msgs: &[BigNumber],
        blindings: &[BigNumber],
    ) -> Result<(VerifiableCipherText, VerifiableEncryptionProof), String> {
        if msgs.len() != blindings.len() {
            return Err(format!(
                "Number of messages {} != number of blindings {}",
                msgs.len(),
                blindings.len()
            ));
        }
        if msgs.len() > self.y1.len() {
            return Err(format!(
                "Number of messages {} is more than supported by this key {}",
                msgs.len(),
                self.y1.len()
            ));
        }

        for (i, b) in blindings.iter().enumerate() {
            if b.is_zero() {
                return Err(format!("Invalid blinding factor at index {}", i));
            }
        }
        let group = &self.group;

        let r = group.random_for_encrypt();
        let r_tick = group.random_for_encrypt();
        let ciphertext = self.encrypt_with_blinding_factor(nonce, msgs, &r);

        let hash = group.hash(&ciphertext.u, ciphertext.e.as_slice(), nonce);
        let test_values = self.ciphertext_test_values(&r_tick, &hash, blindings);
        let challenge = self.fiat_shamir(nonce, &ciphertext, &test_values);

        let r_hat = self.schnorr(&r_tick, &challenge, &r);
        let m_hat = msgs
            .iter()
            .zip(blindings.iter())
            .map(|(m, b)| self.schnorr(b, &challenge, m))
            .collect();

        Ok((
            ciphertext,
            VerifiableEncryptionProof {
                challenge,
                r: r_hat,
                m: m_hat,
            },
        ))
    }

    /// Verify a proof of verifiable encryption
    /// See section 6.2.19 in
    /// <https://dominoweb.draco.res.ibm.com/reports/rz3730_revised.pdf>
    pub fn verify(
        &self,
        nonce: &[u8],
        ciphertext: &VerifiableCipherText,
        proof: &VerifiableEncryptionProof,
    ) -> Result<(), String> {
        if proof.m.len() > self.y1.len() {
            return Err(format!(
                "Number of messages {} is more than supported by this key {}",
                proof.m.len(),
                self.y1.len()
            ));
        }
        if proof.m.len() != ciphertext.e.len() {
            return Err(format!(
                "Number of messages {} is equal to ciphertext {}",
                proof.m.len(),
                ciphertext.e.len()
            ));
        }
        let group = &self.group;
        // Reconstruct u, e, v
        let two_c = &proof.challenge << 1;
        let two_r = &proof.r << 1;

        // u^{2c} mod n^2
        let uc = group.pow(&ciphertext.u, &two_c);

        // g^{2r} mod n^2
        let gr = group.g_pow(&two_r);

        // u^{2c} * g^{2r} mod n^2
        let u = group.mul(&uc, &gr);

        let mut e = Vec::with_capacity(proof.m.len());
        for i in 0..proof.m.len() {
            let ec = group.pow(&ciphertext.e[i], &two_c);
            let yr = group.pow(&self.y1[i], &two_r);
            let hm = group.h_pow(&(&proof.m[i] << 1));
            e.push(group.mul(&group.mul(&ec, &yr), &hm));
        }

        let hs = group.hash(&ciphertext.u, ciphertext.e.as_slice(), nonce);
        let vc = group.pow(&ciphertext.v, &two_c);
        let y3hs = group.pow(&self.y3, &hs);
        let y2y3hs = group.mul(&self.y2, &y3hs);
        let y2y3hsr2 = group.pow(&y2y3hs, &two_r);
        let v = group.mul(&vc, &y2y3hsr2);
        let test_values = VerifiableCipherText { u, e, v };
        let challenge = self.fiat_shamir(nonce, ciphertext, &test_values);
        if challenge == proof.challenge {
            Ok(())
        } else {
            Err("Invalid proof".to_string())
        }
    }

    pub(crate) fn fiat_shamir(
        &self,
        nonce: &[u8],
        ciphertext: &VerifiableCipherText,
        test_values: &VerifiableCipherText,
    ) -> BigNumber {
        let group = &self.group;
        let mut transcript =
            merlin::Transcript::new(b"camenisch-shoup verifiable encryption proof");
        transcript.append_message(b"nonce", nonce);
        transcript.append_message(b"n", &group.n.to_bytes());
        transcript.append_message(b"g", &group.g.to_bytes());
        transcript.append_message(b"y2", &self.y2.to_bytes());
        transcript.append_message(b"y3", &self.y3.to_bytes());
        transcript.append_message(
            b"y1",
            &self
                .y1
                .iter()
                .map(|y| y.to_bytes())
                .flatten()
                .collect::<Vec<u8>>(),
        );
        transcript.append_message(b"ciphertext.u", &ciphertext.u.to_bytes());
        transcript.append_message(
            b"ciphertext.e",
            &ciphertext
                .e
                .iter()
                .map(|e| e.to_bytes())
                .flatten()
                .collect::<Vec<u8>>(),
        );
        transcript.append_message(b"ciphertext.v", &ciphertext.v.to_bytes());
        transcript.append_message(b"ciphertext_test.u", &test_values.u.to_bytes());
        transcript.append_message(
            b"ciphertext_test.e",
            &test_values
                .e
                .iter()
                .map(|e| e.to_bytes())
                .flatten()
                .collect::<Vec<u8>>(),
        );
        transcript.append_message(b"ciphertext_test.v", &test_values.v.to_bytes());

        let mut challenge_bytes = [0u8; 32];
        transcript.challenge_bytes(
            b"verifiable encryption proof challenge",
            &mut challenge_bytes,
        );
        BigNumber::from_slice(&challenge_bytes)
    }

    pub(crate) fn ciphertext_test_values(
        &self,
        r: &BigNumber,
        hash: &BigNumber,
        msgs: &[BigNumber],
    ) -> VerifiableCipherText {
        let two_r = r << 1;
        let two_m = msgs.iter().map(|m| m << 1).collect::<Vec<BigNumber>>();
        let u = self.compute_u(&two_r);
        let e = self.compute_e(two_m.as_slice(), &two_r);
        let v = self.compute_v(&two_r, hash, false);
        VerifiableCipherText { u, e, v }
    }

    pub(crate) fn schnorr(
        &self,
        tilde: &BigNumber,
        challenge: &BigNumber,
        value: &BigNumber,
    ) -> BigNumber {
        tilde - self.group.mul(challenge, value)
    }

    pub(crate) fn encrypt_with_blinding_factor(
        &self,
        domain: &[u8],
        msgs: &[BigNumber],
        r: &BigNumber,
    ) -> VerifiableCipherText {
        let u = self.compute_u(r);
        let e = self.compute_e(msgs, r);
        let hash = self.group.hash(&u, &e, domain);
        let v = self.compute_v(r, &hash, true);
        VerifiableCipherText { u, e, v }
    }

    pub(crate) fn compute_u(&self, r: &BigNumber) -> BigNumber {
        self.group.g_pow(r)
    }

    pub(crate) fn compute_e(&self, msgs: &[BigNumber], r: &BigNumber) -> Vec<BigNumber> {
        let mut e = Vec::with_capacity(msgs.len());
        let group = &self.group;
        for (i, m) in msgs.iter().enumerate() {
            let ee: BigNumber = group.mul(&group.pow(&self.y1[i], r), &group.h_pow(m));
            e.push(ee);
        }
        e
    }

    pub(crate) fn compute_v(&self, r: &BigNumber, hash: &BigNumber, abs: bool) -> BigNumber {
        let group = &self.group;
        // (y2 * (y3^H(u, e, L)))^r
        let v = group.pow(&group.mul(&group.pow(&self.y3, hash), &self.y2), r);
        if abs {
            group.abs(&v)
        } else {
            v
        }
    }
}
