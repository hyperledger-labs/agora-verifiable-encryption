#[cfg(feature = "std")]
mod tests {
    use unknown_order::BigNumber;
    use verenc::camshoup::*;

    fn test_p() -> BigNumber {
        BigNumber::from_slice(hex::decode("3522d66070bc9a6857796dc78adae186f96ab8ddea108400c103cfc73be0ce19e1bc00e0ec2307377086ab687bb90e28edf7e4a2ca3c723a5023d5b62916fe955ef376ee14a4c4521753b17c836d360794a0ad6e05d605a53d912dd624e8cc23036adc964f2f35148e471924bf22ca6ecdf650db067b63fb72702db004e3b4c5").unwrap())
    }

    fn test_q() -> BigNumber {
        BigNumber::from_slice(hex::decode("80000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000af53b313").unwrap())
    }

    #[test]
    fn abs() {
        let opt_group = Group::with_safe_primes_unchecked(&test_p(), &test_q());
        assert!(opt_group.is_some());
        let group = opt_group.unwrap();
        let n2d2 = group.nn() >> 1;
        // known tests
        let one = BigNumber::one();
        let two = &one + &one;
        assert_eq!(group.abs(&(group.nn() - &one)), one);
        assert_eq!(group.abs(&(group.nn() + &one)), one);
        assert_eq!(group.abs(&(&n2d2 - &one)), &n2d2 - &one);
        assert_eq!(group.abs(&(&n2d2 - &two)), &n2d2 - &two);

        // random tests
        for _ in 0..10 {
            let v = group.random_value();
            let abs_v = group.abs(&v);
            let v_sqr = group.mul(&v, &v);
            let abs_v_sqr = group.mul(&abs_v, &abs_v);
            // v^2 == abs(v)^2
            assert_eq!(v_sqr, abs_v_sqr);
        }
    }

    #[test]
    fn g_exp() {
        let group = serde_json::from_str::<Group>(r#"{"g":"3","n":"1A916B30385E4D342BBCB6E3C56D70C37CB55C6EF50842006081E7E39DF0670CF0DE00707611839BB84355B43DDC871476FBF251651E391D2811EADB148B7F4AAF79BB770A5262290BA9D8BE41B69B03CA5056B702EB02D29EC896EB1274661181B56E4B27979A8A47238C925F91653766FB286D833DB1FDB93816D826D60A653BD0D2AFA196C95265635108BD32EF63C52310B93BB682498D17D16E257F19503FE9D718418AD7A1834C64F125944818674AAF2C2C0BBB12D13D45BCC70D8DB697879FBA820FBEDDE986807AD0F15622D1D9FF7EDE7E29B7547C3DB9A2B3CA6D3E086A1D258B0B3F8B6E5008E3D8A85E744299240FD2064811AEB5E1DB2B299F"}"#).unwrap();
        let one = BigNumber::one();
        let two = &one + &one;
        let three = &two + &one;
        assert_eq!(group.g_pow(&two), BigNumber::from(9));
        assert_eq!(group.g_pow(&three), BigNumber::from(27));
        assert_eq!(group.g_pow(&-one), BigNumber::from_slice(hex::decode("01d692eaedf83c796187e3b62456a5ead541f4e3c31eee2c4bf9858201a4b1865b996e5f453974bfd9cdc9353f6dc67700a568e513f326b651ea9f62f71ea2022a1871aec90c08729a8b2463f8b87d753c82aa6d0915fd9198122d326922b16fc76e549db4479ad2347b6370b63595e65bc588e1924157d71e6f82f42a995213e663c903b60ce84e628da9fd43c1d10263af39ba4feb2fd051adf6b61473910fc73255a45b546742e91f6ccb9aeda7ae72c2b5c4176989c51d960e93709024c9f6a73e87f5131de7a477abe0a2349a5f7015e1e9b999a8e3f0d5ca9ef76fd2e07044aefbb224c3b1531121fff27fa1890f70d079e14f00e56b573851bd19f4e2efab05161c28b13d79036433cd0b524fd41d3dcaa886bdea83477c70e7303e74e437cb708ddd0a60702b94447004b55af2e2a42c86b3383aabac0ae5f2641ab2536262d365c3e91b9eaf0ef3478b7e8f3d4f33d301e837476376d059556585d76ae78ef9901749ce7f63d3f6a30d5c8f2fe01317ac50f0fa0a8cc534938107df30a464c4bcd4db0abd64de3425dfe60e965d3934d74b37bbe2ef67f55e09d567a435a88f1a3981e6e80340cecd13f189d2e583de607c06d359d141fe8a7e1ef50d8e3efef82f2eda5f2f952973d5eb5ae66980cc02ff48ea1bde32b9e745976336d17f5d881e436c9c9eae508f264b8932bff8bea5a11f367b009552081ee081").unwrap()));
    }

    #[test]
    fn hash() {
        let opt_group = Group::with_safe_primes_unchecked(&test_p(), &test_q());
        assert!(opt_group.is_some());
        let group = opt_group.unwrap();

        let u = BigNumber::one();
        let e = vec![BigNumber::one()];
        assert_eq!(group.hash(&u, &e, &[1u8, 1u8]), BigNumber::from_slice(&hex::decode("a5f73f4bad2a587a1afba3237f5604a3d329c9b2e13feee922f643a349352f799f94dc7a3e68db9f6837627076540628828d8260a3b78230b1ad85e2ee161b1e").unwrap()));
        let u = BigNumber::from(2);
        let e = vec![BigNumber::from(2)];
        assert_eq!(group.hash(&u, &e, &[2u8, 2u8]), BigNumber::from_slice(&hex::decode("572b6535c0c9d23b73403e2e5778513626e68c1c013a83e66d98e6e9f4fb8d128839a1508d029512a75886c2c38715f68aa60d5d04f9557bacd3c26e747bdf95").unwrap()));
    }

    #[test]
    fn encrypt_single() {
        let opt_group = Group::with_safe_primes_unchecked(&test_p(), &test_q());
        assert!(opt_group.is_some());
        let group = opt_group.unwrap();

        let opt_keys = group.new_keys(1);
        assert!(opt_keys.is_some());
        let (ek, dk) = opt_keys.unwrap();

        let domain = b"encrypt_single_test";
        for i in 0..50 {
            let m = vec![BigNumber::from(i)];
            let res = ek.encrypt(domain, &m);
            assert!(res.is_ok());
            let ct = res.unwrap();
            let res = dk.decrypt(domain, &ct);
            assert!(res.is_ok());
            assert_eq!(m, res.unwrap());
            assert!(dk.decrypt(b"a different domain", &ct).is_err());
        }
    }

    #[test]
    fn encrypt_multi() {
        let opt_group = Group::with_safe_primes_unchecked(&test_p(), &test_q());
        assert!(opt_group.is_some());
        let group = opt_group.unwrap();

        let opt_keys = group.new_keys(10);
        assert!(opt_keys.is_some());
        let (ek, dk) = opt_keys.unwrap();

        let domain = b"encrypt_multi_test";
        let mut msgs = (0..10)
            .map(|_| group.random_for_encrypt())
            .collect::<Vec<BigNumber>>();
        let res = ek.encrypt(domain, &msgs);
        assert!(res.is_ok());
        let ct = res.unwrap();
        let res = dk.decrypt(domain, &ct);
        assert!(res.is_ok());
        let msgs2 = res.unwrap();
        assert_eq!(msgs, msgs2);
        msgs.push(group.random_for_encrypt());
        assert!(ek.encrypt(domain, &msgs).is_err());
        let res = serde_json::to_string(&ct);
        assert!(res.is_ok());
        let ct_json = res.unwrap();
        let res = serde_json::from_str(&ct_json);
        assert!(res.is_ok());
        assert_eq!(ct, res.unwrap());
    }

    #[test]
    fn encrypt_and_prove_single() {
        let opt_group = Group::with_safe_primes_unchecked(&test_p(), &test_q());
        assert!(opt_group.is_some());
        let group = opt_group.unwrap();

        let opt_keys = group.new_keys(1);
        assert!(opt_keys.is_some());
        let (ek, dk) = opt_keys.unwrap();

        let domain = b"encrypt_and_prove_single_test";
        for i in 0..15 {
            let m = vec![BigNumber::from(i)];
            let res = ek.encrypt_and_prove(domain, &m);
            assert!(res.is_ok());
            let (ct, proof) = res.unwrap();
            let res = ek.verify(domain, &ct, &proof);
            assert!(res.is_ok());
            let res = dk.decrypt(domain, &ct);
            assert!(res.is_ok());
            assert_eq!(m, res.unwrap());
            assert!(dk.decrypt(b"a different domain", &ct).is_err());
        }
    }
}
