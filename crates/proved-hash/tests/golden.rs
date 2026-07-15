//! Vérifie que l'implémentation reproduit les golden vectors (cross-langage).

use proved_hash::amount::AmountLimbs;
use proved_hash::digest::Digest;
use proved_hash::domain::{sponge_preamble, Domain};
use proved_hash::felt::Felt;

const VECTORS: &str = include_str!("../vectors/encoding_v1.json");

#[test]
fn ancrage_externe_permutation_sage() {
    // Vecteur de la permutation Rp64_256 issu de l'implémentation de référence Sage
    // (tests publiés de winter-crypto). Le reproduire ancre notre dépendance sur une
    // SECONDE implémentation indépendante : on n'est pas seulement cohérent avec nous-mêmes.
    use winter_crypto::hashers::Rp64_256;
    use winter_math::fields::f64::BaseElement;
    let mut state: [BaseElement; 12] = core::array::from_fn(|i| BaseElement::new(i as u64));
    Rp64_256::apply_permutation(&mut state);
    let expected: [u64; 12] = [
        11084501481526603421,
        6291559951628160880,
        13626645864671311919,
        18397438323058963117,
        7443014167353970324,
        17930833023906771425,
        4275355080008025761,
        7676681476902901785,
        3460534574143792217,
        11912731278641497187,
        8104899243369883110,
        674509706691634438,
    ];
    for (i, e) in expected.iter().enumerate() {
        assert_eq!(state[i], BaseElement::new(*e));
    }
}

#[test]
fn rescue_vecteurs_figes() {
    use proved_hash::rescue::{hash, merge};
    let v: serde_json::Value = serde_json::from_str(VECTORS).unwrap();
    let rh = &v["rescue_hash"];
    let f = |x| Felt::from_canonical_u64(x).unwrap();

    let owner = hash(Domain::Owner, &[f(7), f(8)]);
    assert_eq!(owner.to_hex(), rh["hash_owner_7_8"].as_str().unwrap());

    let a = hash(Domain::NoteCommitment, &[f(1)]);
    let b = hash(Domain::NoteCommitment, &[f(2)]);
    let node = merge(Domain::MerkleNode, &a, &b);
    assert_eq!(
        node.to_hex(),
        rh["merge_merklenode_of_nc1_nc2"].as_str().unwrap()
    );
}

#[test]
fn digest_bytes_correspondent() {
    let v: serde_json::Value = serde_json::from_str(VECTORS).unwrap();
    let d0 = &v["digest"][0];
    let felts: Vec<Felt> = d0["felts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| Felt::from_canonical_u64(x.as_u64().unwrap()).unwrap())
        .collect();
    let digest = Digest([felts[0], felts[1], felts[2], felts[3]]);
    assert_eq!(digest.to_hex(), d0["bytes_hex"].as_str().unwrap());
    // serde round-trip canonique (hex string)
    let json = serde_json::to_string(&digest).unwrap();
    assert_eq!(serde_json::from_str::<Digest>(&json).unwrap(), digest);
}

#[test]
fn amount_limbs_correspondent() {
    let v: serde_json::Value = serde_json::from_str(VECTORS).unwrap();
    for a in v["amount_limbs"].as_array().unwrap() {
        let x = a["u64"].as_u64().unwrap();
        let expected: Vec<u16> = a["limbs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|l| l.as_u64().unwrap() as u16)
            .collect();
        assert_eq!(AmountLimbs::from_u64(x).limbs().to_vec(), expected);
    }
}

#[test]
fn preambules_correspondent() {
    let v: serde_json::Value = serde_json::from_str(VECTORS).unwrap();
    let p = &v["preambles"][0];
    let payload: Vec<Felt> = p["payload"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| Felt::from_small(x.as_u64().unwrap() as u32))
        .collect();
    let got: Vec<u64> = sponge_preamble(Domain::Owner, &payload)
        .iter()
        .map(|f| f.as_u64())
        .collect();
    let expected: Vec<u64> = p["fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_u64().unwrap())
        .collect();
    assert_eq!(got, expected);
}
