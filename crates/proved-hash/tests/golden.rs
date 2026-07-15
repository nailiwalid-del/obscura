//! Vérifie que l'implémentation reproduit les golden vectors (cross-langage).

use proved_hash::amount::AmountLimbs;
use proved_hash::digest::Digest;
use proved_hash::domain::{sponge_preamble, Domain};
use proved_hash::felt::Felt;

const VECTORS: &str = include_str!("../vectors/encoding_v1.json");

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
