use std::collections::{HashMap, HashSet};
use rand::{rngs::OsRng, RngCore};
use crate::{
    bls381_helpers::{Scalar, G1G2, hash_with_domain_separation, multi_pairing},
    pedersen::{Commitment, Proof2PK},
    tsw::{PublicKey, SecretKey, Signature},
    tACT::{PublicParameters as tACTPublicParameters, Issuer, setup as tACT_setup, register, token_request, tissue, aggregate_unblind, prove, verify, BlindRequest, Rand, Token, TokenProof},
};

// Define types for clarity
type Fp = Scalar; 
type Token = (Commitment, Signature); 
type ElID = G1G2; 

// NPR PRF: H(i)^k
fn prf(k: &Scalar, i: usize) -> G1G2 {
    let hashed_i = hash_with_domain_separation(&i.to_le_bytes(), b"PRF-domain");
    hashed_i * *k
}

pub fn spirit_setup(t: usize, n: usize, num_issuers: usize) -> (tACTPublicParameters, Vec<Issuer>, G1G2, Fp, HashSet<Token>) {
    let mut rng = OsRng;

    let (pp_prime, issuers) = tACT_setup(num_issuers, n, t, t - 1, 1).expect("tACT setup failed");

    
    let h: G1G2 = G1G2::random(&mut rng);
    let hash_fp: Fp = Scalar::random(&mut rng);

    
    let t_rgstr: HashSet<Token> = HashSet::new();

    
    (pp_prime, issuers, h, hash_fp, t_rgstr)
}


pub fn spirit_register(
    id_u: Scalar,
    issuers: &[Issuer],
    pp: &tACTPublicParameters,
    t_rgstr: &mut HashSet<Token>,
) -> Option<(Token, Scalar, HashSet<Token>)> {
    let mut rng = OsRng;

    
    let (strg, cm) = register(&id_u, pp).ok()?;

    
    let (blind_request, rand) = token_request(&strg, &cm, pp).ok()?;

    
    let mut blind_tokens = Vec::new();
    for issuer in issuers.iter().take(pp.t) {
        let blind_token = tissue(&blind_request, issuer, pp).ok()?;
        blind_tokens.push(blind_token);
    }

    
    let token = aggregate_unblind(&blind_tokens, &rand, pp);

    
    let token_proof = prove(&token, &rand, pp);
    if verify(&token, &token_proof, &blind_request, pp).is_err() {
        return None;
    }

    
    let cmk = cm.clone();
    let final_token = (cmk, token.s.clone());
    t_rgstr.insert(final_token.clone());

    
    Some((final_token, id_u, t_rgstr.clone()))
}


pub fn spirit_broadcast(i: usize, prv: &Scalar, t_el: &mut HashMap<ElID, Scalar>) -> HashMap<ElID, Scalar> {
    let mut rng = OsRng;

    
    let el_id = prf(prv, i);

    
    let es_i = Scalar::random(&mut rng); 
    t_el.insert(el_id, es_i);

    
    t_el.clone()
}


pub fn spirit_diagnosis(
    ppu: (Token, Scalar),
    prv: &Scalar,
    cp: &HashSet<usize>,
) -> Option<((Token, Scalar), Scalar, ElID)> {
    let (token, _id_u) = ppu;
    let (cmk, token_sig) = token;

    
    let tr: Vec<ElID> = cp.iter().map(|i| prf(prv, *i)).collect();

    
    let pi_r = Proof2PK::zk_proof(&cmk.0, &token_sig.0, &el_id); 

    
    Some((ppu, pi_r, el_id))
}


pub fn spirit_verify(
    tr: ((Token, Scalar), Scalar, ElID),
    t_rgstr: &HashSet<Token>,
    cp: &mut HashSet<ElID>,
) -> (HashSet<ElID>, bool) {
    let ((ppu, _), pi_r, el_id) = tr;
    let (token, _) = ppu;
    let (cmk, token_sig) = token;

    
    let bit = if t_rgstr.contains(&token) && Proof2PK::zk_verify(&cmk.0, &pi_r) {
        1
    } else {
        0
    };

    
    if bit == 1 && cp.contains(&el_id) {
        cp.insert(el_id);
    } else {
        cp.remove(&el_id);
    }

    
    (cp.clone(), bit == 1)
}


pub fn spirit_trace(
    cf: &HashSet<ElID>,
    t_el: &HashMap<ElID, Scalar>,
    exposure_limit: usize,
) -> (usize, bool) {
    let mut int_cnt = 0;

    
    for el_id in cf.iter() {
        if t_el.contains_key(el_id) {
            int_cnt += 1;
        }
    }

    
    let alarm_bit = int_cnt >= exposure_limit;

    
    (int_cnt, alarm_bit)
}