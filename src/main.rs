//! TimeLayer offline verifier — checks a signed receipt (.tlsig) against the
//! public roster: recomputes the root from the receipt's content and counts
//! >= k valid Ed25519 signatures from distinct signers in the roster.

use std::fs;
use std::path::Path;

use timelayer_verifier::proof::QuorumMode;
use timelayer_verifier::receipt::SignedReceipt;
use timelayer_verifier::roster::parse_roster;

fn usage() {
    eprintln!(
        "TimeLayer verifier {}
usage:
  timelayer-verifier verify <receipt.tlsig> <roster.txt> <k> [by_node|by_operator]
  timelayer-verifier testvec gen <dir>     # write roster.txt + valid.tlsig + forged.tlsig
  timelayer-verifier --version             # print version",
        env!("CARGO_PKG_VERSION")
    );
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let code = match args.get(1).map(String::as_str) {
        Some("--version") | Some("-V") | Some("version") => {
            println!("timelayer-verifier {}", env!("CARGO_PKG_VERSION"));
            0
        }
        Some("verify") if args.len() >= 5 => verify(
            Path::new(&args[2]),
            Path::new(&args[3]),
            &args[4],
            args.get(5).map(String::as_str).unwrap_or("by_node"),
        ),
        Some("testvec") if args.get(2).map(String::as_str) == Some("gen") && args.len() == 4 => {
            testvec_gen(Path::new(&args[3]))
        }
        _ => {
            usage();
            2
        }
    };
    std::process::exit(code);
}

fn verify(tlsig: &Path, roster_path: &Path, k_str: &str, mode_str: &str) -> i32 {
    let bytes = match fs::read(tlsig) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("read {}: {}", tlsig.display(), e);
            return 1;
        }
    };
    let receipt = match SignedReceipt::decode(&bytes) {
        Some(r) => r,
        None => {
            println!("NOT VALID (malformed .tlsig)");
            return 1;
        }
    };
    let roster_text = match fs::read_to_string(roster_path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("read roster {}: {}", roster_path.display(), e);
            return 1;
        }
    };
    let roster = match parse_roster(&roster_text) {
        Some(r) => r,
        None => {
            eprintln!("malformed roster");
            return 1;
        }
    };
    let k: usize = match k_str.parse() {
        Ok(v) => v,
        Err(_) => {
            eprintln!("k must be a number");
            return 1;
        }
    };
    let mode = if mode_str == "by_operator" {
        QuorumMode::ByOperator
    } else {
        QuorumMode::ByNode
    };
    let v = receipt.verify(&roster, k, mode);
    if v.valid {
        println!("VALID (signers={} k={} mode={})", v.distinct_signers, k, mode_str);
        0
    } else {
        println!("NOT VALID (signers={} k={} mode={})", v.distinct_signers, k, mode_str);
        1
    }
}

fn testvec_gen(dir: &Path) -> i32 {
    use timelayer_verifier::proof::CohortSig;
    use timelayer_verifier::roster::{to_line, NodeStatus, RosterEntry};
    use timelayer_verifier::{core_fields_from_interval, keygen, sign_root, IntervalInputs, ALG_ED25519};

    if let Err(e) = fs::create_dir_all(dir) {
        eprintln!("{}", e);
        return 1;
    }
    let n = 6usize;
    let peers: Vec<String> = (0..n).map(|i| format!("node-{}", i)).collect();
    let ring: Vec<u64> = (0..n as u64).collect();
    let digs: Vec<[u8; 32]> = (0..n)
        .map(|i| {
            let mut d = [0u8; 32];
            d[0] = i as u8;
            d
        })
        .collect();
    let mut seeds = Vec::new();
    let mut roster_lines = vec!["epoch=1".to_string()];
    for i in 0..n {
        let (s, pk) = keygen().unwrap();
        seeds.push(s);
        roster_lines.push(to_line(&RosterEntry {
            node_id: format!("node-{}", i),
            pubkey: pk,
            alg: ALG_ED25519,
            operator: format!("op-{}", i),
            region: "EU".into(),
            status: NodeStatus::Active,
            valid_from: 0,
            valid_to: None,
        }));
    }
    let _ = fs::write(dir.join("roster.txt"), roster_lines.join("\n") + "\n");

    let mk = |iref: [u8; 32]| {
        core_fields_from_interval(&IntervalInputs {
            interval_ref: iref,
            prev_interval_ref: [0; 32],
            cohort_id: "trial",
            issued_at_pos: 1,
            issuer_node_id: "node-0",
            nonce: [0x22; 16],
            roster_epoch: 1,
            local_digest: [0x33; 32],
            shadow_digest: [0x44; 32],
            replay_params: b"rp",
            peers: &peers,
            ring_indices: &ring,
            peer_new_digests: &digs,
        })
    };
    // valid: signed by all 6 roster operators
    let core = mk([0x11; 32]);
    let root = core.root();
    let proof: Vec<CohortSig> = (0..n)
        .map(|i| CohortSig { node_id: format!("node-{}", i), alg: ALG_ED25519, sig: sign_root(&seeds[i], &root) })
        .collect();
    let _ = fs::write(dir.join("valid.tlsig"), SignedReceipt { core, cohort_proof: proof }.encode());
    // forged: a new document signed by keys NOT on the roster
    let fcore = mk([0xAA; 32]);
    let froot = fcore.root();
    let fproof: Vec<CohortSig> = (0..n)
        .map(|i| {
            let (atk, _pk) = keygen().unwrap();
            CohortSig { node_id: format!("node-{}", i), alg: ALG_ED25519, sig: sign_root(&atk, &froot) }
        })
        .collect();
    let _ = fs::write(dir.join("forged.tlsig"), SignedReceipt { core: fcore, cohort_proof: fproof }.encode());
    println!("wrote roster.txt, valid.tlsig (-> VALID), forged.tlsig (-> NOT VALID) at k=6 by_operator");
    0
}
