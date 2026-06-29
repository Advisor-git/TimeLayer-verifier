use std::env;
use std::fs;
use std::path::Path;

use tl_digest::digest_bytes;
use tl_finality::{decode_tlcert, interval_ref_from_digests};
use tl_receipts::ReceiptStatus;
use tl_verify_public::{verify_bytes, PublicVerdict};

const MAX_CERT_BYTES: u64 = 1024 * 1024;
const MAX_BUNDLE_BYTES: u64 = 16 * 1024 * 1024;

fn usage() -> i32 {
    eprintln!(
        "timelayer-verifier {}\n\
         \n\
         Offline verifier for TimeLayer receipts. No network, no roster lookup:\n\
         a receipt is a self-contained pair of files and verifies on its own.\n\
         \n\
         USAGE:\n    \
             timelayer-verifier verify <cert.tlcert> <bundle.tlbundle> [--expect <hex>]\n    \
             timelayer-verifier --version\n\
         \n\
         --expect <hex> binds the check to a document digest: the receipt must notarize\n    \
             exactly this hex-encoded action digest, or the result is UNVERIFIABLE (exit 1).\n\
         \n\
         OUTPUT:\n    \
             VALID FINAL     the receipt is authentic and complete (exit 0)\n    \
             UNVERIFIABLE    the pair does not verify (exit 1)",
        env!("CARGO_PKG_VERSION")
    );
    1
}

fn run(args: &[String]) -> i32 {
    match args.get(1).map(String::as_str) {
        Some("verify") if args.len() == 4 => {
            verify_files(Path::new(&args[2]), Path::new(&args[3]), None)
        }
        Some("verify") if args.len() == 6 && args[4] == "--expect" => {
            verify_files(Path::new(&args[2]), Path::new(&args[3]), Some(&args[5]))
        }
        Some("--version") | Some("-V") => {
            println!("timelayer-verifier {}", env!("CARGO_PKG_VERSION"));
            0
        }
        _ => usage(),
    }
}

/// Decode a lowercase/uppercase hex string into bytes; None on any non-hex input.
fn hex_to_bytes(value: &str) -> Option<Vec<u8>> {
    if value.len() % 2 != 0 {
        return None;
    }
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(value.len() / 2);
    let mut idx = 0;
    while idx < bytes.len() {
        let hi = (bytes[idx] as char).to_digit(16)?;
        let lo = (bytes[idx + 1] as char).to_digit(16)?;
        out.push(((hi << 4) | lo) as u8);
        idx += 2;
    }
    Some(out)
}

/// Confirm the certificate actually notarizes `expected` (the raw document digest the
/// caller sent as action_hex). The leaf the network binds is
/// `digest_bytes(issued_at_pos_be8 ++ action)`, committed via the certificate's
/// interval_ref — so we recompute it and compare. This is the cryptographic binding:
/// a valid-but-unrelated receipt no longer passes for arbitrary content.
fn cert_attests(cert: &[u8], expected: &[u8]) -> bool {
    let Ok(decoded) = decode_tlcert(cert) else {
        return false;
    };
    let mut material = decoded.issued_at_pos.to_be_bytes().to_vec();
    material.extend_from_slice(expected);
    interval_ref_from_digests(&[digest_bytes(&material)]) == decoded.interval_ref
}

fn read_or_report(path: &Path, max_bytes: u64) -> Option<Vec<u8>> {
    match read_limited(path, max_bytes) {
        Ok(bytes) => Some(bytes),
        Err(error) => {
            eprintln!("{}", error);
            None
        }
    }
}

fn verify_files(cert_path: &Path, bundle_path: &Path, expect_hex: Option<&str>) -> i32 {
    let Some(cert) = read_or_report(cert_path, MAX_CERT_BYTES) else {
        return 1;
    };
    let Some(bundle) = read_or_report(bundle_path, MAX_BUNDLE_BYTES) else {
        return 1;
    };
    match verify_bytes(&cert, Some(&bundle)) {
        PublicVerdict::VALID(ReceiptStatus::FINAL) => {
            if let Some(hex) = expect_hex {
                let Some(expected) = hex_to_bytes(hex) else {
                    eprintln!("UNVERIFIABLE --expect must be a hex digest");
                    return 1;
                };
                if !cert_attests(&cert, &expected) {
                    eprintln!("UNVERIFIABLE receipt does not attest the expected digest");
                    return 1;
                }
            }
            println!("VALID FINAL");
            0
        }
        _ => {
            println!("UNVERIFIABLE");
            1
        }
    }
}

fn read_limited(path: &Path, max_bytes: u64) -> Result<Vec<u8>, String> {
    let metadata = fs::metadata(path).map_err(|error| error.to_string())?;
    if metadata.len() > max_bytes {
        return Err(format!(
            "{} exceeds maximum size {} bytes",
            path.display(),
            max_bytes
        ));
    }
    let bytes = fs::read(path).map_err(|error| error.to_string())?;
    if bytes.len() as u64 > max_bytes {
        return Err(format!(
            "{} exceeds maximum size {} bytes",
            path.display(),
            max_bytes
        ));
    }
    Ok(bytes)
}

fn main() {
    let args: Vec<String> = env::args().collect();
    std::process::exit(run(&args));
}
