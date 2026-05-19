use pqcrypto::sign;
use pqcrypto::traits::sign::{DetachedSignature, PublicKey, SecretKey};
use std::time::Instant;
use indicatif::ProgressBar;
use cli_table::{format::Justify, Cell, Style, Table};

struct BenchResult {
    cycles: u64,
    keygen_ns: u128,
    sign_ns: u128,
    verify_ns: u128,
    pk_bytes: usize,
    sk_bytes: usize,
    sig_bytes: usize,
}

impl BenchResult {
    fn keygen_ms_per_op(&self) -> f64 {
        self.keygen_ns as f64 / self.cycles as f64 / 1_000_000.0
    }
    fn sign_ms_per_op(&self) -> f64 {
        self.sign_ns as f64 / self.cycles as f64 / 1_000_000.0
    }
    fn verify_ms_per_op(&self) -> f64 {
        self.verify_ns as f64 / self.cycles as f64 / 1_000_000.0
    }
}

fn benchmark<KG, SN, VF, PK, SK, SIG, E>(
    name: &str,
    cycles: u64,
    message: &[u8],
    keygen: KG,
    sign: SN,
    verify: VF,
) -> BenchResult
where
    KG: Fn() -> (PK, SK),
    SN: Fn(&[u8], &SK) -> SIG,
    VF: Fn(&SIG, &[u8], &PK) -> Result<(), E>,
    PK: PublicKey,
    SK: SecretKey,
    SIG: DetachedSignature,
    E: std::fmt::Debug,
{
    println!("\nStarting {} computations...", name);
    let pb = ProgressBar::new(cycles);
    let mut sum_keygen = 0u128;
    let mut sum_sign = 0u128;
    let mut sum_verify = 0u128;
    let mut pk_bytes = 0;
    let mut sk_bytes = 0;
    let mut sig_bytes = 0;

    for _ in 0..cycles {
        let now = Instant::now();
        let (pk, sk) = keygen();
        sum_keygen += now.elapsed().as_nanos();

        let now = Instant::now();
        let sig = sign(message, &sk);
        sum_sign += now.elapsed().as_nanos();

        let now = Instant::now();
        verify(&sig, message, &pk).unwrap();
        sum_verify += now.elapsed().as_nanos();

        pk_bytes = pk.as_bytes().len();
        sk_bytes = sk.as_bytes().len();
        sig_bytes = sig.as_bytes().len();

        pb.inc(1);
    }
    pb.finish();

    BenchResult {
        cycles,
        keygen_ns: sum_keygen,
        sign_ns: sum_sign,
        verify_ns: sum_verify,
        pk_bytes,
        sk_bytes,
        sig_bytes,
    }
}

macro_rules! bench {
    ($name:expr, $cycles:expr, $message:expr, $algo:ident) => {
        benchmark(
            $name,
            $cycles,
            $message,
            sign::$algo::keypair,
            sign::$algo::detached_sign,
            sign::$algo::verify_detached_signature,
        )
    };
}

fn print_table(columns: &[(&str, &BenchResult)]) {
    let mut header = vec!["".cell().bold(true)];
    for (name, _) in columns {
        header.push(name.cell().bold(true));
    }

    let mut keygen_row = vec!["Key Gen (ms/op)".cell()];
    let mut sign_row = vec!["Sign (ms/op)".cell()];
    let mut verify_row = vec!["Verify (ms/op)".cell()];
    let mut pk_row = vec!["Public Key (B)".cell()];
    let mut sk_row = vec!["Secret Key (B)".cell()];
    let mut sig_row = vec!["Signature (B)".cell()];
    for (_, r) in columns {
        keygen_row.push(format!("{:.3}", r.keygen_ms_per_op()).cell().justify(Justify::Right));
        sign_row.push(format!("{:.3}", r.sign_ms_per_op()).cell().justify(Justify::Right));
        verify_row.push(format!("{:.3}", r.verify_ms_per_op()).cell().justify(Justify::Right));
        pk_row.push(r.pk_bytes.cell().justify(Justify::Right));
        sk_row.push(r.sk_bytes.cell().justify(Justify::Right));
        sig_row.push(r.sig_bytes.cell().justify(Justify::Right));
    }

    let table = vec![keygen_row, sign_row, verify_row, pk_row, sk_row, sig_row]
        .table()
        .title(header)
        .bold(true);

    println!("\n");
    println!("{}", table.display().unwrap());
}

fn main() {
    println!("Starting performance test with different PQC signing algorithms...");
    let version = env!("CARGO_PKG_VERSION");
    println!("Version {} by H.Funke (May 2026)", version);
    println!("Implementation is based on library pqcrypto v0.18.1 (https://crates.io/crates/pqcrypto)");
    println!("Expanded instruction set of AVX2 and aarch64 are used if supported");

    let message = "This is the message to be signed by various algorithms specificed to be quantum resistent.".as_bytes();
    let number_cycles: u64 = 10;

    println!("\nSize of message to be signed: {}", message.len());
    println!("Number of cycles: {}", number_cycles);

    let ml44 = bench!("ML-DSA-44", number_cycles, message, mldsa44);
    let ml65 = bench!("ML-DSA-65", number_cycles, message, mldsa65);
    let ml87 = bench!("ML-DSA-87", number_cycles, message, mldsa87);

    print_table(&[
        ("ML-DSA-44", &ml44),
        ("ML-DSA-65", &ml65),
        ("ML-DSA-87", &ml87),
    ]);

    let sph_sha2_128f = bench!("Sphincs+-SHA2-128f", number_cycles, message, sphincssha2128fsimple);
    let sph_sha2_128s = bench!("Sphincs+-SHA2-128s", number_cycles, message, sphincssha2128ssimple);
    let sph_sha2_192f = bench!("Sphincs+-SHA2-192f", number_cycles, message, sphincssha2192fsimple);
    let sph_sha2_192s = bench!("Sphincs+-SHA2-192s", number_cycles, message, sphincssha2192ssimple);
    let sph_sha2_256f = bench!("Sphincs+-SHA2-256f", number_cycles, message, sphincssha2256fsimple);
    let sph_sha2_256s = bench!("Sphincs+-SHA2-256s", number_cycles, message, sphincssha2256ssimple);

    print_table(&[
        ("Sphincs+-SHA2-128f", &sph_sha2_128f),
        ("Sphincs+-SHA2-128s", &sph_sha2_128s),
        ("Sphincs+-SHA2-192f", &sph_sha2_192f),
        ("Sphincs+-SHA2-192s", &sph_sha2_192s),
        ("Sphincs+-SHA2-256f", &sph_sha2_256f),
        ("Sphincs+-SHA2-256s", &sph_sha2_256s),
    ]);

    let sph_shake_128f = bench!("Sphincs+-SHAKE-128f", number_cycles, message, sphincsshake128fsimple);
    let sph_shake_128s = bench!("Sphincs+-SHAKE-128s", number_cycles, message, sphincsshake128ssimple);
    let sph_shake_192f = bench!("Sphincs+-SHAKE-192f", number_cycles, message, sphincsshake192fsimple);
    let sph_shake_192s = bench!("Sphincs+-SHAKE-192s", number_cycles, message, sphincsshake192ssimple);
    let sph_shake_256f = bench!("Sphincs+-SHAKE-256f", number_cycles, message, sphincsshake256fsimple);
    let sph_shake_256s = bench!("Sphincs+-SHAKE-256s", number_cycles, message, sphincsshake256ssimple);

    print_table(&[
        ("Sphincs+-SHAKE-128f", &sph_shake_128f),
        ("Sphincs+-SHAKE-128s", &sph_shake_128s),
        ("Sphincs+-SHAKE-192f", &sph_shake_192f),
        ("Sphincs+-SHAKE-192s", &sph_shake_192s),
        ("Sphincs+-SHAKE-256f", &sph_shake_256f),
        ("Sphincs+-SHAKE-256s", &sph_shake_256s),
    ]);

    let falcon512 = bench!("Falcon-512", number_cycles, message, falcon512);
    let falcon512p = bench!("Falcon-512-padded", number_cycles, message, falconpadded512);
    let falcon1024 = bench!("Falcon-1024", number_cycles, message, falcon1024);
    let falcon1024p = bench!("Falcon-1024-padded", number_cycles, message, falconpadded1024);

    print_table(&[
        ("Falcon-512", &falcon512),
        ("Falcon-512-padded", &falcon512p),
        ("Falcon-1024", &falcon1024),
        ("Falcon-1024-padded", &falcon1024p),
    ]);
}
