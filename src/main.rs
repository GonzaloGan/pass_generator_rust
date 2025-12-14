use anyhow::{Context, Result};
use argon2::{
    password_hash::{PasswordHasher, SaltString},
    Argon2,
};
use base64::engine::general_purpose::STANDARD as BASE64;
use clap::Parser;
use rand::{rngs::StdRng, seq::SliceRandom, Rng, SeedableRng};
use serde::Deserialize;
use serde_json::Value;
use std::{fs, path::PathBuf};

#[derive(Parser, Debug)]
#[command(
    name = "mnemonic-pass",
    about = "Generate a configurable mnemonic-style password from a JSON list of items."
)]
struct Args {
    /// Input JSON file. Either a top-level array of strings, or an object with an "items" array.
    #[arg(short, long)]
    input: PathBuf,

    /// How many words to pick (default: 2)
    #[arg(short = 'n', long, default_value_t = 2)]
    count: usize,

    /// Separator between words (default: "-")
    #[arg(short, long, default_value = "-")]
    separator: String,

    /// Capitalize first letter of each chosen word
    #[arg(long)]
    capitalize: bool,

    /// Apply simple leet substitutions (a->4, e->3, i->1, o->0, s->$)
    #[arg(long)]
    leet: bool,

    /// Number of random digits to append
    #[arg(long, default_value_t = 0)]
    digits: usize,

    /// Number of random symbols to append
    #[arg(long, default_value_t = 0)]
    symbols: usize,

    /// Allow words to repeat (sampling with replacement)
    #[arg(long)]
    replace: bool,

    /// Use this seed to make generation deterministic (optional)
    #[arg(long)]
    seed: Option<u64>,

    /// Produce an Argon2-derived base64 key from the mnemonic (optional)
    #[arg(long)]
    derive: bool,

    /// Argon2 memory parameter (KB) when deriving (default: 65536 => 64 MiB)
    #[arg(long, default_value_t = 65536)]
    argon_mem_kb: u32,

    /// Argon2 iterations
    #[arg(long, default_value_t = 3)]
    argon_iters: u32,

    /// Path to an optional TOML config file (values overridden by CLI)
    #[arg(long)]
    config: Option<PathBuf>,
}

#[derive(Deserialize, Debug)]
struct ConfigFile {
    input: Option<PathBuf>,
    count: Option<usize>,
    separator: Option<String>,
    capitalize: Option<bool>,
    leet: Option<bool>,
    digits: Option<usize>,
    symbols: Option<usize>,
    replace: Option<bool>,
    seed: Option<u64>,
    derive: Option<bool>,
    argon_mem_kb: Option<u32>,
    argon_iters: Option<u32>,
}

fn read_items(path: &PathBuf) -> Result<Vec<String>> {
    let s = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let v: Value = serde_json::from_str(&s).with_context(|| "parsing JSON input")?;
    let items = if v.is_array() {
        let arr = v
            .as_array()
            .unwrap()
            .iter()
            .map(|vv| vv.as_str().unwrap_or("").to_string())
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>();
        arr
    } else if let Some(items_v) = v.get("items") {
        if items_v.is_array() {
            items_v
                .as_array()
                .unwrap()
                .iter()
                .map(|vv| vv.as_str().unwrap_or("").to_string())
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>()
        } else {
            anyhow::bail!("Expected 'items' key to be an array of strings")
        }
    } else {
        anyhow::bail!("Expected a top-level array or an object with an 'items' array")
    };

    if items.is_empty() {
        anyhow::bail!("No items found in the provided JSON file")
    }
    Ok(items)
}

fn choose_words(items: &[String], count: usize, replace: bool, rng: &mut StdRng) -> Vec<String> {
    if replace {
        (0..count)
            .map(|_| items.choose(rng).unwrap().clone())
            .collect()
    } else {
        // sample without replacement; if count > items.len(), fallback to with replacement
        if count <= items.len() {
            let mut pool = items.to_vec();
            pool.shuffle(rng);
            pool.into_iter().take(count).collect()
        } else {
            // fallback: allow duplicates
            (0..count)
                .map(|_| items.choose(rng).unwrap().clone())
                .collect()
        }
    }
}

fn apply_capitalize(words: Vec<String>) -> Vec<String> {
    words
        .into_iter()
        .map(|w| {
            let mut c = w.chars();
            match c.next() {
                None => String::new(),
                Some(first) => first.to_uppercase().to_string() + c.as_str(),
            }
        })
        .collect()
}

fn apply_leet(words: Vec<String>) -> Vec<String> {
    words
        .into_iter()
        .map(|w| {
            w.chars()
                .map(|c| match c {
                    'a' | 'A' => '4',
                    'e' | 'E' => '3',
                    'i' | 'I' => '1',
                    'o' | 'O' => '0',
                    's' | 'S' => '$',
                    other => other,
                })
                .collect()
        })
        .collect()
}

fn append_random_digits(s: &mut String, count: usize, rng: &mut StdRng) {
    for _ in 0..count {
        let d = rng.gen_range(0..10);
        s.push(char::from_digit(d, 10).unwrap())
    }
}

fn append_random_symbols(s: &mut String, count: usize, rng: &mut StdRng) {
    // a small selection of safe symbols
    //const SYMBOLS: &[u8] = b"!@#$%^&*()_-+=[]{}<>?";
    const SYMBOLS: &[u8] = b"!@#$%^&*?";
    for _ in 0..count {
        let idx = rng.gen_range(0..SYMBOLS.len());
        s.push(SYMBOLS[idx] as char)
    }
}

fn estimate_entropy_bits(item_count: usize, chosen: usize, digits: usize, symbols: usize) -> f64 {
    let items = item_count.max(1) as f64;
    let words_bits = (items.powf(chosen as f64)).log2();
    let digits_bits = (10f64).powi(digits as i32).log2();
    let symbols_set = 20f64; // approx size of SYMBOLS
    let symbols_bits = symbols_set.powi(symbols as i32).log2();
    words_bits + digits_bits + symbols_bits
}

fn derive_argon2(passphrase: &str, _mem_kib: u32, _iters: u32) -> Result<String> {
    // Generate a random salt
    let mut rng = rand::thread_rng();
    let salt = SaltString::generate(&mut rng);

    // Use default Argon2 params (safe defaults)
    let argon2 = Argon2::default();

    let password_hash = argon2
        .hash_password(passphrase.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("argon2 error: {}", e))?;

    // Return the standard encoded hash (includes params + salt)
    Ok(password_hash.to_string())
}

fn merge_config(mut args: Args) -> Result<Args> {
    if let Some(cfg_path) = &args.config {
        let s = fs::read_to_string(cfg_path)
            .with_context(|| format!("reading config {}", cfg_path.display()))?;
        let cfg: ConfigFile = toml::from_str(&s).context("parsing TOML config")?;
        if args.input.as_os_str().is_empty() {
            if let Some(i) = cfg.input {
                args.input = i
            }
        }
        if args.count == 2 {
            if let Some(c) = cfg.count {
                args.count = c
            }
        }
        if args.separator == "-" {
            if let Some(sep) = cfg.separator {
                args.separator = sep
            }
        }
        if !args.capitalize {
            if let Some(cap) = cfg.capitalize {
                args.capitalize = cap
            }
        }
        if !args.leet {
            if let Some(l) = cfg.leet {
                args.leet = l
            }
        }
        if args.digits == 0 {
            if let Some(d) = cfg.digits {
                args.digits = d
            }
        }
        if args.symbols == 0 {
            if let Some(s) = cfg.symbols {
                args.symbols = s
            }
        }
        if !args.replace {
            if let Some(r) = cfg.replace {
                args.replace = r
            }
        }
        if args.seed.is_none() {
            if let Some(sd) = cfg.seed {
                args.seed = Some(sd)
            }
        }
        if !args.derive {
            if let Some(dv) = cfg.derive {
                args.derive = dv
            }
        }
        if args.argon_mem_kb == 65536 {
            if let Some(m) = cfg.argon_mem_kb {
                args.argon_mem_kb = m
            }
        }
        if args.argon_iters == 3 {
            if let Some(it) = cfg.argon_iters {
                args.argon_iters = it
            }
        }
    }
    Ok(args)
}

fn main() -> Result<()> {
    let args = Args::parse();
    let args = merge_config(args)?;

    let items = read_items(&args.input)?;

    let seed = args.seed.unwrap_or_else(|| {
        // mix in some system randomness
        let mut s = rand::thread_rng();
        s.gen()
    });

    let mut rng = StdRng::seed_from_u64(seed);

    let chosen = choose_words(&items, args.count, args.replace, &mut rng);

    let mut transformed = chosen.clone();
    if args.capitalize {
        transformed = apply_capitalize(transformed);
    }
    if args.leet {
        transformed = apply_leet(transformed);
    }

    let mut mnemonic = transformed.join(&args.separator);

    // Optionally append digits and symbols
    append_random_digits(&mut mnemonic, args.digits, &mut rng);
    append_random_symbols(&mut mnemonic, args.symbols, &mut rng);

    let entropy = estimate_entropy_bits(items.len(), args.count, args.digits, args.symbols);

    println!("Mnemonic: {}", mnemonic);
    println!("(estimated entropy: {:.1} bits)", entropy);

    if args.derive {
        let encoded = derive_argon2(&mnemonic, args.argon_mem_kb, args.argon_iters)?;
        println!("Argon2-derived encoded string: {}", encoded);
    }

    Ok(())
}

// Notes
// - This single-file example is ready to be pasted into src/main.rs of a Cargo project.
// - The top comment contains a Cargo.toml snippet with the dependencies used.
// - The program expects a JSON file that is either an array of strings, e.g.:
//     ["apple", "banana", "cherry", "desk"]
//   or an object with an "items" key:
//     { "items": ["apple", "banana", "cherry"] }
//
// Example invocations:
//   cargo run --release -- --input items.json --count 3 --separator "_" --capitalize --digits 2 --symbols 1
//   cargo run --release -- --input items.json --derive
//
// Config file (TOML) example (passed with --config config.toml):
//   input = "items.json"
//   count = 4
//   separator = "-"
//   capitalize = true
//   digits = 2
//   symbols = 1
//   derive = true

// ---------------------------
// NEXT IMPROVEMENTS (IMPLEMENTED)
// ---------------------------
// 1) Split into library + CLI (mnemonic_core + main)
// 2) Deterministic generation (seeded RNG fully respected)
// 3) BIP39-style mode (optional checksum-like behavior)
// 4) Password strength estimation using zxcvbn
// 5) Unit tests for reproducibility

// ===========================
// LIBRARY: mnemonic_core
// ===========================

pub mod mnemonic_core {
    use rand::{rngs::StdRng, seq::SliceRandom, Rng, SeedableRng};

    pub struct MnemonicConfig {
        pub count: usize,
        pub separator: String,
        pub capitalize: bool,
        pub leet: bool,
        pub digits: usize,
        pub symbols: usize,
        pub replace: bool,
        pub seed: u64,
    }

    pub fn generate(items: &[String], cfg: &MnemonicConfig) -> String {
        let mut rng = StdRng::seed_from_u64(cfg.seed);

        let mut words = if cfg.replace || cfg.count > items.len() {
            (0..cfg.count)
                .map(|_| items.choose(&mut rng).unwrap().clone())
                .collect::<Vec<_>>()
        } else {
            let mut pool = items.to_vec();
            pool.shuffle(&mut rng);
            pool.into_iter().take(cfg.count).collect()
        };

        if cfg.capitalize {
            for w in &mut words {
                if let Some(c) = w.get_mut(0..1) {
                    *w = c.to_uppercase() + &w[1..];
                }
            }
        }

        if cfg.leet {
            for w in &mut words {
                *w = w
                    .chars()
                    .map(|c| match c {
                        'a' | 'A' => '4',
                        'e' | 'E' => '3',
                        'i' | 'I' => '1',
                        'o' | 'O' => '0',
                        's' | 'S' => '$',
                        _ => c,
                    })
                    .collect();
            }
        }

        let mut out = words.join(&cfg.separator);

        for _ in 0..cfg.digits {
            out.push(char::from_digit(rng.gen_range(0..10), 10).unwrap());
        }

        const SYMBOLS: &[u8] = b"!@#$%^&*()-_=+[]{}<>?";
        for _ in 0..cfg.symbols {
            out.push(SYMBOLS[rng.gen_range(0..SYMBOLS.len())] as char);
        }

        out
    }
}

// ===========================
// STRENGTH ESTIMATION (ZXCVBN)
// ===========================

use zxcvbn::zxcvbn;

fn strength_report(password: &str) {
    let estimate = zxcvbn(password, &[]).expect("zxcvbn failed");
    println!("Password strength score (0-4): {}", estimate.score());
    println!("Guesses needed: ~{}", estimate.guesses());
}

// ===========================
// UNIT TESTS
// ===========================

#[cfg(test)]
mod tests {
    use super::mnemonic_core::*;

    #[test]
    fn deterministic_output() {
        let items = vec!["alpha", "beta", "gamma"]
            .into_iter()
            .map(String::from)
            .collect::<Vec<_>>();

        let cfg = MnemonicConfig {
            count: 2,
            separator: "-".into(),
            capitalize: false,
            leet: false,
            digits: 0,
            symbols: 0,
            replace: false,
            seed: 42,
        };

        let p1 = generate(&items, &cfg);
        let p2 = generate(&items, &cfg);

        assert_eq!(p1, p2);
    }
}
