use anyhow::{Context, Result};
use argon2::{
    password_hash::{PasswordHasher, SaltString},
    Argon2, Params,
};
use clap::Parser;
use rand::{rngs::StdRng, seq::SliceRandom, Rng, SeedableRng};
use serde::Deserialize;
use serde_json::Value;
use std::{fs, path::PathBuf};

/// =========================
/// CLI
/// =========================

#[derive(Parser, Debug)]
#[command(name = "mnemonic-pass")]
struct Args {
    #[arg(short, long)]
    input: PathBuf,

    #[arg(short = 'n', long, default_value_t = 2)]
    count: usize,

    #[arg(short, long, default_value = "-")]
    separator: String,

    #[arg(long)]
    capitalize: bool,

    #[arg(long)]
    leet: bool,

    #[arg(long, default_value_t = 0)]
    digits: usize,

    #[arg(long, default_value_t = 0)]
    symbols: usize,

    #[arg(long)]
    replace: bool,

    #[arg(long)]
    seed: Option<u64>,

    #[arg(long)]
    derive: bool,

    #[arg(long, default_value_t = 65536)]
    argon_mem_kb: u32,

    #[arg(long, default_value_t = 3)]
    argon_iters: u32,

    #[arg(long)]
    config: Option<PathBuf>,
}

#[derive(Deserialize)]
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

/// =========================
/// MAIN FLOW
/// =========================

fn main() -> Result<()> {
    let args = merge_config(Args::parse())?;

    let items = read_items(&args.input)?;
    let mut rng = make_rng(args.seed);

    let mnemonic = build_mnemonic(&items, &args, &mut rng);
    let entropy = estimate_entropy_bits(items.len(), &args);

    println!("Mnemonic: {}", mnemonic);
    println!("(estimated entropy: {:.1} bits)", entropy);

    if args.derive {
        let encoded = derive_argon2(&mnemonic, args.argon_mem_kb, args.argon_iters)?;
        println!("Argon2: {}", encoded);
    }

    Ok(())
}

/// =========================
/// CORE LOGIC
/// =========================

fn build_mnemonic(items: &[String], args: &Args, rng: &mut StdRng) -> String {
    let words = choose_words(items, args.count, args.replace, rng);
    let words = transform_words(words, args.capitalize, args.leet);

    let mut out = words.join(&args.separator);
    append_digits(&mut out, args.digits, rng);
    append_symbols(&mut out, args.symbols, rng);

    out
}

fn choose_words(
    items: &[String],
    count: usize,
    replace: bool,
    rng: &mut StdRng,
) -> Vec<String> {
    if replace || count > items.len() {
        (0..count)
            .map(|_| items.choose(rng).unwrap().clone())
            .collect()
    } else {
        let mut pool = items.to_vec();
        pool.shuffle(rng);
        pool.into_iter().take(count).collect()
    }
}

fn transform_words(words: Vec<String>, capitalize: bool, leet: bool) -> Vec<String> {
    words
        .into_iter()
        .map(|w| {
            let w = if capitalize { capitalize_word(&w) } else { w };
            if leet { leet_word(&w) } else { w }
        })
        .collect()
}

fn capitalize_word(w: &str) -> String {
    let mut chars = w.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().to_string() + chars.as_str(),
        None => String::new(),
    }
}

fn leet_word(w: &str) -> String {
    w.chars()
        .map(|c| match c {
            'a' | 'A' => '4',
            'e' | 'E' => '3',
            'i' | 'I' => '1',
            'o' | 'O' => '0',
            's' | 'S' => '$',
            _ => c,
        })
        .collect()
}

fn append_digits(s: &mut String, count: usize, rng: &mut StdRng) {
    for _ in 0..count {
        s.push(char::from_digit(rng.gen_range(0..10), 10).unwrap());
    }
}

fn append_symbols(s: &mut String, count: usize, rng: &mut StdRng) {
    const SYMBOLS: &[u8] = b"!@#$%^&*?";
    for _ in 0..count {
        s.push(SYMBOLS[rng.gen_range(0..SYMBOLS.len())] as char);
    }
}

/// =========================
/// SUPPORT
/// =========================

fn make_rng(seed: Option<u64>) -> StdRng {
    StdRng::seed_from_u64(seed.unwrap_or_else(|| rand::thread_rng().gen()))
}

fn estimate_entropy_bits(item_count: usize, args: &Args) -> f64 {
    let words = (item_count as f64).powf(args.count as f64).log2();
    let digits = (10f64).powi(args.digits as i32).log2();
    let symbols = (20f64).powi(args.symbols as i32).log2();
    words + digits + symbols
}

fn read_items(path: &PathBuf) -> Result<Vec<String>> {
    let s = fs::read_to_string(path)
        .with_context(|| format!("reading {}", path.display()))?;

    let v: Value = serde_json::from_str(&s)
        .context("parsing JSON")?;

    let arr = match v {
        Value::Array(a) => a,
        Value::Object(ref map) => map
            .get("items")
            .and_then(|v| v.as_array())
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("expected 'items' array"))?,
        _ => anyhow::bail!("invalid JSON structure"),
    };

    let items: Vec<String> = arr
        .into_iter()
        .filter_map(|v| v.as_str().map(String::from))
        .collect();

    if items.is_empty() {
        anyhow::bail!("no valid items found");
    }

    Ok(items)
}

fn derive_argon2(pass: &str, mem_kib: u32, iters: u32) -> Result<String> {
    let salt = SaltString::generate(&mut rand::thread_rng());

    let params = Params::new(mem_kib, iters, 1, None)?;
    let argon2 = Argon2::new(Default::default(), Default::default(), params);

    let hash = argon2
        .hash_password(pass.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("argon2 error: {}", e))?;

    Ok(hash.to_string())
}

fn merge_config(mut args: Args) -> Result<Args> {
    if let Some(path) = &args.config {
        let s = fs::read_to_string(path)
            .with_context(|| format!("reading config {}", path.display()))?;
        let cfg: ConfigFile = toml::from_str(&s)?;

        apply(&mut args.input, cfg.input);
        apply_if_default(&mut args.count, cfg.count, 2);
        apply_if_default(&mut args.separator, cfg.separator, "-".into());
        apply_bool(&mut args.capitalize, cfg.capitalize);
        apply_bool(&mut args.leet, cfg.leet);
        apply_if_default(&mut args.digits, cfg.digits, 0);
        apply_if_default(&mut args.symbols, cfg.symbols, 0);
        apply_bool(&mut args.replace, cfg.replace);
        if args.seed.is_none() {
            args.seed = cfg.seed;
        }
        apply_bool(&mut args.derive, cfg.derive);
        apply_if_default(&mut args.argon_mem_kb, cfg.argon_mem_kb, 65536);
        apply_if_default(&mut args.argon_iters, cfg.argon_iters, 3);
    }
    Ok(args)
}

fn apply<T>(target: &mut T, val: Option<T>) {
    if let Some(v) = val {
        *target = v;
    }
}

fn apply_if_default<T: PartialEq>(target: &mut T, val: Option<T>, default: T) {
    if *target == default {
        if let Some(v) = val {
            *target = v;
        }
    }
}

fn apply_bool(target: &mut bool, val: Option<bool>) {
    if !*target {
        if let Some(v) = val {
            *target = v;
        }
    }
}
