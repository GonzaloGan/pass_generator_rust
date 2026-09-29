use anyhow::{anyhow, bail, Context, Result};
use argon2::{Algorithm, Argon2, Params, PasswordHasher, Version};
use clap::Parser;
use rand::{
    rngs::{StdRng, SysRng},
    seq::{IndexedRandom, SliceRandom},
    RngExt, SeedableRng,
};
use serde::Deserialize;
use serde_json::Value;
use std::{
    fs,
    path::{Path, PathBuf},
};

const SYMBOLS: &[u8] = b"!@#$%^&*?";

/// =========================
/// CLI
/// =========================

#[derive(Parser, Debug)]
#[command(name = "mnemonic-pass")]
struct Cli {
    /// Word list JSON file (here or in the config file)
    #[arg(short, long)]
    input: Option<PathBuf>,

    /// Number of words [default: 2]
    #[arg(short = 'n', long)]
    count: Option<usize>,

    /// Word separator [default: -]
    #[arg(short, long)]
    separator: Option<String>,

    #[arg(long)]
    capitalize: bool,

    #[arg(long)]
    leet: bool,

    /// Digits to append [default: 0]
    #[arg(long)]
    digits: Option<usize>,

    /// Symbols to append [default: 0]
    #[arg(long)]
    symbols: Option<usize>,

    /// Sample words with replacement
    #[arg(long)]
    replace: bool,

    /// RNG seed for reproducible output (not secure)
    #[arg(long)]
    seed: Option<u64>,

    #[arg(long)]
    derive: bool,

    /// Argon2 memory cost in KiB [default: 65536]
    #[arg(long)]
    argon_mem_kb: Option<u32>,

    /// Argon2 iterations [default: 3]
    #[arg(long)]
    argon_iters: Option<u32>,

    /// TOML config file; CLI flags take precedence
    #[arg(long)]
    config: Option<PathBuf>,
}

#[derive(Deserialize, Default)]
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

/// Fully-resolved options: CLI > config file > defaults.
struct Settings {
    input: PathBuf,
    count: usize,
    separator: String,
    capitalize: bool,
    leet: bool,
    digits: usize,
    symbols: usize,
    replace: bool,
    seed: Option<u64>,
    derive: bool,
    argon_mem_kb: u32,
    argon_iters: u32,
}

/// =========================
/// MAIN FLOW
/// =========================

fn main() -> Result<()> {
    let cli = Cli::parse();
    let cfg = load_config(cli.config.as_deref())?;
    let settings = resolve(cli, cfg)?;

    let items = read_items(&settings.input)?;
    if !settings.replace && settings.count > items.len() {
        bail!(
            "count ({}) exceeds word list size ({}); use --replace to sample with replacement",
            settings.count,
            items.len()
        );
    }

    let mut rng = make_rng(settings.seed)?;
    let mnemonic = build_mnemonic(&items, &settings, &mut rng);
    let entropy = estimate_entropy_bits(items.len(), &settings);

    println!("Mnemonic: {mnemonic}");
    eprintln!("(estimated entropy: {entropy:.1} bits)");

    if settings.derive {
        let encoded = derive_argon2(&mnemonic, settings.argon_mem_kb, settings.argon_iters)?;
        println!("Argon2: {encoded}");
    }

    Ok(())
}

/// =========================
/// CORE LOGIC
/// =========================

fn build_mnemonic(items: &[String], settings: &Settings, rng: &mut StdRng) -> String {
    let words = choose_words(items, settings.count, settings.replace, rng);
    let words = transform_words(words, settings.capitalize, settings.leet);

    let mut out = words.join(&settings.separator);
    append_digits(&mut out, settings.digits, rng);
    append_symbols(&mut out, settings.symbols, rng);

    out
}

fn choose_words(
    items: &[String],
    count: usize,
    replace: bool,
    rng: &mut StdRng,
) -> Vec<String> {
    if replace {
        (0..count)
            .map(|_| items.choose(rng).expect("word list is non-empty").clone())
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
        s.push(char::from_digit(rng.random_range(0..10), 10).unwrap());
    }
}

fn append_symbols(s: &mut String, count: usize, rng: &mut StdRng) {
    for _ in 0..count {
        s.push(SYMBOLS[rng.random_range(0..SYMBOLS.len())] as char);
    }
}

/// =========================
/// SUPPORT
/// =========================

fn make_rng(seed: Option<u64>) -> Result<StdRng> {
    match seed {
        // seed_from_u64 caps entropy at 64 bits: reproducibility only, not secure
        Some(s) => Ok(StdRng::seed_from_u64(s)),
        None => StdRng::try_from_rng(&mut SysRng).map_err(|e| anyhow!("OS RNG unavailable: {e}")),
    }
}

fn estimate_entropy_bits(item_count: usize, settings: &Settings) -> f64 {
    let words: f64 = if settings.replace {
        (item_count as f64).log2() * settings.count as f64
    } else {
        // without replacement: log2 of falling factorial n*(n-1)*...*(n-count+1)
        (0..settings.count)
            .map(|i| ((item_count - i) as f64).log2())
            .sum()
    };
    let digits = settings.digits as f64 * 10f64.log2();
    let symbols = settings.symbols as f64 * (SYMBOLS.len() as f64).log2();
    words + digits + symbols
}

fn read_items(path: &Path) -> Result<Vec<String>> {
    let s = fs::read_to_string(path)
        .with_context(|| format!("reading {}", path.display()))?;
    parse_items(&s)
}

fn parse_items(s: &str) -> Result<Vec<String>> {
    let v: Value = serde_json::from_str(s)
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
    let params = Params::new(mem_kib, iters, 1, None)
        .map_err(|e| anyhow!("argon2 params: {e}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::default(), params);

    // hash_password generates a random salt via the getrandom feature
    let hash = argon2
        .hash_password(pass.as_bytes())
        .map_err(|e| anyhow!("argon2 error: {e}"))?;

    Ok(hash.to_string())
}

fn load_config(path: Option<&Path>) -> Result<ConfigFile> {
    match path {
        Some(p) => {
            let s = fs::read_to_string(p)
                .with_context(|| format!("reading config {}", p.display()))?;
            toml::from_str(&s).with_context(|| format!("parsing config {}", p.display()))
        }
        None => Ok(ConfigFile::default()),
    }
}

fn resolve(cli: Cli, cfg: ConfigFile) -> Result<Settings> {
    Ok(Settings {
        input: cli
            .input
            .or(cfg.input)
            .ok_or_else(|| anyhow!("--input is required (on the CLI or in the config file)"))?,
        count: cli.count.or(cfg.count).unwrap_or(2),
        separator: cli.separator.or(cfg.separator).unwrap_or_else(|| "-".into()),
        capitalize: cli.capitalize || cfg.capitalize.unwrap_or(false),
        leet: cli.leet || cfg.leet.unwrap_or(false),
        digits: cli.digits.or(cfg.digits).unwrap_or(0),
        symbols: cli.symbols.or(cfg.symbols).unwrap_or(0),
        replace: cli.replace || cfg.replace.unwrap_or(false),
        seed: cli.seed.or(cfg.seed),
        derive: cli.derive || cfg.derive.unwrap_or(false),
        argon_mem_kb: cli.argon_mem_kb.or(cfg.argon_mem_kb).unwrap_or(65536),
        argon_iters: cli.argon_iters.or(cfg.argon_iters).unwrap_or(3),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rng() -> StdRng {
        StdRng::seed_from_u64(42)
    }

    fn words(n: usize) -> Vec<String> {
        (0..n).map(|i| format!("word{i}")).collect()
    }

    fn base_settings() -> Settings {
        Settings {
            input: PathBuf::from("unused"),
            count: 2,
            separator: "-".into(),
            capitalize: false,
            leet: false,
            digits: 0,
            symbols: 0,
            replace: false,
            seed: Some(42),
            derive: false,
            argon_mem_kb: 65536,
            argon_iters: 3,
        }
    }

    fn empty_cli() -> Cli {
        Cli {
            input: None,
            count: None,
            separator: None,
            capitalize: false,
            leet: false,
            digits: None,
            symbols: None,
            replace: false,
            seed: None,
            derive: false,
            argon_mem_kb: None,
            argon_iters: None,
            config: None,
        }
    }

    #[test]
    fn capitalize_word_basic() {
        assert_eq!(capitalize_word("apple"), "Apple");
        assert_eq!(capitalize_word(""), "");
    }

    #[test]
    fn leet_word_substitutions() {
        assert_eq!(leet_word("Sasie"), "$4$13");
        assert_eq!(leet_word("xyz"), "xyz");
    }

    #[test]
    fn choose_without_replacement_is_unique() {
        let items = words(10);
        let picked = choose_words(&items, 5, false, &mut rng());
        assert_eq!(picked.len(), 5);
        let mut deduped = picked.clone();
        deduped.sort();
        deduped.dedup();
        assert_eq!(deduped.len(), 5);
    }

    #[test]
    fn seeded_output_is_deterministic() {
        let items = words(10);
        let settings = base_settings();
        let a = build_mnemonic(&items, &settings, &mut rng());
        let b = build_mnemonic(&items, &settings, &mut rng());
        assert_eq!(a, b);
    }

    #[test]
    fn appended_chars_use_expected_charsets() {
        let mut s = String::new();
        append_digits(&mut s, 8, &mut rng());
        assert_eq!(s.len(), 8);
        assert!(s.chars().all(|c| c.is_ascii_digit()));

        let mut s = String::new();
        append_symbols(&mut s, 8, &mut rng());
        assert_eq!(s.len(), 8);
        assert!(s.bytes().all(|b| SYMBOLS.contains(&b)));
    }

    #[test]
    fn entropy_matches_charsets_and_sampling_mode() {
        let mut settings = base_settings();
        settings.digits = 1;
        settings.symbols = 1;

        let without = estimate_entropy_bits(10, &settings);
        let expected = 10f64.log2() + 9f64.log2() + 10f64.log2() + 9f64.log2();
        assert!((without - expected).abs() < 1e-9);

        settings.replace = true;
        let with = estimate_entropy_bits(10, &settings);
        let expected = 2.0 * 10f64.log2() + 10f64.log2() + 9f64.log2();
        assert!((with - expected).abs() < 1e-9);
    }

    #[test]
    fn parse_items_accepts_array_and_object() {
        let arr = parse_items(r#"["a", "b", 1]"#).unwrap();
        assert_eq!(arr, ["a", "b"]);
        let obj = parse_items(r#"{"items": ["x", "y"]}"#).unwrap();
        assert_eq!(obj, ["x", "y"]);
    }

    #[test]
    fn parse_items_rejects_invalid_input() {
        assert!(parse_items("[]").is_err());
        assert!(parse_items(r#""just a string""#).is_err());
        assert!(parse_items(r#"{"other": []}"#).is_err());
        assert!(parse_items("not json").is_err());
    }

    #[test]
    fn cli_overrides_config_overrides_default() {
        let cli = Cli {
            count: Some(7),
            ..empty_cli()
        };
        let cfg = ConfigFile {
            input: Some(PathBuf::from("from-config.json")),
            count: Some(3),
            separator: Some("_".into()),
            capitalize: Some(true),
            ..ConfigFile::default()
        };

        let s = resolve(cli, cfg).unwrap();
        assert_eq!(s.input, PathBuf::from("from-config.json"));
        assert_eq!(s.count, 7); // CLI wins over config
        assert_eq!(s.separator, "_"); // config wins over default
        assert!(s.capitalize);
        assert_eq!(s.digits, 0); // default
        assert_eq!(s.argon_mem_kb, 65536); // default
    }

    #[test]
    fn resolve_requires_input() {
        assert!(resolve(empty_cli(), ConfigFile::default()).is_err());
    }
}
