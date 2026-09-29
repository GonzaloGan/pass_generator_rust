# Mnemonic Password Generator (Rust)

A simple and configurable CLI tool to generate **memorable yet strong passwords** using random words (mnemonic-style), with optional transformations like capitalization, leetspeak, digits, and symbols.

---

## ✨ Features

* Generate passwords from a custom word list (JSON)
* Deterministic output with a seed (useful for reproducibility)
* Configurable:

  * number of words
  * separator
  * capitalization
  * leetspeak substitutions
  * appended digits and symbols
* Optional **Argon2 derivation** for stronger cryptographic output
* Optional TOML config file
* Entropy estimation

---

## 📦 Installation

Clone and build:

```bash
git clone <your-repo>
cd mnemonic-pass
cargo build --release
```

Run with:

```bash
cargo run --release -- --help
```

---

## 🚀 Usage

Basic example:

```bash
cargo run --release -- \
  --input items.json \
  --count 3 \
  --separator "-" \
  --capitalize \
  --digits 2 \
  --symbols 1
```

Example output:

```
Mnemonic: Apple-Desk-Cloud42!
(estimated entropy: 51.7 bits)
```

---

## 📁 Input Format

The program expects a JSON file containing words.

### Option 1: Array

```json
["apple", "banana", "desk", "cloud"]
```

### Option 2: Object with `items`

```json
{
  "items": ["apple", "banana", "desk", "cloud"]
}
```

---

## ⚙️ Options

| Flag             | Description                            |
| ---------------- | -------------------------------------- |
| `--input`        | Path to JSON word list (required)      |
| `--count`        | Number of words (default: 2)           |
| `--separator`    | Separator between words (default: `-`) |
| `--capitalize`   | Capitalize first letter of each word   |
| `--leet`         | Apply leetspeak (a→4, e→3, etc.)       |
| `--digits`       | Number of random digits to append      |
| `--symbols`      | Number of random symbols to append     |
| `--replace`      | Allow repeated words                   |
| `--seed`         | Deterministic seed                     |
| `--derive`       | Derive Argon2 hash                     |
| `--argon-mem-kb` | Argon2 memory (default: 65536)         |
| `--argon-iters`  | Argon2 iterations (default: 3)         |
| `--config`       | Path to TOML config file               |

---

## 🔁 Deterministic Mode

Using a seed ensures the same output every time:

```bash
cargo run -- --input items.json --seed 42
```

This is useful if you want reproducible passwords from the same word list.

---

## 🔐 Argon2 Derivation

You can derive a secure encoded string:

```bash
cargo run -- --input items.json --derive
```

Output:

```
Argon2: $argon2id$v=19$m=65536,t=3,p=1$...
```

---

## 🧾 Config File (TOML)

You can store defaults in a config file:

```toml
input = "items.json"
count = 4
separator = "-"
capitalize = true
digits = 2
symbols = 1
derive = true
```

Run with:

```bash
cargo run -- --config config.toml
```

CLI arguments override config values.

---

## 🧠 Entropy

The tool prints an **estimated entropy** value in bits.

Higher is better:

* ~40 bits → moderate
* ~60 bits → strong
* ~80+ bits → very strong

---

## 🛠 Example Recipes

### Simple memorable password

```bash
--count 3 --separator "-"
```

→ `tree-apple-cloud`

---

### Stronger password

```bash
--count 4 --capitalize --digits 2 --symbols 1
```

→ `Tree-Apple-Cloud-Desk42!`

---

### Compact password

```bash
--count 3 --separator "" --leet
```

→ `tr33cl0uddesk`

---

## 📌 Notes

* If `count` > number of words and `--replace` is not set, duplicates may still occur.
* Symbols are chosen from a safe subset: `!@#$%^&*?`
* Entropy is an estimate, not a guarantee.

---

## 🧪 Future Improvements

* Separate library + CLI crate
* Better entropy estimation (zxcvbn)
* Built-in wordlists (e.g. BIP39)
* Passphrase validation tools

---

## 📄 License

unlicense, see LICENCE file
