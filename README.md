# whois-that

[![Crates.io](https://img.shields.io/crates/v/whois-that.svg)](https://crates.io/crates/whois-that)
[![Documentation](https://docs.rs/whois-that/badge.svg)](https://docs.rs/whois-that)
[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/supercoolspy/whois-that/blob/master/LICENSE)

`whois-that` is a fast, asynchronous WHOIS client library for Rust using `tokio`. It provides comprehensive domain information lookups with support for international domains, custom server lists, and various character encodings.

## Features

- **Async by default** - Built on Tokio for non-blocking network operations
- **International Domain Support** - Handles IDNs via IDNA Punycode conversion
- **Multiple Character Encodings** - Support for non-UTF8 responses (Windows-1252)
- **Configurable Server Lists** - Use default or custom WHOIS server configurations
- **Efficient Domain Suffix Lookup** - Fast TLD and domain lookups
- **Minimal Dependencies** - Feature flags let you include only what you need

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
whois-that = "0.1"
tokio = { version = "1", features = ["full"] }
```

### Feature Flags

The library uses feature flags to provide flexibility:

| Flag | Description | Default |
|------|-------------|---------|
| `serde` | Enable serde support for loading server lists from files/JSON data | ✓ |
| `idna` | Enable IDNA support for international domain names | ✓ |
| `decode-global` | Enable Windows-1252 character encoding support | ✓ |

To use only specific features:

```toml
[dependencies]
whois-that = { version = "0.1", default-features = false, features = ["serde", "idna"] }
```

## Usage

### Basic Usage

```rust
use whois_that::whois::Whois;
use whois_that::builder::WhoisBuilder;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a default whois client with built-in server list
    let whois = WhoisBuilder::default().build()?;
    
    // Look up WHOIS data for a domain
    let whois_data = whois.whois_lookup("google.com").await?;
    
    println!("{}", whois_data);
    
    Ok(())
}
```

### Custom Server List

You can provide your own WHOIS server list as a JSON file:

```rust
use whois_that::whois::Whois;
use whois_that::builder::WhoisBuilder;
use std::path::Path;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a whois client with a custom server list
    let whois = WhoisBuilder::default()
        .with_server_path(Path::new("path/to/custom_servers.json"))
        .build()?;
    
    // Look up WHOIS data for a domain
    let whois_data = whois.whois_lookup("example.com").await?;
    
    println!("{}", whois_data);
    
    Ok(())
}
```

### International Domain Names

When the `idna` feature is enabled (on by default), you can lookup international domain names:

```rust
use whois_that::whois::Whois;
use whois_that::builder::WhoisBuilder;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let whois = WhoisBuilder::default().build()?;
    
    // Look up WHOIS data for an IDN domain
    let whois_data = whois.whois_lookup("例子.网址").await?;
    println!("{}", whois_data);
    
    Ok(())
}
```

### Server List Format

Custom server lists should be JSON files in the following formats:

```json5
{
  // Standard format
  "io": "whois.nic.io",
  // Detailed format
  "net": {
    "host": "whois.verisign-grs.com",
    "query": "DOMAIN $addr\r\n",
    "punycode": true
  },
}
```

## Contributing

Contributions are welcome!

## Acknowledgments

- [Tokio](https://tokio.rs/) for the asynchronous runtime
- [DashMap](https://github.com/xacrimon/dashmap) for concurrent maps
- [node-whois](https://github.com/FurqanSoftware/node-whois) for the original server list
