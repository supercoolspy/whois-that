use crate::WhoisError;
use crate::builder::WhoisBuilder;
use dashmap::DashMap;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

extern crate dashmap;

#[derive(Debug, Clone)]
pub struct Whois {
    /// The list of whois servers to lookup.
    /// Uses `Arc<str>` since it is more efficient when looking up
    /// since you may have to clone.
    pub(crate) whois_servers: DashMap<String, Option<WhoisServerEntry>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// A whois server info entry
pub enum WhoisServerEntry {
    /// A simple entry with only the whois server host as a parameter
    Simple(Arc<str>),
    /// A detailed entry with the whois server host
    /// along with the full query and whether to use punycode
    Detailed {
        host: Arc<str>,
        query: Arc<str>,
        punycode: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainLookupInfo {
    /// The whois server for a domain
    server_info: WhoisServerEntry,
    /// The domain, without any subdomains
    domain: String,
}

impl Whois {
    #[cfg(feature = "serde")]
    pub fn builder() -> WhoisBuilder {
        WhoisBuilder::default()
    }

    /// Lookup a whois suffix in the table and see if a whois server exists for it.
    /// Needs to be punycode before being put into this function.
    pub fn lookup_server(&self, suffix: &str) -> Option<WhoisServerEntry> {
        self.whois_servers
            .get(suffix)
            .map(|kv_info| kv_info.value().to_owned())
            .unwrap_or(None)
    }

    /// Lookup the whois server for a domain and see if a whois server exists for it.
    /// This method is less efficient than lookup_server since it has to split the domain by `.`
    /// until it can find a matching server.
    /// Needs to be punycode before being put into this function.
    pub fn lookup_server_domain(&self, domain: &str) -> Option<WhoisServerEntry> {
        let domain_chunks: Vec<&str> = domain.split(".").collect();

        // Start from the entire domain and then remove each `.` chunk until valid domain is found, or nothing is found
        for i in (1..=domain_chunks.len()).rev() {
            // Attempts to use the entire domain as a suffix, then removes the first chunk and so on
            let suffix = domain_chunks[domain_chunks.len() - i..].join(".");

            // Checks if a match is found
            if self.whois_servers.contains_key(&suffix) {
                return self.lookup_server(&suffix);
            }
        }

        // Return none if no suffix is found
        None
    }

    /// Lookup the whois server for a domain and see if a whois server exists for it.
    /// This method is less efficient than lookup_server since it has to split the domain by `.`
    /// until it can find a matching server. Returns the whois server and the domain (without subdomains).
    /// Needs to be punycode before being put into this function.
    /// If a suffix like `com.uk` is put into this function it will return the suffix as both fields.
    pub fn lookup_domain_info(&self, domain: &str) -> Option<DomainLookupInfo> {
        let domain_chunks: Vec<&str> = domain.split(".").collect();

        // Start from the entire domain and then remove each `.` chunk until valid domain is found, or nothing is found
        for i in (1..=domain_chunks.len()).rev() {
            // Attempts to use the entire domain as a suffix, then removes the first chunk and so on
            let suffix = domain_chunks[domain_chunks.len() - i..].join(".");

            // Checks if a match is found
            if self.whois_servers.contains_key(&suffix) {
                let server = self.lookup_server(&suffix)?;

                let suffix_start =  domain_chunks.len() - i;
                
                let index = if suffix_start == 0 {
                    // Occurs for domains like uk.com where they are a website and a suffix
                    0
                } else {
                    suffix_start - 1
                };

                let domain = domain_chunks[index..].join(".");

                return Some(DomainLookupInfo {
                    server_info: server,
                    domain,
                });
            }
        }

        // Return none if no suffix is found
        None
    }

    #[cfg(feature = "decode-global")]
    /// Decodes a non-UTF8 string by attempting to parsing it as Windows_1252,
    /// but returning the raw data if it has errors when parsing with that encoding
    fn decode(data: Vec<u8>) -> Result<String, Vec<u8>> {
        let (decoded, _, had_errors) = encoding_rs::WINDOWS_1252.decode(&data);

        if had_errors {
            return Err(data);
        }

        Ok(decoded.into_owned())
    }

    #[cfg(not(feature = "decode-global"))]
    /// Decodes a non-UTF8 string into a lossy UTF8 one
    fn decode(data: Vec<u8>) -> Result<String, Vec<u8>> {
        Ok(String::from_utf8_lossy(&data).into_owned())
    }

    /// Lookup a domain using already-found whois info and domain root
    pub async fn lookup(&self, domain_lookup_info: DomainLookupInfo) -> Result<String, WhoisError> {
        let mut stream = match domain_lookup_info.server_info {
            WhoisServerEntry::Simple(ref host) => TcpStream::connect(format!("{}:43", host)),
            WhoisServerEntry::Detailed { ref host, .. } => {
                TcpStream::connect(format!("{}:43", host))
            }
        }
        .await?;

        match domain_lookup_info.server_info {
            WhoisServerEntry::Simple(_) => {
                stream
                    .write_all(domain_lookup_info.domain.as_bytes())
                    .await?;
                stream.write_all("\r\n".as_bytes()).await?;
            }
            WhoisServerEntry::Detailed { query, .. } => {
                stream
                    .write_all(
                        query
                            .replace("$addr", &domain_lookup_info.domain)
                            .as_bytes(),
                    )
                    .await?;
            }
        }

        let mut data = Vec::new();

        stream.read_to_end(&mut data).await?;

        if let Ok(whois_data) = std::str::from_utf8(&data) {
            Ok(whois_data.to_string())
        } else {
            Self::decode(data).map_err(|e| WhoisError::WhoisData(e))
        }
    }

    /// Get the whois data for a domain
    #[cfg(feature = "idna")]
    pub async fn whois_lookup(&self, domain: &str) -> Result<String, WhoisError> {
        let mut info = self
            .lookup_domain_info(&idna::domain_to_ascii(domain)?)
            .ok_or(WhoisError::WhoisServer(domain.to_string()))?;

        let info = if let WhoisServerEntry::Detailed { punycode, .. } = info.server_info {
            if !punycode {
                let (new_domain, res) = idna::domain_to_unicode(domain);
                res?;

                info.domain = new_domain;
            }

            info
        } else {
            info
        };

        self.lookup(info).await
    }
}
