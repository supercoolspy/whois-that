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
    pub(crate) whois_servers: DashMap<String, Option<Arc<str>>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainLookupInfo {
    /// The whois server for a domain
    server: Arc<str>,
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
    pub fn lookup_server(&self, suffix: &str) -> Option<Arc<str>> {
        self.whois_servers
            .get(suffix)
            .map(|kv_info| kv_info.value().clone())
            .unwrap_or_default()
    }

    /// Lookup the whois server for a domain and see if a whois server exists for it.
    /// This method is less efficient than lookup_server since it has to split the domain by `.`
    /// until it can find a matching server.
    /// Needs to be punycode before being put into this function.
    pub fn lookup_server_domain(&self, domain: &str) -> Option<Arc<str>> {
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
    pub fn lookup_domain_info(&self, domain: &str) -> Option<DomainLookupInfo> {
        let domain_chunks: Vec<&str> = domain.split(".").collect();

        // Start from the entire domain and then remove each `.` chunk until valid domain is found, or nothing is found
        for i in (1..=domain_chunks.len()).rev() {
            // Attempts to use the entire domain as a suffix, then removes the first chunk and so on
            let suffix = domain_chunks[domain_chunks.len() - i..].join(".");

            // Checks if a match is found
            if self.whois_servers.contains_key(&suffix) {
                let server = self.lookup_server(&suffix)?;

                let domain = domain_chunks[domain_chunks.len() - i + 1..].join(".");

                return Some(DomainLookupInfo { server, domain });
            }
        }

        // Return none if no suffix is found
        None
    }

    #[cfg(feature = "decode-global")]
    fn decode_global(data: Vec<u8>) -> Result<String, Vec<u8>> {
        let (decoded, _, had_errors) = encoding_rs::WINDOWS_1252.decode(&data);

        if had_errors {
            return Err(data);
        }

        Ok(decoded.into_owned())
    }

    #[cfg(not(feature = "decode-global"))]
    fn decode_global(data: Vec<u8>) -> Result<String, Vec<u8>> {
        Ok(String::from_utf8_lossy(&data).into_owned())
    }

    pub async fn lookup(&self, domain_lookup_info: DomainLookupInfo) -> Result<String, WhoisError> {
        let mut stream = TcpStream::connect(format!("{}:43", domain_lookup_info.server)).await?;

        stream
            .write_all(domain_lookup_info.domain.as_bytes())
            .await?;
        stream.write_all("\r\n".as_bytes()).await?;

        let mut data = Vec::new();

        stream.read_to_end(&mut data).await?;

        if let Ok(whois_data) = std::str::from_utf8(&data) {
            Ok(whois_data.to_string())
        } else {
            Self::decode_global(data).map_err(|e| WhoisError::WhoisData(e))
        }
    }

    /// Get the whois data for a domain
    #[cfg(feature = "idna")]
    pub async fn whois_lookup(&self, domain: &str) -> Result<String, WhoisError> {
        let info = self
            .lookup_domain_info(&idna::domain_to_ascii(domain)?)
            .ok_or(WhoisError::WhoisServer(domain.to_string()))?;

        self.lookup(info).await
    }
}
