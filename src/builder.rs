use crate::whois::Whois;
use dashmap::DashMap;
use std::collections::HashMap;
#[cfg(feature = "serde")]
use std::fs::File;
#[cfg(feature = "serde")]
use std::path::{Path, PathBuf};
use std::sync::Arc;
#[cfg(feature = "serde")]
use thiserror::Error;

#[derive(Debug, Error)]
#[cfg(feature = "serde")]
pub enum WhoisBuilderError {
    #[error("IO Error: {0}")]
    IO(#[from] std::io::Error),

    #[error("Serde Json Error: {0}")]
    SerdeJson(#[from] serde_json::Error),
}

/// The type of server list data that the builder will use
pub enum ServerListType {
    #[cfg(feature = "serde")]
    Path(PathBuf),
    #[cfg(feature = "serde")]
    Data(String),
    Parsed(DashMap<String, Option<Arc<str>>>),
}

pub struct WhoisBuilder {
    server_list: ServerListType,
}

#[cfg(feature = "serde")]
impl<'a> Default for WhoisBuilder {
    fn default() -> Self {
        Self {
            server_list: ServerListType::Data(include_str!("assets/servers.json").to_string()),
        }
    }
}

impl WhoisBuilder {
    /// Creates a new whois client builder
    pub fn new(whois_server_list: ServerListType) -> Self {
        WhoisBuilder {
            server_list: whois_server_list,
        }
    }

    #[cfg(not(feature = "serde"))]
    /// Builds the whois client
    pub fn build(self) -> Whois {
        match self.server_list {
            ServerListType::Parsed(data) => Whois {
                whois_servers: data,
            },
        }
    }
}

#[cfg(feature = "serde")]
impl WhoisBuilder {
    /// Sets the path to get the whois server data from
    pub fn with_server_path(mut self, path: impl AsRef<Path>) -> Self {
        self.server_list = ServerListType::Path(path.as_ref().to_path_buf());

        self
    }

    /// Sets the data to get the whois server from
    pub fn with_server_data(mut self, path: impl AsRef<Path>) -> Self {
        self.server_list = ServerListType::Path(path.as_ref().to_path_buf());

        self
    }

    /// Builds the whois client, errors if unable to parse data or get file
    pub fn build(self) -> Result<Whois, WhoisBuilderError> {
        let server_list = match self.server_list {
            ServerListType::Path(path) => {
                let file = File::open(path)?;

                serde_json::from_reader::<_, HashMap<String, Option<String>>>(file)?
                    .into_iter()
                    .map(|(k, v)| (k, v.map(Arc::from)))
                    .collect()
            }
            ServerListType::Data(data) => {
                serde_json::from_str::<HashMap<String, Option<String>>>(&data)?
                    .into_iter()
                    .map(|(k, v)| (k, v.map(Arc::from)))
                    .collect()
            }
            ServerListType::Parsed(server_list) => server_list,
        };

        Ok(Whois {
            whois_servers: server_list,
        })
    }
}
