use thiserror::Error;

pub mod builder;
pub mod whois;

#[cfg(test)]
mod tests;

#[derive(Debug, Error)]
pub enum WhoisError {
    #[error("Tokio IO Error: {0}")]
    TokioIO(#[from] tokio::io::Error),

    #[error("IDNA Error: {0}")]
    IDNA(#[from] idna::Errors),

    #[error("Unable to parse whois data to known encoding")]
    WhoisData(Vec<u8>),

    #[error("No whois server found for {0} in server list")]
    WhoisServer(String),
}
