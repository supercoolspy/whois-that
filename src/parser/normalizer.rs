use crate::parser::{Contact, DateType, ParsedDomain};

enum NormalizedOutput {
    FullData(Box<dyn Into<ParsedDomain>>)
}

/// Normalizes the whois output for better parsing.
/// Returns Ok if specific tld normalizer exists
/// and returns Err if no tld normalizer exists, but still applies basic normalization.
pub fn normalize(suffix: &str, response: String) -> Result<String, String> {
    let normalized_response = response
        .replace("\r", "")
        .replace("\t", " ")
        .trim()
        .to_owned();

    Ok(response)
}

struct EduNormalized {
    registrant: Contact,
    administrative: Contact,
    technical: Contact,
    name_servers: Vec<String>,
    created: DateType,
    updated: DateType,
    expires: DateType,
}

impl Into<ParsedDomain> for EduNormalized {
    fn into(self) -> ParsedDomain {
        ParsedDomain {
            registrant: Some(self.registrant),
            administrative: Some(self.administrative),
            technical: Some(self.technical),
            created: Some(self.created),
            updated: Some(self.updated),
            expires: Some(self.expires),
            name_servers: Some(self.name_servers),
            ..Default::default()
        }
    }
}

fn normalize_edu(response: String) -> String {

}