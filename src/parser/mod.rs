mod normalizer;

use thiserror::Error;
#[cfg(feature = "date-parse")]
use time::Date;

/// The type of date that was extracted from whois.
#[derive(Debug, Clone)]
pub enum DateType {
    #[cfg(feature = "date-parse")]
    /// Parsed date from whois
    Parsed(Date),
    /// Raw date string from whois. Happens either because the `date-parse` feature isn't enabled or the date couldn't be parsed
    Raw(String),
}

#[derive(Debug, Clone, Default)]
pub struct ParsedDomain {
    registrar: Option<Contact>,
    registrant: Option<Contact>,
    administrative: Option<Contact>,
    technical: Option<Contact>,
    billing: Option<Contact>,
    created: Option<DateType>,
    updated: Option<DateType>,
    expires: Option<DateType>,
    name_servers: Option<Vec<String>>,
    dns_sec: Option<bool>,
}

#[derive(Debug, Clone)]
pub enum ContactField {
    /// Data included in the whois response
    Included(String),
    /// Data redacted from the whois response
    Redacted,
}

#[derive(Debug, Clone)]
pub struct Contact {
    name: Option<ContactField>,
    organization: Option<ContactField>,
    street: Option<ContactField>,
    city: Option<ContactField>,
    province: Option<ContactField>,
    postal_code: Option<ContactField>,
    country: Option<ContactField>,
    phone: Option<ContactField>,
    phone_ext: Option<ContactField>,
    fax: Option<ContactField>,
    fax_ext: Option<ContactField>,
    email: Option<ContactField>,
    referral_url: Option<ContactField>,
}

#[derive(Debug, Error)]
enum WhoisParseError {}

pub fn parse(suffix: &str, response: String) -> Result<ParsedDomain, WhoisParseError> {
    todo!("Write")
}
