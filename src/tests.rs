use crate::builder::WhoisBuilder;
use crate::whois::Whois;

#[cfg(feature = "serde")]
fn basic_whois_client() -> Whois {
    WhoisBuilder::default()
        .build()
        .expect("Should be able to build whois client")
}

#[cfg(feature = "serde")]
#[tokio::test]
async fn test_whois_client() {
    basic_whois_client();
}

#[cfg(feature = "serde")]
#[tokio::test]
async fn test_whois_builder() {
    Whois::builder()
        .build()
        .expect("Should be able to build whois client");
}

#[cfg(feature = "serde")]
async fn lookup(domain: &'static str) {
    let whois = basic_whois_client();

    let info = whois
        .whois_lookup(domain)
        .await
        .expect(&format!("Should be able to get whois data for {}", domain));

    println!("{}", &info);

    assert!(
        info.to_ascii_lowercase().contains(domain)
            || info
                .to_ascii_lowercase()
                .contains(&idna::domain_to_ascii(domain).expect("Should be able to get as ascii"))
    )
}

#[tokio::test]
#[cfg(feature = "serde")]
async fn test_simple_domain() {
    lookup("google.com").await;
}

#[tokio::test]
#[cfg(feature = "serde")]
async fn test_fail_rdap() {
    let whois = basic_whois_client();

    whois
        .whois_lookup("google.dev")
        .await
        .expect_err("Shouldn't be able to get whois data for google.dev");
}

#[tokio::test]
#[cfg(feature = "serde")]
#[cfg(feature = "decode-global")]
async fn test_simple_international() {
    lookup("registro.br").await;
}

#[tokio::test]
#[cfg(feature = "serde")]
#[cfg(feature = "decode-global")]
async fn test_simple_unicode() {
    lookup("xn--1lq68wkwbj6u.jp").await;
}

#[tokio::test]
#[cfg(feature = "serde")]
#[cfg(feature = "decode-global")]
async fn test_simple_unicode_unparsed() {
    lookup("öbb.at").await;
}
