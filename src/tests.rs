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

#[tokio::test]
#[cfg(feature = "serde")]
async fn test_simple_domain() {
    let whois = basic_whois_client();

    println!(
        "{}",
        whois
            .whois_lookup("google.com")
            .await
            .expect("Should be able to get whois data for google")
    );
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
    let whois = basic_whois_client();

    whois
        .whois_lookup("registro.br")
        .await
        .expect("Shouldn't be able to get whois data for google.dev");
}
