use samael::metadata::{EntityDescriptor};
use samael::service_provider::ServiceProviderBuilder;
use std::collections::HashMap;
use std::fs;
use warp::{Filter};
use warp::http::{StatusCode};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    openssl_probe::init_ssl_cert_env_vars();

    let resp = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" entityID=\"pillar-idp-2\"><md:IDPSSODescriptor WantAuthnRequestsSigned=\"false\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\"><md:KeyDescriptor use=\"signing\"><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:X509Data><ds:X509Certificate>MIIC/jCCAeYCCQDFnYjj9WMgQDANBgkqhkiG9w0BAQsFADBBMQswCQYDVQQGEwJJRDEQMA4GA1UECAwHSkFLQVJUQTEQMA4GA1UEBwwHSkFLQVJUQTEOMAwGA1UECgwFUkVBUk0wHhcNMjIwNjMwMDMzMjM1WhcNMjUwNjI5MDMzMjM1WjBBMQswCQYDVQQGEwJJRDEQMA4GA1UECAwHSkFLQVJUQTEQMA4GA1UEBwwHSkFLQVJUQTEOMAwGA1UECgwFUkVBUk0wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDgsSswLauPzxlOmTkckxW4+qQzss4Wk5SRF/g88bv/RDGyk6Vo1oFXn6sSLBYTdjvHWY85pB6gWMb5ULLjJAY+rVTf1Ii87KXhjn6kb96emFowy9x5BISzgwukn12aIA2RoUeMr9RAvlDLaWRZsA7OAvaLP4SPiK8HVcHNI92QvRkq7EHYb4VuVMy3VNDYJ04J5gVu8Jje1jIJoG0lGrJV9Rpm/6JD1YstHpgrlYTdWqNQgjFYfrkFpWqyqFBZenGlsVDs9GKszoyiX2EefQUXdEGHC57aIqZJazvSMcOWxBfyvBiMaw/92CGrWG9x22TXVhpnuhR4gPNaykPcbSs3AgMBAAEwDQYJKoZIhvcNAQELBQADggEBAFM/fqYih0ULkmSA2Ty0g3AuBbjm7vcXGWQKFop7OSNj3ArdIU8DwG8FI+RHZYWXMXmMeWRth6/IWQxxnb9mKg3+V1/Q5kFxNaLwgsIsezSDtN3rCRXNfXWKMyhE6Tr4x58xePqh5HQrcALD+xbNnlIAKVuoyMuTn2Fea2KJ4nP7vYXUhTK1sdeMNY/FjKtvpBo9++u4E6p633XnBUSt0VEswyODgrDTzQdXBV4Mjh1Sj896H0Ta16xyKIbCRBOmAeP07HGBWUbdetShoV9JbzMUHrBrtfsK6m8ZxqeE6X3tGWBkzcfmEsrDVz0l2nNEIrtq97obHlAXe9Rb45LOzcM=</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:NameIDFormat>urn:oasis:names:tc:SAML:1.0:nameid-format:unspecified</md:NameIDFormat><md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://sso.jumpcloud.com/saml2/pillar-idp\"/><md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://sso.jumpcloud.com/saml2/pillar-idp\"/></md:IDPSSODescriptor></md:EntityDescriptor>";
    println!("{}",resp);
    let idp_metadata: EntityDescriptor = samael::metadata::de::from_str(&resp)?;

    let pub_key = openssl::x509::X509::from_pem(&fs::read("./cert.pem")?)?;
    let private_key = openssl::rsa::Rsa::private_key_from_pem(&fs::read("./private.pem")?)?;

    let sp = ServiceProviderBuilder::default()
        .entity_id("pillar-sp-2".to_string())
        .key(private_key)
        .certificate(pub_key)
        .allow_idp_initiated(true)
        .idp_metadata(idp_metadata)
        .acs_url("http://localhost:8000/saml/acs".to_string())
        .slo_url("http://localhost:8000/saml/slo".to_string())
        .build()?;

    let metadata = sp.metadata()?.to_xml()?;

    let metadata_route = warp::get()
        .and(warp::path("metadata"))
        .map(move || metadata.clone());

    let acs_route = warp::post()
        .and(warp::path("acs"))
        .and(warp::body::form())
        .map(move |s: HashMap<String, String>| {
            if let Some(encoded_resp) = s.get("SAMLResponse") {
                println!("{:?}", encoded_resp);

                let sp_res = sp.parse_response(encoded_resp, &["a_possible_request_id".to_string()]);
                return match sp_res {
                    Ok(resp) => {
                        println!("{:?}", resp);

                        let cookie_val = format!("token={}; Path=/; Max-Age=1209600", "abc");

                        warp::http::Response::builder()
                            .header("set-cookie", string_to_static_str(cookie_val))
                            .header("Location", "http://localhost:3000/")
                            .status(StatusCode::FOUND)
                            .body("".to_string())
                    },
                    Err(e) => warp::http::Response::builder()
                        .status(StatusCode::BAD_REQUEST)
                        .body(e.to_string())
                }
            }

            return warp::http::Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body("Error FORBIDDEN".to_string())
        });

    let saml_routes = warp::path("saml").and(acs_route.or(metadata_route));
    warp::serve(saml_routes).run(([127, 0, 0, 1], 8000)).await;
    Ok(())
}

fn string_to_static_str(s: String) -> &'static str {
    Box::leak(s.into_boxed_str())
}
