use tscc::{handle_message, mock_transport, ProtocolMessage, RequestMessage, VerifiedUrl};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("--- TSCC Demo: Formal Verification in Rust ---\n");

    // 1. DEMO: Type-Safe Invariant (VerifiedUrl)
    // The `VerifiedUrl` guarantees that no empty URL string can exist.

    println!("[1. URL INVARIANT DEMO]");

    // Success: URL creation
    match VerifiedUrl::try_new("https://safe.site/path".to_string()) {
        Ok(url) => println!("Success: Created valid URL: {}", url.as_str()),
        Err(e) => println!("Failure: {}", e),
    }

    // Failure: Attempting to create an invalid (empty) URL
    match VerifiedUrl::try_new(" ".to_string()) {
        Ok(_) => println!("Error: Should have failed for empty URL!"),
        Err(e) => println!("Success: Blocked invalid URL: {}", e),
    }

    println!("\n-------------------------------------------");

    // 2. DEMO: Protocol Message with Policy Enforcement (Success Case)
    // We demonstrate a message handler that only proceeds if the message origin
    // satisfies a formal, type-driven policy (VerifiedOrigin).

    println!("[2. POLICY ENFORCEMENT DEMO: SUCCESS]");

    // The message includes an origin that is explicitly listed in the OriginPolicy enum.
    let trusted_origin = "https://trusted.app".to_string();
    let success_query = ProtocolMessage::Request(RequestMessage::SecureQuery {
        origin: trusted_origin,
        query: "Get user settings".to_string(),
    });

    let received_success_msg = mock_transport(&success_query)?;
    let success_response = handle_message(received_success_msg);
    println!("Main received response: {:?}", success_response);

    // 3. DEMO: Protocol Message with Policy Enforcement (Failure Case)

    println!("\n-------------------------------------------");
    println!("[3. POLICY ENFORCEMENT DEMO: FAILURE]");

    // The message includes an origin that is NOT listed in the OriginPolicy enum.
    let untrusted_origin = "https://untrusted.evil.com".to_string();
    let failure_query = ProtocolMessage::Request(RequestMessage::SecureQuery {
        origin: untrusted_origin,
        query: "Delete all data".to_string(),
    });

    let received_failure_msg = mock_transport(&failure_query)?;
    let failure_response = handle_message(received_failure_msg);
    println!("Main received response: {:?}", failure_response);

    Ok(())
}
