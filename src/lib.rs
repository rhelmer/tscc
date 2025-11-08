//! # Type-Safe Comms Crate (TSCC)
//! ## Formally Verified Web Standards and Message Passing in Rust
//!
//! This project demonstrates two critical use cases for formal verification via Rust's type system:
//!
//! 1.  **Compile-Time Protocol Verification:** Guaranteeing message passing integrity.
//! 2.  **Web Standard Invariant Enforcement (New):** Creating types that can only represent valid, policy-compliant states for web concepts (like communication origins).
//!
//! ---
//!
//! ## 1. Protocol Verification: Structured Reasoning
//!
//! We model the entire communication protocol using **Algebraic Data Types (ADTs)**, forcing the **compiler** to verify the completeness and exhaustiveness of our communication handlers.
//!
//! ### High-Level System Design (Flowchart Fixed)
//!
//! ```mermaid
//! flowchart TD
//!     A[Protocol Definition: Rust Enums/Structs] --> B{Sender Creates Message}
//!     B --> C{Compiler: Is Message Structurally Valid?}
//!     C -- Yes, Verified --> D[Serialize Message (Serde)]
//!     D --> E((Network/Channel Transport))
//!     E --> F[Deserialize Message]
//!     F --> G{Receiver Matches Message}
//!     G --> H{Compiler: Are ALL Cases Handled?}
//!     H -- Yes, Verified --> I[Runtime Logic Executes]
//!     C -- No --> J[Compile-Time ERROR: Missing Field/Wrong Type]
//!     H -- No --> J
//!
//!     style J fill:#f9f,stroke:#333,stroke-width:4px
//! ```
//!
//! ### Type-Verification Architecture (Class Diagram Fix Applied)
//!
//! ```mermaid
//! classDiagram
//!     class ProtocolMessage {
//!         <<Enum>>
//!         +Request(RequestMessage)
//!         +Response(ResponseMessage)
//!         +Notification(NotificationMessage)
//!     }
//!
//!     class RequestMessage {
//!         <<Enum>>
//!         +GetIdentityToken()
//!         +ProcessUrl(VerifiedUrl, PolicyAction)
//!         +SecureQuery(String, String)
//!     }
//!
//!     class ResponseMessage {
//!         <<Enum>>
//!         +IdentityToken(String)
//!         +ProcessUrlResult(u64)
//!         +SecureQueryResponse(String)
//!     }
//!
//!     class PolicyAction {
//!         <<Enum>>
//!         +Allow
//!         +Block
//!         +Warn
//!     }
//!
//!     ProtocolMessage o-- RequestMessage
//!     ProtocolMessage o-- ResponseMessage
//!     ProtocolMessage o-- NotificationMessage
//!     RequestMessage o-- PolicyAction
//! ```
//!
//! ---
//!
//! ## 2. Web Standard Verification: Origin Safety (New Feature)
//!
//! We use a custom type (`VerifiedOrigin`) and an explicit policy (`OriginPolicy`) to ensure that any inter-window or cross-iframe communication (simulating a `postMessage` receiver) is only processed if the origin is explicitly trusted.
//!
//! ### The Policy (The Formal Constraint)
//!
//! The `OriginPolicy` enum formally lists all trusted origins for this service. If an origin is not in this list, a `VerifiedOrigin` cannot be constructed.
//!
//! ```mermaid
//! flowchart LR
//!     A[Incoming Origin String] --> B{OriginPolicy::Verify()}
//!     B -- Trusted Origin? --> C[VerifiedOrigin Type Constructed]
//!     C --> D{Message Handler Logic}
//!     B -- Untrusted Origin --> E[Policy Violation Error (Prevented at Construction)]
//! ```

use serde::{Deserialize, Serialize};
use std::fmt;

// --- 1. Formal Logic in Types (Ensuring Invariants for Protocol) ---

/// A custom type that can only be constructed if the URL is non-empty.
/// Prevents empty-string URLs from entering the system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiedUrl(String);

impl VerifiedUrl {
    /// Attempts to create a VerifiedUrl, failing if the input is invalid.
    pub fn try_new(s: String) -> Result<Self, &'static str> {
        if s.trim().is_empty() {
            Err("URL must not be empty")
        } else {
            Ok(VerifiedUrl(s))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// --- 2. Formal Verification of a Web Standard (Origin Policy) ---

/// A formal list of all allowed origins for postMessage verification.
/// This enum is the policy itself, making the trusted origins auditable.
#[derive(Debug, Clone)]
pub enum OriginPolicy {
    ExtensionService,
    TrustedWebApp,
}

impl OriginPolicy {
    /// Maps a known policy variant to its expected string value.
    pub fn get_value(&self) -> &'static str {
        match self {
            OriginPolicy::ExtensionService => "chrome-extension://my-id",
            OriginPolicy::TrustedWebApp => "https://trusted.app",
        }
    }
}

/// A type that can *only* exist if the incoming origin string matches an
/// allowed origin in the OriginPolicy.
#[derive(Debug, Clone)]
pub struct VerifiedOrigin(String);

impl VerifiedOrigin {
    /// Attempts to create a VerifiedOrigin, enforcing the web standard policy.
    pub fn try_new(s: String) -> Result<Self, String> {
        let is_trusted = [
            OriginPolicy::ExtensionService.get_value(),
            OriginPolicy::TrustedWebApp.get_value(),
        ]
        .contains(&s.as_str());

        if is_trusted {
            Ok(VerifiedOrigin(s))
        } else {
            Err(format!(
                "Origin '{}' violated policy: not in trusted list.",
                s
            ))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for VerifiedOrigin {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// --- 3. Protocol Definition (ADTs for Message Passing) ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PolicyAction {
    Allow,
    Block,
    Warn,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RequestMessage {
    ProcessUrl {
        url: VerifiedUrl,
        action: PolicyAction,
    },
    GetIdentityToken,
    // NEW REQUEST: Requires an origin string which will be validated in the handler
    SecureQuery {
        origin: String,
        query: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ResponseMessage {
    ProcessUrlResult(u64),
    IdentityToken(String),
    SecureQueryResponse(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProtocolMessage {
    Request(RequestMessage),
    Response(ResponseMessage),
    Notification(NotificationMessage),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NotificationMessage {
    PolicyEngineUpdated(u64),
}

// --- 4. Protocol Handler (Compiler-Verified Exhaustiveness) ---

/// Processes an incoming ProtocolMessage and returns an optional response message.
pub fn handle_message(msg: ProtocolMessage) -> Option<ProtocolMessage> {
    match msg {
        ProtocolMessage::Request(req) => match req {
            RequestMessage::GetIdentityToken => {
                println!("--> Handling GetIdentityToken Request...");
                let token = "XYZ-123-ABC".to_string();
                Some(ProtocolMessage::Response(ResponseMessage::IdentityToken(
                    token,
                )))
            }
            RequestMessage::ProcessUrl { url, action } => {
                println!("--> Handling ProcessUrl Request:");
                println!("    - URL: {}", url.as_str());
                println!("    - Action: {:?}", action);
                // ... logic
                let tx_id = 421_u64;
                Some(ProtocolMessage::Response(
                    ResponseMessage::ProcessUrlResult(tx_id),
                ))
            }
            RequestMessage::SecureQuery { origin, query } => {
                println!("--> Handling SecureQuery Request. Origin: {}", origin);

                // **CORE WEB STANDARD VERIFICATION:**
                // The handler logic only proceeds if the Origin can be converted
                // into a VerifiedOrigin.
                let verified_origin = match VerifiedOrigin::try_new(origin) {
                    Ok(vo) => {
                        println!("    -> Policy Success! Trusted Origin: {}", vo);
                        vo
                    }
                    Err(e) => {
                        eprintln!("    -> Policy Failure! {}", e);
                        return Some(ProtocolMessage::Response(
                            ResponseMessage::SecureQueryResponse(
                                "ERROR: Origin policy violation.".to_string(),
                            ),
                        ));
                    }
                };

                // Logic only runs with a guaranteed safe origin
                let response_data = format!(
                    "Processed query '{}' securely from {}",
                    query,
                    verified_origin.as_str()
                );
                Some(ProtocolMessage::Response(
                    ResponseMessage::SecureQueryResponse(response_data),
                ))
            }
        },
        // ... (Response and Notification branches must also be exhaustive)
        ProtocolMessage::Notification(note) => {
            println!("--> Received Notification: {:?}", note);
            None
        }
        ProtocolMessage::Response(resp) => {
            println!("--> Received Response (Processed client-side): {:?}", resp);
            None
        }
    }
}

// --- Example Transport Mockup ---

pub fn mock_transport(msg: &ProtocolMessage) -> Result<ProtocolMessage, serde_json::Error> {
    let json_string = serde_json::to_string(msg)?;
    println!("\n[Transport] Sending JSON: {}", json_string);
    let received_msg: ProtocolMessage = serde_json::from_str(&json_string)?;
    Ok(received_msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_flow_with_web_standard_success() {
        // We simulate a request coming from a KNOWN, trusted origin
        let trusted_origin = OriginPolicy::TrustedWebApp.get_value().to_string();

        let request = ProtocolMessage::Request(RequestMessage::SecureQuery {
            origin: trusted_origin,
            query: "Get config hash".to_string(),
        });

        let received_msg = mock_transport(&request).unwrap();
        let response_opt = handle_message(received_msg);

        assert!(response_opt.is_some());

        // Ensure the response is the SecureQueryResponse and contains success message
        match response_opt.unwrap() {
            ProtocolMessage::Response(ResponseMessage::SecureQueryResponse(s)) => {
                println!("\n[Test Result] Success response: {}", s);
                assert!(s.contains("Processed query"));
            }
            _ => panic!("Did not receive the expected SecureQueryResponse"),
        }
    }

    #[test]
    fn test_protocol_flow_with_web_standard_failure() {
        // We simulate a request coming from an UNKNOWN, untrusted origin
        let untrusted_origin = "https://evil-site.com".to_string();

        let request = ProtocolMessage::Request(RequestMessage::SecureQuery {
            origin: untrusted_origin,
            query: "Drop table".to_string(),
        });

        let received_msg = mock_transport(&request).unwrap();
        let response_opt = handle_message(received_msg);

        assert!(response_opt.is_some());

        // Ensure the response is an error message due to policy failure
        match response_opt.unwrap() {
            ProtocolMessage::Response(ResponseMessage::SecureQueryResponse(s)) => {
                println!("\n[Test Result] Failure response: {}", s);
                assert!(s.contains("ERROR: Origin policy violation"));
            }
            _ => panic!("Did not receive the expected SecureQueryResponse"),
        }
    }
}
