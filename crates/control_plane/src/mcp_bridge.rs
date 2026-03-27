use crate::extension_host::{
    ExtensionHost, McpAuthorizedToolCall, McpScopedToken, McpTokenAuthorizationError,
    McpTokenIssueError,
};
use std::collections::HashMap;
use std::error::Error;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpBridgeSession {
    pub session_id: String,
    pub extension_id: String,
    pub opened_at_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum McpBridgeError {
    InvalidSessionId,
    InvalidExtensionId,
    SessionAlreadyOpen(String),
    SessionNotFound(String),
    SessionExtensionMismatch {
        session_id: String,
        expected_extension_id: String,
        actual_extension_id: String,
    },
    TokenIssue(McpTokenIssueError),
    TokenAuthorization(McpTokenAuthorizationError),
}

impl fmt::Display for McpBridgeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            McpBridgeError::InvalidSessionId => {
                f.write_str("MCP bridge session_id cannot be empty")
            }
            McpBridgeError::InvalidExtensionId => {
                f.write_str("MCP bridge extension_id cannot be empty")
            }
            McpBridgeError::SessionAlreadyOpen(session_id) => {
                write!(f, "MCP bridge session already open: {session_id}")
            }
            McpBridgeError::SessionNotFound(session_id) => {
                write!(f, "MCP bridge session not found: {session_id}")
            }
            McpBridgeError::SessionExtensionMismatch {
                session_id,
                expected_extension_id,
                actual_extension_id,
            } => write!(
                f,
                "MCP bridge session extension mismatch session={} expected={} actual={}",
                session_id, expected_extension_id, actual_extension_id
            ),
            McpBridgeError::TokenIssue(error) => write!(f, "{error}"),
            McpBridgeError::TokenAuthorization(error) => write!(f, "{error}"),
        }
    }
}

impl Error for McpBridgeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            McpBridgeError::TokenIssue(error) => Some(error),
            McpBridgeError::TokenAuthorization(error) => Some(error),
            _ => None,
        }
    }
}

#[derive(Debug, Default)]
pub struct McpBridge {
    sessions: HashMap<String, McpBridgeSession>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpScopedTokenIssueRequest {
    pub extension_id: String,
    pub audience: String,
    pub scopes: Vec<String>,
    pub ttl_ms: u64,
    pub now_unix_ms: u64,
}

impl McpBridge {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn open_session(
        &mut self,
        extension_id: &str,
        session_id: &str,
        opened_at_unix_ms: u64,
    ) -> Result<McpBridgeSession, McpBridgeError> {
        let trimmed_extension_id = extension_id.trim();
        if trimmed_extension_id.is_empty() {
            return Err(McpBridgeError::InvalidExtensionId);
        }
        let trimmed_session_id = session_id.trim();
        if trimmed_session_id.is_empty() {
            return Err(McpBridgeError::InvalidSessionId);
        }
        if self.sessions.contains_key(trimmed_session_id) {
            return Err(McpBridgeError::SessionAlreadyOpen(
                trimmed_session_id.to_string(),
            ));
        }
        let session = McpBridgeSession {
            session_id: trimmed_session_id.to_string(),
            extension_id: trimmed_extension_id.to_string(),
            opened_at_unix_ms,
        };
        self.sessions
            .insert(trimmed_session_id.to_string(), session.clone());
        Ok(session)
    }

    pub fn session(&self, session_id: &str) -> Option<&McpBridgeSession> {
        self.sessions.get(session_id.trim())
    }

    pub fn sessions(&self) -> Vec<&McpBridgeSession> {
        let mut sessions = self.sessions.values().collect::<Vec<_>>();
        sessions.sort_by_key(|entry| entry.session_id.as_str());
        sessions
    }

    pub fn issue_scoped_token(
        &self,
        host: &mut ExtensionHost,
        session_id: &str,
        request: McpScopedTokenIssueRequest,
    ) -> Result<McpScopedToken, McpBridgeError> {
        let trimmed_session_id = session_id.trim();
        if trimmed_session_id.is_empty() {
            return Err(McpBridgeError::InvalidSessionId);
        }
        let Some(session) = self.sessions.get(trimmed_session_id) else {
            return Err(McpBridgeError::SessionNotFound(
                trimmed_session_id.to_string(),
            ));
        };
        let requested_extension_id = request.extension_id.trim();
        if requested_extension_id.is_empty() {
            return Err(McpBridgeError::InvalidExtensionId);
        }
        if session.extension_id != requested_extension_id {
            return Err(McpBridgeError::SessionExtensionMismatch {
                session_id: session.session_id.clone(),
                expected_extension_id: session.extension_id.clone(),
                actual_extension_id: requested_extension_id.to_string(),
            });
        }
        host.issue_mcp_scoped_token(
            requested_extension_id,
            trimmed_session_id,
            request.audience.as_str(),
            request.scopes,
            request.ttl_ms,
            request.now_unix_ms,
        )
        .map_err(McpBridgeError::TokenIssue)
    }

    pub fn authorize_tool_call(
        &self,
        host: &ExtensionHost,
        token: &str,
        tool_name: &str,
        audience: &str,
        now_unix_ms: u64,
    ) -> Result<McpAuthorizedToolCall, McpBridgeError> {
        let authorized = host
            .authorize_mcp_tool_call(token, tool_name, audience, now_unix_ms)
            .map_err(McpBridgeError::TokenAuthorization)?;
        let Some(session) = self.sessions.get(authorized.session_id.as_str()) else {
            return Err(McpBridgeError::SessionNotFound(
                authorized.session_id.clone(),
            ));
        };
        if session.extension_id != authorized.extension_id {
            return Err(McpBridgeError::SessionExtensionMismatch {
                session_id: authorized.session_id.clone(),
                expected_extension_id: session.extension_id.clone(),
                actual_extension_id: authorized.extension_id.clone(),
            });
        }
        Ok(authorized)
    }

    pub fn end_session(
        &mut self,
        host: &mut ExtensionHost,
        session_id: &str,
    ) -> Result<usize, McpBridgeError> {
        let trimmed_session_id = session_id.trim();
        if trimmed_session_id.is_empty() {
            return Err(McpBridgeError::InvalidSessionId);
        }
        if self.sessions.remove(trimmed_session_id).is_none() {
            return Err(McpBridgeError::SessionNotFound(
                trimmed_session_id.to_string(),
            ));
        }
        Ok(host.revoke_mcp_session_tokens(trimmed_session_id))
    }

    pub fn close_extension_sessions(
        &mut self,
        host: &mut ExtensionHost,
        extension_id: &str,
    ) -> usize {
        let trimmed_extension_id = extension_id.trim();
        if trimmed_extension_id.is_empty() {
            return 0;
        }
        let session_ids = self
            .sessions
            .values()
            .filter(|session| session.extension_id == trimmed_extension_id)
            .map(|session| session.session_id.clone())
            .collect::<Vec<_>>();
        let mut revoked = 0usize;
        for session_id in session_ids {
            self.sessions.remove(session_id.as_str());
            revoked = revoked.saturating_add(host.revoke_mcp_session_tokens(session_id.as_str()));
        }
        revoked
    }

    pub fn prune_expired_tokens(&self, host: &mut ExtensionHost, now_unix_ms: u64) -> usize {
        host.prune_expired_mcp_tokens(now_unix_ms)
    }
}

#[cfg(test)]
mod tests {
    use super::{McpBridge, McpBridgeError, McpScopedTokenIssueRequest};
    use crate::extension_host::{McpTokenAuthorizationError, default_extension_host};

    fn setup_enabled_provider_host() -> crate::extension_host::ExtensionHost {
        let mut host = default_extension_host();
        assert!(host.grant_all_permissions("provider-openai").is_ok());
        assert!(host.set_enabled("provider-openai", true).is_ok());
        assert!(
            host.set_mcp_tool_policy("chat.send", "provider.chat", "mcp://tools/chat")
                .is_ok()
        );
        host
    }

    #[test]
    fn open_issue_authorize_and_end_session_round_trip() {
        let mut host = setup_enabled_provider_host();
        let mut bridge = McpBridge::new();

        let opened = bridge.open_session("provider-openai", "session-1", 1_000);
        assert!(opened.is_ok());

        let issued = bridge.issue_scoped_token(
            &mut host,
            "session-1",
            McpScopedTokenIssueRequest {
                extension_id: "provider-openai".to_string(),
                audience: "mcp://tools/chat".to_string(),
                scopes: vec!["provider.chat".to_string()],
                ttl_ms: 5_000,
                now_unix_ms: 1_100,
            },
        );
        assert!(issued.is_ok());
        let issued = match issued {
            Ok(value) => value,
            Err(_) => return,
        };

        let authorized = bridge.authorize_tool_call(
            &host,
            issued.token.as_str(),
            "chat.send",
            "mcp://tools/chat",
            1_200,
        );
        assert!(authorized.is_ok());
        let authorized = match authorized {
            Ok(value) => value,
            Err(_) => return,
        };
        assert_eq!(authorized.extension_id, "provider-openai");
        assert_eq!(authorized.session_id, "session-1");

        let revoked = bridge.end_session(&mut host, "session-1");
        assert_eq!(revoked.ok(), Some(1));

        let denied = bridge.authorize_tool_call(
            &host,
            issued.token.as_str(),
            "chat.send",
            "mcp://tools/chat",
            1_300,
        );
        assert!(denied.is_err());
        let denied = match denied {
            Ok(_) => return,
            Err(value) => value,
        };
        assert!(matches!(
            denied,
            McpBridgeError::TokenAuthorization(McpTokenAuthorizationError::TokenRevoked)
        ));
    }

    #[test]
    fn issue_fails_for_unknown_session() {
        let mut host = setup_enabled_provider_host();
        let bridge = McpBridge::new();
        let issued = bridge.issue_scoped_token(
            &mut host,
            "unknown-session",
            McpScopedTokenIssueRequest {
                extension_id: "provider-openai".to_string(),
                audience: "mcp://tools/chat".to_string(),
                scopes: vec!["provider.chat".to_string()],
                ttl_ms: 5_000,
                now_unix_ms: 1_100,
            },
        );
        assert!(issued.is_err());
        let issued = match issued {
            Ok(_) => return,
            Err(value) => value,
        };
        assert!(matches!(issued, McpBridgeError::SessionNotFound(_)));
    }

    #[test]
    fn issue_fails_when_session_extension_mismatches() {
        let mut host = setup_enabled_provider_host();
        let mut bridge = McpBridge::new();
        assert!(
            bridge
                .open_session("provider-openai", "session-1", 1_000)
                .is_ok()
        );
        let issued = bridge.issue_scoped_token(
            &mut host,
            "session-1",
            McpScopedTokenIssueRequest {
                extension_id: "viewer-session-inspector".to_string(),
                audience: "mcp://tools/chat".to_string(),
                scopes: vec!["provider.chat".to_string()],
                ttl_ms: 5_000,
                now_unix_ms: 1_100,
            },
        );
        assert!(issued.is_err());
        let issued = match issued {
            Ok(_) => return,
            Err(value) => value,
        };
        assert!(matches!(
            issued,
            McpBridgeError::SessionExtensionMismatch { .. }
        ));
    }

    #[test]
    fn authorize_fails_when_session_not_tracked_by_bridge() {
        let mut host = setup_enabled_provider_host();
        let mut bridge = McpBridge::new();
        assert!(
            bridge
                .open_session("provider-openai", "session-1", 1_000)
                .is_ok()
        );
        let issued = host.issue_mcp_scoped_token(
            "provider-openai",
            "session-1",
            "mcp://tools/chat",
            vec!["provider.chat".to_string()],
            5_000,
            1_100,
        );
        assert!(issued.is_ok());
        let issued = match issued {
            Ok(value) => value,
            Err(_) => return,
        };
        let ended = bridge.end_session(&mut host, "session-1");
        assert!(ended.is_ok());
        let authorized = bridge.authorize_tool_call(
            &host,
            issued.token.as_str(),
            "chat.send",
            "mcp://tools/chat",
            1_200,
        );
        assert!(authorized.is_err());
    }

    #[test]
    fn close_extension_sessions_revokes_all_tokens() {
        let mut host = setup_enabled_provider_host();
        let mut bridge = McpBridge::new();
        assert!(
            bridge
                .open_session("provider-openai", "session-a", 1_000)
                .is_ok()
        );
        assert!(
            bridge
                .open_session("provider-openai", "session-b", 1_100)
                .is_ok()
        );

        let issued_a = bridge.issue_scoped_token(
            &mut host,
            "session-a",
            McpScopedTokenIssueRequest {
                extension_id: "provider-openai".to_string(),
                audience: "mcp://tools/chat".to_string(),
                scopes: vec!["provider.chat".to_string()],
                ttl_ms: 5_000,
                now_unix_ms: 1_200,
            },
        );
        assert!(issued_a.is_ok());
        let issued_a = match issued_a {
            Ok(value) => value,
            Err(_) => return,
        };

        let issued_b = bridge.issue_scoped_token(
            &mut host,
            "session-b",
            McpScopedTokenIssueRequest {
                extension_id: "provider-openai".to_string(),
                audience: "mcp://tools/chat".to_string(),
                scopes: vec!["provider.chat".to_string()],
                ttl_ms: 5_000,
                now_unix_ms: 1_300,
            },
        );
        assert!(issued_b.is_ok());
        let issued_b = match issued_b {
            Ok(value) => value,
            Err(_) => return,
        };

        let revoked = bridge.close_extension_sessions(&mut host, "provider-openai");
        assert_eq!(revoked, 2);
        assert!(bridge.sessions().is_empty());

        let denied_a = bridge.authorize_tool_call(
            &host,
            issued_a.token.as_str(),
            "chat.send",
            "mcp://tools/chat",
            1_400,
        );
        assert!(denied_a.is_err());
        let denied_b = bridge.authorize_tool_call(
            &host,
            issued_b.token.as_str(),
            "chat.send",
            "mcp://tools/chat",
            1_400,
        );
        assert!(denied_b.is_err());
    }
}
