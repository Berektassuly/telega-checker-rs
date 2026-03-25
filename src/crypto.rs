use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Deterministic pseudonymization of a Telegram user ID.
///
/// Produces a 32-character hex string (truncated HMAC-SHA256) suitable for
/// use as a TEXT primary key in SQLite analytics tables.
///
/// The same `(telegram_id, salt)` pair always produces the same hash,
/// enabling consistent analytics without storing raw PII.
pub fn hash_user_id(telegram_id: i64, salt: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(salt.as_bytes())
        .expect("HMAC accepts keys of any length");
    mac.update(&telegram_id.to_be_bytes());
    let result = mac.finalize();
    let full_hex = hex::encode(result.into_bytes());
    // Truncate to 32 hex characters (128 bits) — optimal for SQLite TEXT indexing
    full_hex[..32].to_string()
}
