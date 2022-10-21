use tokio_postgres::types::{ToSql};

pub mod client_handler;
pub mod server_handler;

#[derive(Debug, ToSql)]
#[postgres(name = "auth_type")]
enum AuthType {
    #[postgres(name = "password")]
	Password,
    #[postgres(name = "publickey")]
	PublicKey,
    #[postgres(name = "none")]
    None,
}