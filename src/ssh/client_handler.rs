use std::net::{IpAddr};
use std::pin::Pin;
use std::sync::{Arc};
use futures::FutureExt;
use russh::*;
use russh::server::{Auth, Session};
use russh_keys::*;
use tracing::{debug, info, warn};
use deadpool_postgres::Pool;
use tracing_futures::Instrument;

use super::AuthType;
use super::server_handler::SSHServerHandler;

pub struct SSHClientHandler {
    pub server: SSHServerHandler,
    pub current_client_ip: IpAddr
}

impl Drop for SSHClientHandler {
    fn drop(&mut self) {
        debug!("Dropping ssh client handler")
    }
}

impl SSHClientHandler {
    fn finished_deny_auth(self) -> Pin<Box<dyn futures::future::Future<Output = Result<(Self, server::Auth), anyhow::Error>> + Send>> {
        futures::future::ready(self.reject_auth()).boxed()
    }
 
    fn reject_auth(self) -> Result<(Self, server::Auth), anyhow::Error> {
        return Ok((
            self,
            server::Auth::Reject { 
                proceed_with_methods: None
            }
        ))
    }
}

#[tracing::instrument(name = "INSERT ssh_honeypot.credentials", level="info", skip(db, secret), fields(db.system = "postgresql", db.name = "ssh_honeypot", db.operation = "INSERT"))]
async fn db_action(db: Arc<Pool>, client_ip: IpAddr, port: i32, auth_type: AuthType, username: String, secret: String) {
    let client = db.get().await.unwrap();
    let statement = client.prepare_cached(
        "INSERT INTO credentials (timestamp, client_ip, port, auth_type, username, secret) VALUES (current_timestamp, $1, $2, $3, $4, $5)"
    ).await.unwrap();
    
    if let Err(_err) = client.query(&statement, &[&client_ip, &port, &auth_type, &username, &secret]).await {
        info!("Unable to perform INSERT INTO credentials")
    }
}

impl server::Handler for SSHClientHandler {
    type Error = anyhow::Error;
    type FutureAuth = Pin<Box<dyn futures::future::Future<Output = Result<(Self, server::Auth), anyhow::Error>> + Send>>;
    type FutureUnit = Pin<Box<dyn futures::future::Future<Output = Result<(Self, Session), anyhow::Error>> + Send>>;
    type FutureBool = Pin<Box<dyn futures::future::Future<Output = Result<(Self, Session, bool), anyhow::Error>> + Send>>;

    fn finished_auth(self, auth: Auth) -> Self::FutureAuth {
        futures::future::ready(Ok((self, auth))).boxed()
    }
    fn finished_bool(self, b: bool, s: Session) -> Self::FutureBool {
        futures::future::ready(Ok((self, s, b))).boxed()
    }
    fn finished(self, s: Session) -> Self::FutureUnit {
        futures::future::ready(Ok((self, s))).boxed()
    }
    
    // ======================================= START AUTH =======================================

    #[tracing::instrument(level = "info", skip(self), fields(external_port = %self.server.external_port, user = %user))]
    fn auth_publickey(self, user: &str, key: &key::PublicKey) -> Self::FutureAuth {
        debug!("Credentials: user{}, key_fingerprint={}", user, key.fingerprint());
        
        Box::pin(
            db_action(
                self.server.db.clone(), 
                self.current_client_ip, 
                self.server.external_port.into() , 
                AuthType::PublicKey, 
                user.to_string(), 
                key.fingerprint()
            ).instrument(tracing::info_span!("async context"))
             .map(|_| self.reject_auth())
        )
    }

    #[tracing::instrument(level = "info", skip(self), fields(external_port = %self.server.external_port, user = %user))]
    fn auth_password(self, user: &str, password: &str) -> Self::FutureAuth {
        debug!("Credentials: user={}, password=***masked***", user);
        
        Box::pin(
            db_action(
                self.server.db.clone(), 
                self.current_client_ip, 
                self.server.external_port.into() , 
                AuthType::Password, 
                user.to_string(), 
                password.to_string()
            ).instrument(tracing::info_span!("async context"))
             .map(|_| self.reject_auth())
        )
    }

    #[tracing::instrument(level = "info", skip(self, _response))]
    fn auth_keyboard_interactive(self, user: &str, submethods: &str, _response: Option<server::Response>) -> Self::FutureAuth {
        debug!("Deny Interactive: {} -> {}", user, submethods);
        self.finished_deny_auth()
    }

    #[tracing::instrument(level = "info", skip(self), fields(external_port = %self.server.external_port, user = %user))]
    fn auth_none(self, user: &str) -> Self::FutureAuth {
        

        Box::pin(
            db_action(
                self.server.db.clone(), 
                self.current_client_ip, 
                self.server.external_port.into() , 
                AuthType::None, 
                user.to_string(), 
                String::new()
            ).instrument(tracing::info_span!("async context"))
             .map(|_| self.reject_auth())
        )
    }

    // ======================================= END  AUTH =======================================

}
