use std::net::IpAddr;
use std::sync::{Arc};
use russh::{server, ChannelId};
use tokio::runtime::Handle;
use tokio::sync::{Mutex};
use std::collections::HashMap;
use tracing::{info, warn, error};
use deadpool_postgres::{Pool};

use super::client_handler::SSHClientHandler;

#[derive(Clone)]
pub struct SSHServerHandler {
    // Shared server state
    pub clients: Arc<Mutex<HashMap<(usize, ChannelId), russh::server::Handle>>>,
    pub handle: Handle,
    pub db: Arc<Pool>,
    pub external_port: u16,
}

impl<'a> server::Server for SSHServerHandler {
    type Handler = SSHClientHandler;

    // produced instance is given to stream -> unqiue per stream / session 
    #[tracing::instrument(level = "info", skip(self))]
    fn new_client(&mut self, client_ip: Option<std::net::SocketAddr>) -> SSHClientHandler {
        if client_ip.is_none() {
            error!("No peer IP-Adress specified!")
        }

        let ip = client_ip.map(|sock_addr| sock_addr.ip()).expect("No peer IP-Adress specified!");
        {
            let _guard = self.handle.enter();
            futures::executor::block_on(save_client_connected(self.db.clone(), ip, self.external_port as i32));
        }

        info!("Processing new client connection: {:?}", ip);
        SSHClientHandler {
            server: self.clone(), 
            current_client_ip: ip
        }
    }
}

#[tracing::instrument(name = "INSERT ssh_honeypot.clients", level="info", skip(db), fields(db.system = "postgresql", db.name = "ssh_honeypot", db.operation = "INSERT"))]
async fn save_client_connected(db: Arc<Pool>, client_ip: IpAddr, port: i32) {
    let client = db.get().await.unwrap();
    let statement = client.prepare_cached(
        "INSERT INTO clients (client_ip) VALUES ($1)"
    ).await.unwrap();
    
    if let Err(_err) = client.query(&statement, &[&client_ip]).await {
        info!("Unable to insert client connection event into table")
    }
}