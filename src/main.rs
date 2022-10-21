use std::net::{SocketAddr, IpAddr, Ipv4Addr};
use std::sync::{Arc};
use russh::*;
use russh_keys::*;
use tokio::runtime::Handle;
use tokio::sync::{Mutex};
use std::collections::HashMap;
use tracing::{info};
use tracing_subscriber::{fmt, filter::EnvFilter};
use tracing_subscriber::prelude::*;
use tracing_subscriber::layer::SubscriberExt;
use opentelemetry::{KeyValue};
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_semantic_conventions as semcov;
use uuid::Uuid;
use std::env;
use deadpool_postgres::{Config, ManagerConfig, RecyclingMethod, Runtime};
use tokio_postgres::NoTls;

mod ssh;

#[tokio::main]
async fn main() {
    init_tracing();

    // === DB Setup ===
    let mut cfg = Config::new();
    cfg.host = env::var("DB_HOST").ok();
    cfg.dbname = Some("ssh_honeypot".to_string());
    cfg.user = env::var("DB_USERNAME").ok();
    cfg.password = env::var("DB_PASSWORD").ok();
    cfg.manager = Some(ManagerConfig { recycling_method: RecyclingMethod::Fast });

    let db_pool = cfg.create_pool(Some(Runtime::Tokio1), NoTls).unwrap();
   
    // === SSH Setup ===
    let ed25519_private_key = tokio::fs::read_to_string("./id_ed25519").await.unwrap();
    let decoded_ed25519_key = decode_secret_key(ed25519_private_key.as_str(), None).unwrap();
    let rsa_private_key = tokio::fs::read_to_string("./id_rsa").await.unwrap();
    let decoded_rsa_key = decode_secret_key(rsa_private_key.as_str(), None).unwrap();

    let mut config = russh::server::Config::default();
    config.connection_timeout = Some(std::time::Duration::from_secs(600));
    config.auth_rejection_time = std::time::Duration::from_secs(1);
    config.max_auth_attempts = 5000;
    config.keys.push(decoded_ed25519_key);
    config.keys.push(decoded_rsa_key);
    config.server_id = SshId::Standard("SSH-2.0-OpenSSH_9.0".to_string());
    config.methods = MethodSet::PASSWORD | MethodSet::PUBLICKEY;
    

    // === Get External port + listen ===
    let external_port = env::var("EXTERNAL_PORT").unwrap();
    let listen_address = SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 2222
    );

    let ssh_server_handler = ssh::server_handler::SSHServerHandler {
        clients: Arc::new(Mutex::new(HashMap::new())),
        handle: Handle::current(),
        db: Arc::new(db_pool),
        external_port: external_port.parse::<u16>().unwrap()
    };
    
    info!("Starting SSH Server at {:?}", listen_address);
    let config = Arc::new(config);
    if let Err(err) = russh::server::run(config, &listen_address, ssh_server_handler).await {
        panic!("Unable to start SSH Server: {}", err);
    }

    opentelemetry::global::shutdown_tracer_provider();
}

fn init_tracing() {
    info!("Using endpoint {:?} for OTEL traces", std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT"));

    // Create a new OpenTelemetry pipeline
    let tracer = opentelemetry_otlp::new_pipeline()
    .tracing()
    .with_exporter(
        opentelemetry_otlp::new_exporter()
            .tonic()
            // .http()
            .with_env()
            // .with_endpoint("http://localhost:4317/v1/traces")
    )
    .with_trace_config(
        opentelemetry::sdk::trace::config()
            .with_sampler(opentelemetry::sdk::trace::Sampler::AlwaysOn)
            .with_id_generator(opentelemetry::sdk::trace::RandomIdGenerator::default())
            .with_max_events_per_span(64)
            .with_max_attributes_per_span(16)
            .with_max_events_per_span(16)
            .with_resource(opentelemetry::sdk::Resource::new(vec![
                KeyValue::new(semcov::resource::SERVICE_NAME, "ssh-honeypot"),
                KeyValue::new(semcov::resource::SERVICE_VERSION, env!("CARGO_PKG_VERSION")),
                KeyValue::new(semcov::resource::SERVICE_INSTANCE_ID, Uuid::new_v4().to_string()),
                KeyValue::new(semcov::resource::CONTAINER_ID, env::var("HOSTNAME").unwrap_or("".to_string())),
                KeyValue::new(semcov::resource::CONTAINER_RUNTIME, "docker")
            ]))
    )
    .install_batch(opentelemetry::runtime::Tokio)
    .unwrap();

    // Create a tracing layer with the configured tracer
    let telemetry = tracing_opentelemetry::layer().with_tracer(
    tracer // stdout::new_pipeline().install_simple()
    );

    let stdout_layer = fmt::layer()
    .with_target(true);

    let filter_layer = EnvFilter::try_from_default_env()
    .or_else(|_| EnvFilter::try_new("info"))
    .unwrap();

    tracing_subscriber::registry()
    .with(filter_layer)
    .with(telemetry)
    .with(stdout_layer)
    .init();
}