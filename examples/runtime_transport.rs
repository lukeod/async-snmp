//! Select a configured built-in transport at runtime
//!
//! Pass `udp` or `tcp`, followed by an optional socket address:
//!
//! `cargo run --example runtime_transport -- tcp 127.0.0.1:161`

use async_snmp::{
    Auth, BuiltinTransport, ClientBuilder, RuntimeClient, TcpTransport, UdpTransport, oid,
};
use std::net::SocketAddr;

#[tokio::main]
async fn main() -> async_snmp::Result<()> {
    let protocol = std::env::args().nth(1).unwrap_or_else(|| "udp".into());
    let target: SocketAddr = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "127.0.0.1:161".into())
        .parse()
        .expect("target must be a socket address");

    // Apply transport-specific settings before erasing the concrete type into
    // BuiltinTransport. The client builder preserves these settings.
    let transport = match protocol.as_str() {
        "udp" => {
            let endpoint = UdpTransport::builder()
                .bind("0.0.0.0:0")
                .max_message_size(8192)
                .build()
                .await?;
            BuiltinTransport::from(endpoint.handle(target)?)
        }
        "tcp" => BuiltinTransport::from(
            TcpTransport::builder()
                .max_message_size(256 * 1024)
                .connect(target)
                .await?,
        ),
        _ => return Err(async_snmp::Error::Config("protocol must be udp or tcp".into()).boxed()),
    };

    let client: RuntimeClient =
        ClientBuilder::new(Auth::v2c("public")).build_with_transport(transport)?;
    let response = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await?;
    println!("{response:?}");
    Ok(())
}
