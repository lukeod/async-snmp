//! Select a configured built-in transport at runtime
//!
//! Pass `udp` or `tcp`, followed by an optional socket address. Run against an
//! agent that accepts SNMPv2c with the `public` community on the selected transport.
//!
//! `cargo run --example runtime_transport -- tcp 127.0.0.1:161`

use async_snmp::{
    Auth, BuiltinTransport, ClientBuilder, RuntimeClient, TcpTransport, UdpEndpoint, oid,
};
use std::net::SocketAddr;
use std::time::Duration;

#[tokio::main]
async fn main() -> async_snmp::Result<()> {
    let protocol = std::env::args().nth(1).unwrap_or_else(|| "udp".into());
    let target: SocketAddr = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "127.0.0.1:161".into())
        .parse()
        .expect("target must be a socket address");

    // Configure the selected transport before converting its handle to BuiltinTransport.
    let mut udp_service = None;
    let transport = match protocol.as_str() {
        "udp" => {
            // Pick a matching local address family and use the default caps for this GET.
            let bind = if target.ip().to_canonical().is_ipv4() {
                "0.0.0.0:0"
            } else {
                "[::]:0"
            };
            let endpoint = UdpEndpoint::spawn(bind).await?;
            let peer = endpoint.handle(target)?;
            udp_service = Some(endpoint);
            BuiltinTransport::from(peer)
        }
        "tcp" => BuiltinTransport::from(
            TcpTransport::builder()
                // Bound connection setup independently of SNMP request deadlines.
                .connect_timeout(Duration::from_secs(5))
                .connect(target)
                .await?,
        ),
        _ => return Err(async_snmp::Error::Config("protocol must be udp or tcp".into()).boxed()),
    };

    let client: RuntimeClient =
        ClientBuilder::new(Auth::v2c("public")).build_with_transport(transport)?;
    let response = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await?;
    println!("{response:?}");
    if let Some(service) = udp_service {
        service.shutdown().await?;
    }
    Ok(())
}
