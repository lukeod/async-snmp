#[derive(Clone, Copy)]
struct ContractTransport;

impl Transport for ContractTransport {
    async fn send(&self, _data: &[u8]) -> Result<()> {
        Ok(())
    }

    async fn recv_with<T, F>(
        &self,
        _registration: RequestRegistration,
        _validate: F,
    ) -> Result<T>
    where
        T: Send,
        F: FnMut(Bytes, SocketAddr) -> Result<Candidate<T>> + Send,
    {
        Err(Error::Config("compile-contract transport has no response".into()).boxed())
    }

    fn peer_addr(&self) -> SocketAddr {
        SocketAddr::from((Ipv4Addr::LOCALHOST, 161))
    }

    fn local_addr(&self) -> SocketAddr {
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
    }

    fn is_reliable(&self) -> bool {
        true
    }
}

fn assert_send<T: Send>(_value: T) {}

fn compile_default_and_generic_surface<T: Transport>(transport: &T) {
    let registration = RequestRegistration::v3(7, std::time::Duration::from_secs(1));

    assert_send(transport.send(b"request"));
    assert_send(transport.recv(registration.clone()));
    assert_send(transport.recv_with(registration.clone(), |data, source| {
        Result::Ok(Candidate::Accept((data, source)))
    }));
    assert_send(transport.request(b"request", registration.clone()));
    assert_send(transport.request_with(b"request", registration, |data, source| {
        Result::Ok(Candidate::Accept((data, source)))
    }));
}

#[test]
fn transport_contract_compiles_with_required_method_and_send_futures() {
    compile_default_and_generic_surface(&ContractTransport);
}
