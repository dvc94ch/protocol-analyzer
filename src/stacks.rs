use crate::protocols::{Ethernet, Ipv4, Ipv6, Quic, Tcp, Udp};
use crate::{Keyfile, ProtocolHandler, Registry};
use libpacket::ethernet::EtherTypes;
use libpacket::ip::IpNextHeaderProtocols;
use parking_lot::Mutex;
use std::sync::Arc;

pub fn libp2p_stack(keyfile: Keyfile) -> ProtocolHandler {
    let eth = Arc::new(Mutex::new(Ethernet::default()));
    let ip4 = Arc::new(Mutex::new(Ipv4::default()));
    let ip6 = Arc::new(Mutex::new(Ipv6::default()));
    eth.lock().register(EtherTypes::Ipv4, ip4.clone());
    eth.lock().register(EtherTypes::Ipv6, ip6.clone());
    let udp = Arc::new(Mutex::new(Udp::default()));
    let tcp = Arc::new(Mutex::new(Tcp::default()));
    ip4.lock().register(IpNextHeaderProtocols::Udp, udp.clone());
    ip6.lock().register(IpNextHeaderProtocols::Udp, udp.clone());
    ip4.lock().register(IpNextHeaderProtocols::Tcp, tcp.clone());
    ip6.lock().register(IpNextHeaderProtocols::Tcp, tcp);
    let quic = Arc::new(Mutex::new(Quic::new(keyfile)));
    udp.lock().register((), quic);
    eth
}
