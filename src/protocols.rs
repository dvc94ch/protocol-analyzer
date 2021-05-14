use crate::{transmute, Packet, Protocol, ProtocolHandler, Registry};
use anyhow::{anyhow, Result};
use fnv::FnvHashMap;
use libpacket::ethernet::{EtherType, EthernetPacket};
use libpacket::ip::IpNextHeaderProtocol;
use libpacket::ipv4::Ipv4Packet;
use libpacket::ipv6::Ipv6Packet;
use libpacket::quic::QuicPacket;
use libpacket::tcp::TcpPacket;
use libpacket::udp::UdpPacket;
use libpacket::Packet as _;
use std::net::IpAddr;
#[derive(Default)]

pub struct Ethernet {
    registry: FnvHashMap<EtherType, ProtocolHandler>,
}

impl Protocol for Ethernet {
    fn name(&self) -> &'static str {
        "ethernet"
    }

    fn handle_packet<'a>(
        &mut self,
        mut packet: Packet<'a>,
    ) -> Result<(Option<ProtocolHandler>, Packet<'a>)> {
        let eth =
            EthernetPacket::new(&packet.payload).ok_or_else(|| anyhow!("invalid eth packet"))?;
        let protocol = self.registry.get(&eth.get_ethertype()).cloned();
        packet.payload = transmute(eth.payload());
        Ok((protocol, packet))
    }
}

impl Registry for Ethernet {
    type ProtocolId = EtherType;

    fn register(&mut self, protocol: Self::ProtocolId, handler: ProtocolHandler) {
        self.registry.insert(protocol, handler);
    }
}

#[derive(Default)]
pub struct Ipv4 {
    registry: FnvHashMap<IpNextHeaderProtocol, ProtocolHandler>,
}

impl Protocol for Ipv4 {
    fn name(&self) -> &'static str {
        "ipv4"
    }

    fn handle_packet<'a>(
        &mut self,
        mut packet: Packet<'a>,
    ) -> Result<(Option<ProtocolHandler>, Packet<'a>)> {
        let ip = Ipv4Packet::new(&packet.payload).ok_or_else(|| anyhow!("invalid ip4 packet"))?;
        let protocol = self.registry.get(&ip.get_next_level_protocol()).cloned();
        packet.flow.src_ip = IpAddr::V4(ip.get_source());
        packet.flow.dst_ip = IpAddr::V4(ip.get_destination());
        packet.payload = transmute(ip.payload());
        Ok((protocol, packet))
    }
}

impl Registry for Ipv4 {
    type ProtocolId = IpNextHeaderProtocol;

    fn register(&mut self, protocol: Self::ProtocolId, handler: ProtocolHandler) {
        self.registry.insert(protocol, handler);
    }
}

#[derive(Default)]
pub struct Ipv6 {
    registry: FnvHashMap<IpNextHeaderProtocol, ProtocolHandler>,
}

impl Protocol for Ipv6 {
    fn name(&self) -> &'static str {
        "ipv6"
    }

    fn handle_packet<'a>(
        &mut self,
        mut packet: Packet<'a>,
    ) -> Result<(Option<ProtocolHandler>, Packet<'a>)> {
        let ip = Ipv6Packet::new(&packet.payload).ok_or_else(|| anyhow!("invalid ip6 packet"))?;
        let protocol = self.registry.get(&ip.get_next_header()).cloned();
        packet.flow.src_ip = IpAddr::V6(ip.get_source());
        packet.flow.dst_ip = IpAddr::V6(ip.get_destination());
        packet.payload = transmute(ip.payload());
        Ok((protocol, packet))
    }
}

impl Registry for Ipv6 {
    type ProtocolId = IpNextHeaderProtocol;

    fn register(&mut self, protocol: Self::ProtocolId, handler: ProtocolHandler) {
        self.registry.insert(protocol, handler);
    }
}

#[derive(Default)]
pub struct Udp {
    registry: FnvHashMap<(), ProtocolHandler>,
}

impl Protocol for Udp {
    fn name(&self) -> &'static str {
        "udp"
    }

    fn handle_packet<'a>(
        &mut self,
        mut packet: Packet<'a>,
    ) -> Result<(Option<ProtocolHandler>, Packet<'a>)> {
        let udp = UdpPacket::new(packet.payload).ok_or_else(|| anyhow!("invalid udp packet"))?;
        let protocol = self.registry.get(&()).cloned();
        packet.flow.src_port = udp.get_source();
        packet.flow.dst_port = udp.get_destination();
        packet.payload = transmute(udp.payload());
        Ok((protocol, packet))
    }
}

impl Registry for Udp {
    type ProtocolId = ();

    fn register(&mut self, protocol: Self::ProtocolId, handler: ProtocolHandler) {
        self.registry.insert(protocol, handler);
    }
}

#[derive(Default)]
pub struct Tcp {
    registry: FnvHashMap<(), ProtocolHandler>,
}

impl Protocol for Tcp {
    fn name(&self) -> &'static str {
        "tcp"
    }

    fn handle_packet<'a>(
        &mut self,
        mut packet: Packet<'a>,
    ) -> Result<(Option<ProtocolHandler>, Packet<'a>)> {
        let tcp = TcpPacket::new(packet.payload).ok_or_else(|| anyhow!("invalid tcp packet"))?;
        let protocol = self.registry.get(&()).cloned();
        packet.flow.src_port = tcp.get_source();
        packet.flow.dst_port = tcp.get_destination();
        packet.payload = transmute(tcp.payload());
        Ok((protocol, packet))
    }
}

impl Registry for Tcp {
    type ProtocolId = ();

    fn register(&mut self, protocol: Self::ProtocolId, handler: ProtocolHandler) {
        self.registry.insert(protocol, handler);
    }
}

#[derive(Default)]
pub struct Quic {
    registry: FnvHashMap<(), ProtocolHandler>,
}

impl Protocol for Quic {
    fn name(&self) -> &'static str {
        "quic"
    }

    fn handle_packet<'a>(
        &mut self,
        mut packet: Packet<'a>,
    ) -> Result<(Option<ProtocolHandler>, Packet<'a>)> {
        let quic = QuicPacket::new(packet.payload).ok_or_else(|| anyhow!("invalid quic packet"))?;
        println!("{:?}", quic);
        println!("{}", quic);
        let protocol = self.registry.get(&()).cloned();
        packet.payload = &[];
        Ok((protocol, packet))
    }
}

impl Registry for Quic {
    type ProtocolId = ();

    fn register(&mut self, protocol: Self::ProtocolId, handler: ProtocolHandler) {
        self.registry.insert(protocol, handler);
    }
}
