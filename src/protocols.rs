use crate::{transmute, Keyfile, Packet, Protocol, ProtocolHandler, Registry};
use anyhow::{anyhow, Result};
use fnv::{FnvHashMap, FnvHashSet};
use libpacket::ethernet::{EtherType, EthernetPacket};
use libpacket::ip::IpNextHeaderProtocol;
use libpacket::ipv4::Ipv4Packet;
use libpacket::ipv6::Ipv6Packet;
use libpacket::quic::{CryptoPacket, Frame, QuicPacket};
use libpacket::tcp::TcpPacket;
use libpacket::udp::UdpPacket;
use libpacket::Packet as _;
use std::convert::TryInto;
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

pub struct Quic {
    registry: FnvHashMap<(), ProtocolHandler>,
    keyfile: Keyfile,
    flows: Vec<QuicFlow>,
}

impl Quic {
    pub fn new(keyfile: Keyfile) -> Self {
        Self {
            registry: Default::default(),
            keyfile,
            flows: Default::default(),
        }
    }

    fn process_packet(&mut self, packet: &QuicPacket, key: usize) -> Result<()> {
        let mut flow = None;
        let dest_id = packet.dest_id();
        let src_id = packet.src_id();
        for f in &mut self.flows {
            if let Some(src_id) = src_id.as_ref() {
                if f.client_ids.contains(src_id) {
                    flow = Some((f, true));
                    break;
                }
                if f.server_ids.contains(src_id) {
                    flow = Some((f, false));
                    break;
                }
            }
            if f.server_ids.contains(&dest_id) {
                flow = Some((f, true));
                break;
            }
            if f.client_ids.contains(&dest_id) {
                flow = Some((f, false));
                break;
            }
        }
        let (flow, client) = if let Some(f) = flow {
            f
        } else {
            let mut flow = QuicFlow::default();
            if packet.packet().len() >= 1200 {
                flow.client_ids.insert(src_id.unwrap());
            } else {
                unimplemented!();
            }
            self.flows.push(flow);
            (self.flows.last_mut().unwrap(), true)
        };
        let payload = if key == 0 {
            if !client {
                flow.server_ids.insert(packet.src_id().unwrap());
            }
            decrypt_with(&packet, &[0; 32])?
        } else {
            let conn_id = flow.conn_id;
            let keys = if client {
                self.keyfile.client_keys(&conn_id)
            } else {
                self.keyfile.server_keys(&conn_id)
            };
            decrypt_with(&packet, &keys[key - 1])?
        };
        for frame in Frame::new(&payload).unwrap() {
            println!("{}", frame);
            match frame {
                Frame::Ack(ack) => {
                    // TODO: packet number
                }
                Frame::Crypto(crypto) => {
                    if let Some(conn_id) = extract_conn_id(&crypto) {
                        flow.conn_id = conn_id;
                    }
                }
                Frame::NewConnectionId(id) => {
                    let conn_id = id.get_connection_id();
                    if client {
                        flow.client_ids.insert(conn_id);
                    } else {
                        flow.server_ids.insert(conn_id);
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }
}

impl Protocol for Quic {
    fn name(&self) -> &'static str {
        "quic"
    }

    fn handle_packet<'a>(
        &mut self,
        mut packet: Packet<'a>,
    ) -> Result<(Option<ProtocolHandler>, Packet<'a>)> {
        println!("begin datagram");
        for quic in QuicPacket::new(packet.payload).ok_or_else(|| anyhow!("invalid quic packet"))? {
            print!("{}", quic);
            match &quic {
                QuicPacket::Initial(_) => self.process_packet(&quic, 0)?,
                QuicPacket::ZeroRtt(_) | QuicPacket::Handshake(_) => {
                    self.process_packet(&quic, 1)?
                }
                QuicPacket::OneRtt(_) => self.process_packet(&quic, 2)?,
                QuicPacket::Retry(_) => {}
                QuicPacket::VersionNegotiation(_) => {}
            }
        }
        println!("end datagram\n");

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

fn extract_conn_id(crypto: &CryptoPacket) -> Option<[u8; 32]> {
    let crypto = crypto.get_crypto_payload_raw();
    let (proto, rest) = crypto.split_at(34);
    if proto == &b"!Noise_IKpsk1_Edx25519_ChaCha8Poly"[..] {
        let (conn_id, _rest) = rest.split_at(32);
        Some(conn_id.try_into().unwrap())
    } else {
        None
    }
}

fn decrypt_with(packet: &QuicPacket, key: &[u8; 32]) -> Result<Vec<u8>> {
    use quinn_proto::crypto::PacketKey;
    let number = packet.packet_number().unwrap();
    let payload = packet.frames().unwrap();
    let header_len = packet.packet().len() - payload.len() - packet.remaining().len();
    let header = &packet.packet()[..header_len];
    let mut payload = bytes::BytesMut::from(payload);
    let key = quinn_noise::ChaCha8PacketKey::new(*key);
    key.decrypt(number, header, &mut payload)
        .or_else(|_| Err(anyhow!("failed to decrypt packet")))?;
    Ok(payload.to_vec())
}

#[derive(Debug, Default)]
struct QuicFlow {
    conn_id: [u8; 32],
    client_ids: FnvHashSet<Vec<u8>>,
    server_ids: FnvHashSet<Vec<u8>>,
}
