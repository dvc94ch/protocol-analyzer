use anyhow::{anyhow, Result};
use fnv::{FnvHashMap, FnvHashSet};
use libpacket::ethernet::{EtherType, EtherTypes, EthernetPacket};
use libpacket::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use libpacket::ipv4::Ipv4Packet;
use libpacket::ipv6::Ipv6Packet;
use libpacket::udp::UdpPacket;
use libpacket::Packet as _;
use libpcap_tools::{Config, Error, ParseContext, PcapAnalyzer, PcapDataEngine, PcapEngine};
use parking_lot::Mutex;
use pcap_parser::data::PacketData as PcapPacket;
use std::fs::File;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

fn main() -> Result<()> {
    env_logger::init();
    let config = Config::default();

    let eth = Arc::new(Mutex::new(Ethernet::default()));
    let ip4 = Arc::new(Mutex::new(Ipv4::default()));
    let ip6 = Arc::new(Mutex::new(Ipv6::default()));
    eth.lock().register(EtherTypes::Ipv4, ip4.clone());
    eth.lock().register(EtherTypes::Ipv6, ip6.clone());
    let udp = Arc::new(Mutex::new(Udp::default()));
    ip4.lock().register(IpNextHeaderProtocols::Udp, udp.clone());
    ip6.lock().register(IpNextHeaderProtocols::Udp, udp.clone());
    let quic = Arc::new(Mutex::new(Quic::default()));
    udp.lock().register((), quic);

    let analyzer = Analyzer::new(eth);
    let mut engine = PcapDataEngine::new(analyzer, &config);
    let mut f = File::open("/home/dvc/ipld/quinn-noise-dissector/libp2p-quic.pcap")?;
    engine.run(&mut f)?;

    Ok(())
}

fn transmute<'a, 'b>(a: &'a [u8]) -> &'b [u8] {
    unsafe { std::mem::transmute(a) }
}

pub struct Analyzer {
    handler: ProtocolHandler,
    flows: FnvHashSet<Flow>,
}

impl Analyzer {
    pub fn new(handler: ProtocolHandler) -> Self {
        Self { handler, flows: Default::default() }
    }
}

impl PcapAnalyzer for Analyzer {
    fn init(&mut self) -> Result<(), Error> {
        Ok(())
    }

    fn handle_packet(
        &mut self,
        packet: &libpcap_tools::Packet,
        _ctx: &ParseContext,
    ) -> Result<(), Error> {
        let payload = match packet.data {
            PcapPacket::L2(data) => data,
            PcapPacket::L3(_, data) => data,
            PcapPacket::L4(_, data) => data,
            PcapPacket::Unsupported(data) => data,
        };
        let mut packet = Packet {
            payload,
            flow: Flow::default(),
        };
        let mut handler = self.handler.clone();
        loop {
            let (handler2, packet2) = handler
                .lock()
                .handle_packet(packet)
                .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;
            if let Some(handler2) = handler2 {
                handler = handler2;
                packet = packet2;
            } else {
                if !packet2.payload.is_empty() {
                    log::debug!("{} undissected bytes", packet2.payload.len());
                }
                self.flows.insert(packet2.flow);
                break;
            }
        }
        Ok(())
    }

    fn teardown(&mut self) {
        for flow in &self.flows {
            println!("udp {}:{} => {}:{}", flow.src_ip, flow.src_port, flow.dst_ip, flow.dst_port);
        }
    }
}

#[derive(PartialEq, Eq, Hash)]
pub struct Flow {
    src_ip: IpAddr,
    dst_ip: IpAddr,
    protocol: IpNextHeaderProtocol,
    src_port: u16,
    dst_port: u16,
}

impl Default for Flow {
    fn default() -> Self {
        Self {
            src_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            dst_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            protocol: IpNextHeaderProtocol(255),
            src_port: 0,
            dst_port: 0,
        }
    }
}

pub struct Packet<'a> {
    payload: &'a [u8],
    flow: Flow,
}

pub trait Protocol {
    fn name(&self) -> &'static str;

    fn handle_packet<'a>(
        &mut self,
        packet: Packet<'a>,
    ) -> Result<(Option<ProtocolHandler>, Packet<'a>)>;
}

pub type ProtocolHandler = Arc<Mutex<dyn Protocol>>;

pub trait Registry {
    type ProtocolId;

    fn register(&mut self, protocol: Self::ProtocolId, handler: ProtocolHandler);
}

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
        println!("{}", packet.payload.len());
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
