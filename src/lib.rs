use anyhow::Result;
use fnv::FnvHashSet;
use libpacket::ip::IpNextHeaderProtocol;
use libpcap_tools::{Config, Error, ParseContext, PcapAnalyzer, PcapDataEngine};
use parking_lot::Mutex;
use pcap_parser::data::PacketData as PcapPacket;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

pub mod protocols;
pub mod stacks;

pub use libpcap_tools::PcapEngine;

pub fn engine(handler: ProtocolHandler) -> PcapDataEngine<Analyzer> {
    let config = Config::default();
    let analyzer = Analyzer::new(handler);
    PcapDataEngine::new(analyzer, &config)
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
        Self {
            handler,
            flows: Default::default(),
        }
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
            println!(
                "udp {}:{} => {}:{}",
                flow.src_ip, flow.src_port, flow.dst_ip, flow.dst_port
            );
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
