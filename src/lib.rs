use anyhow::Result;
use libpcap_tools::{Config, Error, ParseContext, PcapAnalyzer, PcapDataEngine};
use parking_lot::Mutex;
use pcap_parser::data::PacketData as PcapPacket;
use std::sync::Arc;

mod keyfile;
pub mod protocols;
pub mod stacks;

pub use crate::keyfile::Keyfile;
pub use libpcap_tools::PcapEngine;

pub fn engine(handler: ProtocolHandler<()>) -> PcapDataEngine<Analyzer> {
    let config = Config::default();
    let analyzer = Analyzer::new(handler);
    PcapDataEngine::new(analyzer, &config)
}

fn transmute<'a, 'b>(a: &'a [u8]) -> &'b [u8] {
    unsafe { std::mem::transmute(a) }
}

pub struct Analyzer {
    handler: ProtocolHandler<()>,
}

impl Analyzer {
    pub fn new(handler: ProtocolHandler<()>) -> Self {
        Self { handler }
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
        let packet = Packet { payload, flow: () };
        let undissected_bytes = self
            .handler
            .lock()
            .handle_packet(packet)
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;
        log::debug!("undissected bytes {}", undissected_bytes);
        Ok(())
    }
}

pub struct Packet<'a, F> {
    pub payload: &'a [u8],
    pub flow: F,
}

pub trait Protocol<F> {
    fn name(&self) -> &'static str;

    fn handle_packet<'a>(&mut self, packet: Packet<'a, F>) -> Result<usize>;
}

pub type ProtocolHandler<F> = Arc<Mutex<dyn Protocol<F>>>;

pub trait Registry<F> {
    type ProtocolId;

    fn register(&mut self, protocol: Self::ProtocolId, handler: ProtocolHandler<F>);
}

pub type ProtocolRegistry<F, P> = Arc<Mutex<dyn Registry<F, ProtocolId = P>>>;
