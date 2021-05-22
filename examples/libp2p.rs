use anyhow::Result;
use parking_lot::Mutex;
use protocol_analyzer::protocols::Substream;
use protocol_analyzer::stacks::libp2p_stack;
use protocol_analyzer::{engine, Keyfile, Packet, PcapEngine, Protocol};
use std::fs::File;
use std::sync::Arc;

fn main() -> Result<()> {
    env_logger::init();
    let keyfile = Keyfile::open("keylog")?;
    let (eth, ms) = libp2p_stack(keyfile);
    let ping = Arc::new(Mutex::new(Ping));
    ms.lock().register(Ping.name(), ping);
    let mut engine = engine(eth);
    let mut pcap = File::open("libp2p-quic.pcap")?;
    engine.run(&mut pcap)?;
    Ok(())
}

pub struct Ping;

impl Protocol<Substream> for Ping {
    fn name(&self) -> &'static str {
        "/ping/1\n"
    }

    fn handle_packet(&mut self, packet: Packet<Substream>) -> Result<usize> {
        println!("{} {:x?}", packet.flow.stream_id, packet.payload);
        Ok(0)
    }
}
