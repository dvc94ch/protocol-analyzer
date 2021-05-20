use anyhow::Result;
use protocol_analyzer::stacks::libp2p_stack;
use protocol_analyzer::{engine, Keyfile, PcapEngine};
use std::fs::File;

fn main() -> Result<()> {
    env_logger::init();
    let keyfile = Keyfile::open("keylog")?;
    let stack = libp2p_stack(keyfile);
    let mut engine = engine(stack);
    let mut pcap = File::open("libp2p-quic.pcap")?;
    engine.run(&mut pcap)?;
    Ok(())
}
