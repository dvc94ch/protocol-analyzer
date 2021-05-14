use anyhow::Result;
use protocol_analyzer::stacks::libp2p_stack;
use protocol_analyzer::{engine, PcapEngine};
use std::fs::File;

fn main() -> Result<()> {
    env_logger::init();
    let stack = libp2p_stack();
    let mut engine = engine(stack);
    let mut f = File::open("libp2p-quic.pcap")?;
    engine.run(&mut f)?;
    Ok(())
}
