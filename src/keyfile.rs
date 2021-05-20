use anyhow::{anyhow, Result};
use fnv::FnvHashMap;
use hex::FromHex;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

pub struct Keyfile {
    keys: FnvHashMap<[u8; 32], Connection>,
}

impl Keyfile {
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let f = BufReader::new(File::open(path)?);
        let mut keys: FnvHashMap<[u8; 32], Connection> = FnvHashMap::default();
        for line in f.lines() {
            let line = line?;
            let mut iter = line.split_whitespace();
            let is_client_key = match iter.next() {
                Some("CLIENT_KEY") => true,
                Some("SERVER_KEY") => false,
                _ => return Err(anyhow!("invalid keyfile")),
            };
            let conn_id: [u8; 32] = FromHex::from_hex(iter.next().unwrap())?;
            let key: [u8; 32] = FromHex::from_hex(iter.next().unwrap())?;
            let entry = keys.entry(conn_id).or_default();
            if is_client_key {
                entry.client.push(key);
            } else {
                entry.server.push(key);
            }
        }
        Ok(Self { keys })
    }

    pub fn client_keys(&self, conn_id: &[u8; 32]) -> &[[u8; 32]] {
        if let Some(conn) = self.keys.get(conn_id) {
            &conn.client
        } else {
            &[]
        }
    }

    pub fn server_keys(&self, conn_id: &[u8; 32]) -> &[[u8; 32]] {
        if let Some(conn) = self.keys.get(conn_id) {
            &conn.server
        } else {
            &[]
        }
    }
}

#[derive(Default)]
struct Connection {
    client: Vec<[u8; 32]>,
    server: Vec<[u8; 32]>,
}
