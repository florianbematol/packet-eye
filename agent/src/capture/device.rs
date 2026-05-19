//! Network device discovery via libpcap.

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct DeviceInfo {
    pub name: String,
    pub description: Option<String>,
    pub addresses: Vec<String>,
    pub flags: u32,
    pub is_loopback: bool,
}

pub fn list() -> Result<Vec<DeviceInfo>, String> {
    let devices = pcap::Device::list().map_err(|e| e.to_string())?;
    let out = devices
        .into_iter()
        .map(|d| {
            let is_loopback = d.flags.is_loopback();
            DeviceInfo {
                name: d.name,
                description: d.desc,
                addresses: d
                    .addresses
                    .iter()
                    .map(|a| a.addr.to_string())
                    .collect(),
                flags: d.flags.if_flags.bits() as u32,
                is_loopback,
            }
        })
        .collect();
    Ok(out)
}
