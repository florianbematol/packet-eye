//! Map a local socket (port + protocol) to the owning process.
//!
//! On Windows we periodically snapshot the full TCP/UDP tables via
//! `GetExtendedTcpTable` / `GetExtendedUdpTable` (with `TCP_TABLE_OWNER_PID_ALL`
//! / `UDP_TABLE_OWNER_PID`) and resolve each PID's image name once via
//! `sysinfo`.
//!
//! Lookups from the capture pipeline are O(1) on a `DashMap` keyed by
//! `(port, proto)`.

use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use parking_lot::RwLock;
use sysinfo::{Pid, ProcessRefreshKind, RefreshKind, System};

use crate::capture::types::Protocol;

#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
}

pub struct ProcessResolver {
    /// Key: (port, proto). Value: process info.
    table: DashMap<(u16, Protocol), ProcessInfo>,
    /// Reusable system snapshot (kept private to allow cheap refreshes).
    sys: RwLock<System>,
}

impl ProcessResolver {
    pub fn new() -> Arc<Self> {
        let me = Arc::new(Self {
            table: DashMap::new(),
            sys: RwLock::new(System::new_with_specifics(
                RefreshKind::new()
                    .with_processes(ProcessRefreshKind::new()),
            )),
        });
        me.refresh();
        me
    }

    /// Spawn a background thread that refreshes the table every `interval`.
    pub fn spawn_refresher(self: Arc<Self>, interval: Duration) {
        std::thread::Builder::new()
            .name("packet-eye-procmap".into())
            .spawn(move || loop {
                std::thread::sleep(interval);
                self.refresh();
            })
            .expect("spawn procmap thread");
    }

    pub fn lookup(&self, port: u16, proto: Protocol) -> Option<ProcessInfo> {
        self.table.get(&(port, proto)).map(|e| e.value().clone())
    }

    pub fn refresh(&self) {
        let entries = match snapshot_sockets() {
            Ok(v) => v,
            Err(e) => {
                tracing::debug!("socket table snapshot failed: {e}");
                return;
            }
        };

        // Refresh sysinfo only for the PIDs we actually saw.
        let mut sys = self.sys.write();
        sys.refresh_processes_specifics(
            sysinfo::ProcessesToUpdate::All,
            true,
            ProcessRefreshKind::new(),
        );

        // Rebuild table.
        self.table.clear();
        for (port, proto, pid) in entries {
            let name = sys
                .process(Pid::from_u32(pid))
                .map(|p| p.name().to_string_lossy().to_string())
                .unwrap_or_else(|| format!("pid-{pid}"));
            self.table.insert(
                (port, proto),
                ProcessInfo { pid, name },
            );
        }
    }
}

#[cfg(windows)]
fn snapshot_sockets() -> std::io::Result<Vec<(u16, Protocol, u32)>> {
    use std::mem::size_of;
    use std::ptr::null_mut;
    use windows::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCPTABLE_OWNER_PID,
        MIB_UDPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
    };
    use windows::Win32::Networking::WinSock::AF_INET;

    let mut out = Vec::new();

    // ---- TCP (IPv4) ----
    let mut size: u32 = 0;
    unsafe {
        GetExtendedTcpTable(
            None,
            &mut size,
            false,
            AF_INET.0 as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        );
    }
    let mut buf = vec![0u8; size as usize];
    let rc = unsafe {
        GetExtendedTcpTable(
            Some(buf.as_mut_ptr() as *mut _),
            &mut size,
            false,
            AF_INET.0 as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    };
    if rc == 0 {
        let table = unsafe { &*(buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID) };
        let count = table.dwNumEntries as usize;
        // The table struct has a 1-element array; the rest is laid out after it.
        let entries = unsafe {
            std::slice::from_raw_parts(table.table.as_ptr(), count)
        };
        for e in entries {
            // Local port is stored in the first 16 bits, network byte order.
            let port = u16::from_be_bytes([
                (e.dwLocalPort & 0xff) as u8,
                ((e.dwLocalPort >> 8) & 0xff) as u8,
            ]);
            out.push((port, Protocol::Tcp, e.dwOwningPid));
        }
    } else {
        tracing::debug!("GetExtendedTcpTable rc={rc}");
        let _ = null_mut::<()>(); // silence unused warning
    }

    // ---- UDP (IPv4) ----
    let mut size: u32 = 0;
    unsafe {
        GetExtendedUdpTable(
            None,
            &mut size,
            false,
            AF_INET.0 as u32,
            UDP_TABLE_OWNER_PID,
            0,
        );
    }
    let mut buf = vec![0u8; size as usize];
    let rc = unsafe {
        GetExtendedUdpTable(
            Some(buf.as_mut_ptr() as *mut _),
            &mut size,
            false,
            AF_INET.0 as u32,
            UDP_TABLE_OWNER_PID,
            0,
        )
    };
    if rc == 0 {
        let table = unsafe { &*(buf.as_ptr() as *const MIB_UDPTABLE_OWNER_PID) };
        let count = table.dwNumEntries as usize;
        let entries = unsafe {
            std::slice::from_raw_parts(table.table.as_ptr(), count)
        };
        for e in entries {
            let port = u16::from_be_bytes([
                (e.dwLocalPort & 0xff) as u8,
                ((e.dwLocalPort >> 8) & 0xff) as u8,
            ]);
            out.push((port, Protocol::Udp, e.dwOwningPid));
        }
    }

    let _ = size_of::<MIB_TCPTABLE_OWNER_PID>(); // keep types in scope on cfg
    Ok(out)
}

#[cfg(not(windows))]
fn snapshot_sockets() -> std::io::Result<Vec<(u16, Protocol, u32)>> {
    Ok(Vec::new())
}
