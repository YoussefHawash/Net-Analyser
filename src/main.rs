use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::Path;

#[derive(Debug, Clone)]
struct SocketEntry {
    proto: String,
    local_addr: String,
    local_port: u16,
    remote_addr: String,
    remote_port: u16,
    inode: String,
    state: String,
}

#[derive(Debug, Clone)]
struct ProcessConnection {
    pid: u32,
    process_name: String,
    proto: String,
    local_addr: String,
    local_port: u16,
    remote_addr: String,
    remote_port: u16,
    state: String,
}

#[derive(Debug, Clone)]
struct InterfaceStats {
    interface: String,
    rx_bytes: u64,
    rx_packets: u64,
    tx_bytes: u64,
    tx_packets: u64,
}

fn hex_to_ipv4(hex: &str) -> String {
    if hex.len() != 8 {
        return "Invalid".to_string();
    }

    let bytes = (0..4)
        .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap_or(0))
        .collect::<Vec<_>>();

    format!("{}.{}.{}.{}", bytes[3], bytes[2], bytes[1], bytes[0])
}

fn parse_addr_port(s: &str) -> (String, u16) {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 2 {
        return ("Invalid".to_string(), 0);
    }

    let ip = hex_to_ipv4(parts[0]);
    let port = u16::from_str_radix(parts[1], 16).unwrap_or(0);

    (ip, port)
}

fn tcp_state(hex: &str) -> String {
    match hex {
        "01" => "ESTABLISHED",
        "02" => "SYN_SENT",
        "03" => "SYN_RECV",
        "04" => "FIN_WAIT1",
        "05" => "FIN_WAIT2",
        "06" => "TIME_WAIT",
        "07" => "CLOSE",
        "08" => "CLOSE_WAIT",
        "09" => "LAST_ACK",
        "0A" => "LISTEN",
        "0B" => "CLOSING",
        _ => "UNKNOWN",
    }
    .to_string()
}

fn parse_proc_net_file(path: &str, proto: &str) -> io::Result<Vec<SocketEntry>> {
    let content = fs::read_to_string(path)?;
    let mut entries = Vec::new();

    for line in content.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 10 {
            continue;
        }

        let (local_addr, local_port) = parse_addr_port(cols[1]);
        let (remote_addr, remote_port) = parse_addr_port(cols[2]);
        let state = if proto == "tcp" {
            tcp_state(cols[3])
        } else {
            "N/A".to_string()
        };
        let inode = cols[9].to_string();

        entries.push(SocketEntry {
            proto: proto.to_string(),
            local_addr,
            local_port,
            remote_addr,
            remote_port,
            inode,
            state,
        });
    }

    Ok(entries)
}

fn get_all_sockets() -> io::Result<HashMap<String, SocketEntry>> {
    let mut map = HashMap::new();

    for (path, proto) in [
        ("/proc/net/tcp", "tcp"),
        ("/proc/net/udp", "udp"),
    ] {
        if let Ok(entries) = parse_proc_net_file(path, proto) {
            for e in entries {
                map.insert(e.inode.clone(), e);
            }
        }
    }

    Ok(map)
}

fn read_process_name(pid: u32) -> String {
    let path = format!("/proc/{}/comm", pid);
    fs::read_to_string(path)
        .unwrap_or_else(|_| "unknown".to_string())
        .trim()
        .to_string()
}

fn list_process_networks() -> io::Result<Vec<ProcessConnection>> {
    let sockets = get_all_sockets()?;
    let mut results = Vec::new();

    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        let file_name = entry.file_name();
        let pid_str = file_name.to_string_lossy();

        if let Ok(pid) = pid_str.parse::<u32>() {
            let fd_path = format!("/proc/{}/fd", pid);
            let process_name = read_process_name(pid);

            if let Ok(fds) = fs::read_dir(fd_path) {
                for fd in fds.flatten() {
                    if let Ok(target) = fs::read_link(fd.path()) {
                        let target_str = target.to_string_lossy();

                        // Example: socket:[12345]
                        if target_str.starts_with("socket:[") && target_str.ends_with(']') {
                            let inode = target_str
                                .trim_start_matches("socket:[")
                                .trim_end_matches(']')
                                .to_string();

                            if let Some(sock) = sockets.get(&inode) {
                                results.push(ProcessConnection {
                                    pid,
                                    process_name: process_name.clone(),
                                    proto: sock.proto.clone(),
                                    local_addr: sock.local_addr.clone(),
                                    local_port: sock.local_port,
                                    remote_addr: sock.remote_addr.clone(),
                                    remote_port: sock.remote_port,
                                    state: sock.state.clone(),
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(results)
}

fn get_interface_stats() -> io::Result<Vec<InterfaceStats>> {
    let content = fs::read_to_string("/proc/net/dev")?;
    let mut stats = Vec::new();

    for line in content.lines().skip(2) {
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() != 2 {
            continue;
        }

        let iface = parts[0].trim().to_string();
        let values: Vec<&str> = parts[1].split_whitespace().collect();

        if values.len() < 16 {
            continue;
        }

        stats.push(InterfaceStats {
            interface: iface,
            rx_bytes: values[0].parse().unwrap_or(0),
            rx_packets: values[1].parse().unwrap_or(0),
            tx_bytes: values[8].parse().unwrap_or(0),
            tx_packets: values[9].parse().unwrap_or(0),
        });
    }

    Ok(stats)
}

fn main() -> io::Result<()> {
    println!("=== Process Network Connections ===");
    let conns = list_process_networks()?;
    for c in conns {
        println!(
            "PID: {:<6} Proc: {:<20} Proto: {:<4} {}:{} -> {}:{} [{}]",
            c.pid,
            c.process_name,
            c.proto,
            c.local_addr,
            c.local_port,
            c.remote_addr,
            c.remote_port,
            c.state
        );
    }

    println!("\n=== Interface Statistics ===");
    let ifaces = get_interface_stats()?;
    for s in ifaces {
        println!(
            "{} | RX: {} bytes, {} pkts | TX: {} bytes, {} pkts",
            s.interface, s.rx_bytes, s.rx_packets, s.tx_bytes, s.tx_packets
        );
    }

    Ok(())
}