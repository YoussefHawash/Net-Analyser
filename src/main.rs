use comfy_table::Table;
use comfy_table::modifiers::UTF8_ROUND_CORNERS;
use std::collections::HashMap;
use std::fs;
use std::io::{self, Write};
use std::thread;
use std::time::Duration;

use crossterm::{
    cursor::MoveTo,
    execute,
    style::{Color, Print, ResetColor, SetBackgroundColor, SetForegroundColor},
    terminal::{Clear, ClearType, size},
};

fn draw_bottom_status(line: &str) -> io::Result<()> {
    let (cols, rows) = size()?;
    let bottom_row = rows.saturating_sub(1);

    // Trim if too long for terminal width
    let mut text = line.to_string();
    if text.len() > cols as usize {
        text.truncate(cols as usize);
    }

    let stdout = io::stdout();
    let mut out = stdout.lock();

    execute!(
        out,
        MoveTo(0, bottom_row),
        Clear(ClearType::CurrentLine),
        SetBackgroundColor(Color::White),
        SetForegroundColor(Color::Black),
        Print(format!("{:<width$}", text, width = cols as usize)),
        ResetColor
    )?;

    out.flush()?;
    Ok(())
}
const REFRESH_INTERVAL: u64 = 1; // seconds
const EXPOSED_FILES: [(&str, &str); 2] = [("/proc/net/tcp", "tcp"), ("/proc/net/udp", "udp")];
struct ConnectionInfo {
    pid: u32,
    process_name: String,
    proto: String,
    local_addr: String,
    local_port: u16,
    remote_addr: String,
    remote_port: u16,
    state: String,
}
struct InterfaceStats {
    interface: String,
    rx_bytes: u64,
    rx_packets: u64,
    tx_bytes: u64,
    tx_packets: u64,
}
struct Socket {
    proto: String,
    local_addr: String,
    local_port: u16,
    remote_addr: String,
    remote_port: u16,
    inode: String,
    state: String,
}
//Helper Functions
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
fn read_process_name(pid: u32) -> String {
    let path = format!("/proc/{}/comm", pid);
    fs::read_to_string(path)
        .unwrap_or_else(|_| "unknown".to_string())
        .trim()
        .to_string()
}

fn read_net_files(file: &str, protocol: &str) -> io::Result<Vec<Socket>> {
    let content = fs::read_to_string(file)?;
    let mut sockets: Vec<Socket> = Vec::new();
    for line in content.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 10 {
            continue;
        }

        let (local_addr, local_port) = parse_addr_port(cols[1]);
        let (remote_addr, remote_port) = parse_addr_port(cols[2]);

        let state = if protocol == "tcp" {
            tcp_state(cols[3])
        } else {
            "N/A".to_string()
        };
        let inode = cols[9].to_string();

        sockets.push(Socket {
            proto: protocol.to_string(),
            local_addr,
            local_port,
            remote_addr,
            remote_port,
            inode,
            state,
        });
    }

    Ok(sockets)
}

fn get_sockets() -> io::Result<HashMap<String, Socket>> {
    let mut map = HashMap::new();
    for (file, protocol) in EXPOSED_FILES {
        if let Ok(scokets) = read_net_files(&file, &protocol) {
            for s in scokets {
                map.insert(s.inode.clone(), s);
            }
        }
    }
    Ok(map)
}

fn list_connections() -> io::Result<Vec<ConnectionInfo>> {
    let sockets = get_sockets()?;
    let mut connections = Vec::new();
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
                                connections.push(ConnectionInfo {
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
    Ok(connections)
}

fn clear_screen() {
    print!("\x1B[2J\x1B[1;1H");
}
fn list_packets() -> io::Result<Vec<InterfaceStats>> {
    let content = fs::read_to_string("/proc/net/dev")?;
    let mut stats = Vec::new();

    for line in content.lines().skip(2) {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        // Example format:
        // eth0: 12345 67 0 0 0 0 0 0 54321 76 0 0 0 0 0 0
        let mut parts = line.split(':');
        let iface = match parts.next() {
            Some(v) => v.trim().to_string(),
            None => continue,
        };

        let data = match parts.next() {
            Some(v) => v,
            None => continue,
        };

        let cols: Vec<&str> = data.split_whitespace().collect();

        // /proc/net/dev gives RX fields first, then TX fields.
        // We only need:
        // RX: bytes[0], packets[1]
        // TX: bytes[8], packets[9]
        if cols.len() < 10 {
            continue;
        }

        let rx_bytes = cols[0].parse::<u64>().unwrap_or(0);
        let rx_packets = cols[1].parse::<u64>().unwrap_or(0);
        let tx_bytes = cols[8].parse::<u64>().unwrap_or(0);
        let tx_packets = cols[9].parse::<u64>().unwrap_or(0);

        stats.push(InterfaceStats {
            interface: iface,
            rx_bytes,
            rx_packets,
            tx_bytes,
            tx_packets,
        });
    }

    Ok(stats)
}
fn main() -> io::Result<()> {
    loop {
        let mut table = Table::new();
        table
            .set_header(vec!["PID", "Process", "Protocol", "Src", "Dst", "State"])
            .apply_modifier(UTF8_ROUND_CORNERS);
        clear_screen();
        println!("=== Process Network Connections ===");
        match list_connections() {
            Ok(conns) => {
                for c in conns.iter().take(30) {
                    table.add_row(vec![
                        c.pid.to_string(),
                        c.process_name.clone(),
                        c.proto.clone(),
                        format!("{}:{}", c.local_addr, c.local_port),
                        format!("{}:{}", c.remote_addr, c.remote_port),
                        c.state.clone(),
                    ]);
                }
                println!("{}", table);
            }
            Err(e) => {
                eprintln!("Failed to read process connections: {}", e);
            }
        }
        match list_packets() {
            Ok(stats) => {
                for s in stats.iter() {
                    draw_bottom_status(&format!(
                        "{} - RX: {} bytes ({} packets), TX: {} bytes ({} packets)",
                        s.interface, s.rx_bytes, s.rx_packets, s.tx_bytes, s.tx_packets
                    ))?;
                }
            }
            Err(e) => {
                eprintln!("Failed to read network stats: {}", e);
            }
        }

        thread::sleep(Duration::from_secs(REFRESH_INTERVAL));
    }
}
