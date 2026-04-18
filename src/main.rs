use comfy_table::Table;
use comfy_table::modifiers::UTF8_ROUND_CORNERS;
use std::collections::HashMap;
use std::fs;
use std::io;
use std::thread;
use std::time::Duration;

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

        println!(
            "\nRefreshing every {} seconds... Press Ctrl+C to stop.",
            REFRESH_INTERVAL
        );
        thread::sleep(Duration::from_secs(REFRESH_INTERVAL));
    }
}
