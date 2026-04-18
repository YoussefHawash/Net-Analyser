Rust Network Monitor (Process + Interface Stats)

A lightweight Linux CLI tool written in Rust that:

- Maps network connections to processes
- Displays TCP/UDP connections in a table
- Shows live RX/TX stats per interface in a bottom status bar

No external system libraries — everything is read directly from /proc.

---

Features

- Process-level network inspection
- TCP state decoding (ESTABLISHED, LISTEN, etc.)
- Interface traffic stats (bytes + packets)
- Live refresh (default: 1s)
- Clean terminal UI using:
  - comfy_table
  - crossterm

---

Data Sources

- /proc/net/tcp → TCP sockets
- /proc/net/udp → UDP sockets
- /proc/[pid]/fd → maps sockets to processes
- /proc/net/dev → interface stats

---

How to Run

cargo run

Linux only (relies on /proc filesystem)

---

Output

Main Table

Shows active connections:

- PID
- Process name
- Protocol (TCP/UDP)
- Source IP:Port
- Destination IP:Port
- TCP State

Bottom Status Bar

Example:
eth0 - RX: 123456 bytes (120 packets), TX: 654321 bytes (98 packets)

---

How It Works

1. Read /proc/net/tcp and /proc/net/udp
   - Parse each line into a socket struct
   - Convert hex IP/port to readable format
   - Store sockets indexed by inode

2. Scan /proc/[pid]/fd for every process
   - Each file descriptor may point to socket:[inode]
   - Extract inode and match it with the socket table
   - Build a list of connections with:
     - PID
     - Process name
     - Network details

3. Read /proc/net/dev
   - Extract RX/TX bytes and packet counts per interface

4. Render output
   - Connections → table (comfy_table)
   - Interface stats → bottom status bar (crossterm)

5. Loop every second
   - Clear screen
   - Refresh data
   - Re-render UI

---

Notes

- Requires permission to read /proc/[pid]/fd (run with sudo if needed)
- Only IPv4 is supported
- UDP has no connection state (shown as N/A)
- Displays first 30 connections for readability

---

Dependencies

- comfy_table
- crossterm

---

Possible Improvements

- Real packet sniffing (pcap / raw sockets)
- IPv6 support
- Filtering/ Sorting / paging
- Better UI (tabs, scrolling)
