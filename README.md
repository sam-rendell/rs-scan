# rs-scan

A high-speed, stateless network scanner that values your time more than your network's stability. 

## A Brief History of Shouting into the Void
Some of us are old enough to remember the sublime simplicity of Julian Assange’s `strobe.c` and the raw, unpolished utility of `udp_scan.c` from the SATAN suite. It was a simpler time, when the internet was small enough to fit in a single `/16` and "security" was mostly a matter of not leaving your telnet port open. We grew up on the late-night hum of a CRT and the thrill of a SYN-ACK from a machine three time zones away. These tools weren't just software; they were invitations to a global conversation that most people didn't even know was happening.

Fast forward a few decades, and the conversation has become a cacophony. Robert Graham’s `masscan` and the ZMap project showed us how to shout at the entire internet in under an hour, turning stateless scanning into a fine art. `rs-scan` isn't an attempt to reinvent that particular wheel—mostly because Robert already did a rather smashing job of it. Instead, it’s a pragmatic nod to that history, built for those of us who want nmap-style familiarity paired with a signature system that doesn't require a tiresome, over-engineered language. It’s about getting the banner, handling the negotiation, and moving on without the architectural bloat of a thousand threads.

## Architecture
`rs-scan` follows the classic stateless architecture: minimal threads, no kernel-level state tracking for SYN packets, and a healthy disregard for your firewall's feelings. 

### Optimisations
While heavily inspired by the works of Robert Graham, we've made some minor architectural refinements over the current state of things:
* **The "X and Y" Stack**: Proper platform-specific sending and receiving implementations. We don't just shove everything through a generic wrapper. On Linux, we utilize `afpacket` (AF_PACKET) with ring buffers for zero-copy efficiency. On Darwin, we fall back to `pcap` and `BPF`. It's the right tool for the right job, even if the job is mostly shouting into the void.
* **Target Shuffling**: We use a **Feistel Network** (Format-Preserving Encryption) for shuffling the search space. No Linear Congruential Generators here; we prefer the strong avalanche properties of a proper Feistel cipher with Murmur3 as the round function.
* **Stateless(ish) Cookies**: Sequence numbers are generated via FNV-1a based **SYN Cookies**. While we maintain a connection table for complex banner grabs, the sequence numbers themselves are statelessly verifiable.
* **Minimal Threading**: Senders and receivers are decoupled via lockless ring buffers, ensuring we aren't wasting cycles on mutex contention while the internet is waiting to be indexed.
* **Tuning**: Performance needs to be actively tuned. If it's slow, it's likely your configuration or your kernel's refusal to keep up.

## Features
We've taken a pragmatic approach to a handful of features that actually matter:
* **Nmap-style Syntax**: `-sS`, `-sU`, `-p`, `-iL`. You know the drill. No need to learn a new language just to find an open port.
* **Protocol Signatures**: A wide array of protocol signatures using a simple YAML-based approach to define them. We avoid the "everything needs its own language" trap—it's tiresome and unnecessary.

### Multi-modal Negotiation
Telnet is the perfect example of our approach. We don't just grab a banner; we handle the protocol negotiation (IAC) before settling into the capture. It's flexible without being a burden.

```yaml
name: telnet
protocol: tcp
ports: [23, 2323]
recv_bytes: 512
negotiate:
  rules:
    - when: ["0xff", "0xfb", "_"]
      reply: ["0xff", "0xfe", "$1"]
    - when: ["0xff", "0xfd", "_"]
      reply: ["0xff", "0xfc", "$1"]
  max_rounds: 10
  max_bytes: 2048
  escape_on: ["0x00"]
```

## Usage

### Basic SYN Scan
```bash
./rs_scan -t 192.168.1.0/24 -p 80,443,22
```

### Banner Grabbing
```bash
./rs_scan -t 10.0.0.0/8 -p 80,23,21 --banners
```

### UDP Scanning
```bash
./rs_scan -sU -t 1.1.1.1 -p 53,123,161
```

### The Full Monty
```bash
./rs_scan -i eth0 -t 0.0.0.0/0 -p 80 --pps 100000 --banners -o internet.jsonl
```

### Notable Flags
* `-i <iface>`: Interface to use (e.g., eth0, wlan0).
* `-pps <rate>`: Target packets per second (default: 1000). Crank it up until your router starts smoking.
* `-iL <file>`: Load targets from a file. One per line, no fluff.
* `-o <file>`: Output results in JSONL format.
* `-oG <file>`: Grepable output for the traditionalists.
* `-exclude <ips>`: Skip the bits you aren't supposed to touch.
* `-c <config.yaml>`: Use a config file because typing is hard.
* `--no-tui`: Just give me the text, hold the fancy terminal interface.
* `--webhook <url>`: Ship your findings off to a webhook for someone else to deal with.

## Build
```bash
make build
```

Or just:
```bash
go build -o rs_scan ./cmd/rs_scan
```

## License
MIT. Use it, don't sue us.
