# Linux NFQueue Firewall

A userspace IPv4 firewall for Linux. The kernel sends packets to the daemon through a
Netfilter queue (NFQUEUE); the daemon parses them, applies per-source rate limiting,
tracks connections, matches them against an ordered rule set, and returns an
`ACCEPT` or `DROP` verdict.

It supports text or JSON logging, live statistics, an interactive shell, and rules
loaded from a file or the built-in defaults.

## Requirements

- Linux with iptables and the `nfnetlink_queue` kernel module
- Root privileges
- `g++` with C++17 and `make`
- `libnetfilter-queue-dev` and `libmnl-dev`

## Build

```bash
make deps    # install Netfilter queue development packages
make
```

The binary is created at `./firewall`. Use `make debug` for an AddressSanitizer
build.

## Configure traffic redirection

```bash
sudo ./setup.sh [queue-number] [interface]
```

This installs the required dependencies, creates an iptables chain named `FW_CHAIN`,
and sends all inbound and outbound IPv4 traffic to the selected NFQUEUE number.

Defaults: queue `0`, interface `eth0`. The interface argument is informational only;
the rules apply to all interfaces.

Remove the rules with:

```bash
sudo iptables -D INPUT -j FW_CHAIN
sudo iptables -D OUTPUT -j FW_CHAIN
sudo iptables -F FW_CHAIN
sudo iptables -X FW_CHAIN
```

## Run

```bash
sudo ./firewall -q 0 -r config/rules.conf -l /var/log/firewall.log
```

Use the same queue number as `setup.sh`.

| Option | Description |
|---|---|
| `-q, --queue <num>` | NFQUEUE number (default `0`) |
| `-r, --rules <file>` | Load rules from a file instead of the built-in set |
| `-l, --log <file>` | Log file path (default `/var/log/firewall.log`) |
| `-d, --default <action>` | Fallback action: `accept` or `drop` (default `drop`) |
| `-s, --stateful` | Enable connection tracking (on by default) |
| `-v, --verbose` | Print every verdict to the console |
| `-j, --json` | Write packet logs as JSON |
| `-h, --help` | Show usage |

## Rules

Rules are plain text, one per line. Blank lines and `#` comments are ignored.

```
<name> <action> [proto <tcp|udp|icmp|any>] [src <ip[/mask]>] [dst <ip[/mask]>]
                [sport <port>] [dport <port>] [log] [in|out]
```

- **Actions:** `accept`, `drop`, `reject`, `log`
- **Protocols:** `tcp`, `udp`, `icmp`, `any`
- **Ports:** `0` or omitted means any
- **Addresses:** IPv4 addresses or CIDR ranges, e.g. `10.0.0.0/8`
- **`log`:** log matching packets

Rules are evaluated top to bottom and the first match wins, so place specific block
rules before broad allow rules.

Example:

```text
allow_loopback   accept  proto any  src 127.0.0.0/8  dst 127.0.0.0/8
allow_ssh        accept  proto tcp  dport 22  log
block_telnet     drop    proto tcp  dport 23  log
block_ftp        drop    proto tcp  dport 21  log
default_drop     drop    proto any
```

## Interactive shell

While the daemon is running, use the `fw>` prompt:

| Command | Description |
|---|---|
| `stats` | Show firewall statistics |
| `rules` | List active rules |
| `add` | Add a rule interactively |
| `remove <id>` | Remove a rule by ID |
| `clear` | Remove all rules |
| `block <ip>` | Block a source IP |
| `unblock <ip>` | Unblock a source IP |
| `load <file>` | Load additional rules from a file |
| `quit` | Stop the firewall |

Press `Ctrl+C` to stop the daemon.
