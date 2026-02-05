# Guardian Portal

A local configuration interface for an Orange Pi Zero 2W acting as a VPN-protected WiFi access point. Users connect to the AP, a captive portal opens the web UI, and they can manage VPN settings, WiFi, and system status from their phone or laptop.

## What It Does

Guardian turns a small Orange Pi into a portable VPN router. Connect any device to its WiFi, and all traffic is routed through a WireGuard VPN tunnel. A built-in kill switch ensures no traffic leaks if the VPN goes down.

### Features

**WireGuard VPN**
- Live status: connected/disconnected, public IP, handshake age, transfer stats
- Auto-refresh every 30 seconds
- Config editor: server public key, endpoint, DNS
- Device key viewer + key regeneration

**WiFi Management**
- Access Point: SSID, channel, connected client list (MAC + signal)
- AP settings: change SSID and password
- Internet Uplink: connected network, signal strength, IP address
- Network scanner: find and connect to nearby networks

**System**
- Live stats: uptime, CPU temp, memory, disk, load average
- Log viewer: guardian-portal, wireguard, hostapd, dnsmasq
- Password change
- VPN toggle (danger zone, with kill switch warning)
- Power controls: reboot, shutdown with confirmation

**Security**
- Password auth with session cookies (httponly, samesite)
- Rate limiting: 5 login attempts per 5 minutes per IP
- All mutations require authentication
- Input validation via pydantic models
- Atomic config file writes
- No shell injection (subprocess with argument lists only)
- VPN kill switch: iptables FORWARD DROP by default

**UI**
- Pico CSS v2 with custom dark/light theme toggle (preference saved)
- Blue/orange colorblind-safe palette (no red/green)
- SVG shield logo, tab icons, help tooltips
- Loading spinners, toast notifications
- Responsive mobile-first layout
- Captive portal auto-opens on device connect

## Hardware

- Orange Pi Zero 2W (Allwinner H618, aarch64)
- Armbian v25.11 rolling
- USB WiFi adapter (TP-Link AC600, RTL8811AU) for AP
- Onboard WiFi for internet uplink
- WireGuard VPN tunnel

## Network Topology

```
Internet <-> [wlan0 uplink] <-> WireGuard wg0 <-> [USB WiFi AP] <-> Client devices
                                                        |
                                              nginx:80 -> FastAPI:8080
```

Kill switch: `FORWARD` policy is `DROP`. Only wg0 forwarding is allowed via PostUp rules. When the VPN is down, clients have no internet access — preventing data leaks.

## Tech Stack

- **Backend**: Python 3, FastAPI, uvicorn
- **Frontend**: Single HTML file, Pico CSS v2 (CDN), vanilla JS
- **Reverse proxy**: nginx (port 80 -> 8080)
- **DNS/DHCP**: dnsmasq
- **VPN**: WireGuard (wg-quick)
- **Captive portal**: dnsmasq DNS redirects + nginx 302 responses

## Quick Start

```bash
# Mount from Pi via SSHFS
sshfs wil@david:/opt/guardian-portal ~/guardian -o reconnect

# Restart after code changes
ssh root@david 'systemctl restart guardian-portal'

# Check status
ssh root@david 'systemctl status guardian-portal'

# Health check
curl -s http://david:8080/api/health
```

## Testing

```bash
python3 tests/test_api.py                # 15 API tests
python3 tests/test_api.py --rate-limit   # rate limit test (restart service after)
```

## Project Structure

```
app.py                  # FastAPI backend
static/index.html       # Single-page frontend
tests/test_api.py       # API test suite
config.json             # Password hash + settings (delete to reset)
guardian-portal.service  # systemd unit
```

## License

Private project.
