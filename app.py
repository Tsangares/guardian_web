#!/usr/bin/env python3
"""Guardian Portal - Local config interface for Orange Pi Zero 2W VPN AP"""

import asyncio
import hashlib
import hmac
import json
import os
import re
import secrets
import subprocess
import tempfile
import shutil
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Depends, Request, Response
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field, validator

# Constants
CONFIG_FILE = Path("/opt/guardian-portal/config.json")
WG_CONFIG = Path("/etc/wireguard/wg0.conf")
HOSTAPD_CONFIG = Path("/etc/hostapd/hostapd.conf")
SESSION_TIMEOUT = timedelta(hours=24)

# In-memory session store
sessions: dict[str, datetime] = {}

# Rate limiting for login attempts (IP -> list of attempt timestamps)
login_attempts: dict[str, list[datetime]] = {}
RATE_LIMIT_WINDOW = timedelta(minutes=5)
RATE_LIMIT_MAX_ATTEMPTS = 5

app = FastAPI(title="Guardian Portal", docs_url=None, redoc_url=None)


def check_rate_limit(ip: str) -> bool:
    """Check if IP has exceeded rate limit. Returns True if allowed."""
    now = datetime.now()
    cutoff = now - RATE_LIMIT_WINDOW

    # Clean old attempts
    if ip in login_attempts:
        login_attempts[ip] = [t for t in login_attempts[ip] if t > cutoff]
    else:
        login_attempts[ip] = []

    # Check limit
    if len(login_attempts[ip]) >= RATE_LIMIT_MAX_ATTEMPTS:
        return False

    # Record attempt
    login_attempts[ip].append(now)
    return True


# --- Config Management ---

def load_config() -> dict:
    """Load portal config from JSON file."""
    if CONFIG_FILE.exists():
        return json.loads(CONFIG_FILE.read_text())
    return {"password_hash": None}


def save_config(config: dict) -> None:
    """Save portal config atomically."""
    CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = CONFIG_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(config, indent=2))
    tmp.rename(CONFIG_FILE)


def hash_password(password: str) -> str:
    """Hash password with SHA-256 and salt."""
    salt = secrets.token_hex(16)
    h = hashlib.sha256((salt + password).encode()).hexdigest()
    return f"{salt}:{h}"


def verify_password(password: str, stored: str) -> bool:
    """Verify password against stored hash."""
    if not stored or ":" not in stored:
        return False
    salt, expected = stored.split(":", 1)
    h = hashlib.sha256((salt + password).encode()).hexdigest()
    return hmac.compare_digest(h, expected)


# --- Authentication ---

def get_session_token(request: Request) -> Optional[str]:
    """Extract session token from cookie or header."""
    token = request.cookies.get("session")
    if not token:
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            token = auth[7:]
    return token


def require_auth(request: Request) -> str:
    """Dependency that requires valid authentication."""
    token = get_session_token(request)
    if not token or token not in sessions:
        raise HTTPException(status_code=401, detail="Not authenticated")
    if sessions[token] < datetime.now():
        del sessions[token]
        raise HTTPException(status_code=401, detail="Session expired")
    return token


def is_authenticated(request: Request) -> bool:
    """Check if request is authenticated without raising."""
    try:
        require_auth(request)
        return True
    except HTTPException:
        return False


def cleanup_expired_sessions():
    """Remove expired sessions from memory."""
    now = datetime.now()
    expired = [token for token, expiry in sessions.items() if expiry < now]
    for token in expired:
        del sessions[token]


# --- System Command Execution ---

def run_cmd(args: list[str], timeout: int = 30, check: bool = False) -> subprocess.CompletedProcess:
    """Execute system command safely with logging."""
    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=check
        )
        return result
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail=f"Command timed out: {args[0]}")
    except subprocess.CalledProcessError as e:
        raise HTTPException(status_code=500, detail=f"Command failed: {e.stderr}")


# --- API Models ---

class LoginRequest(BaseModel):
    password: str


class SetPasswordRequest(BaseModel):
    password: str = Field(..., min_length=8)


class VPNConfigUpdate(BaseModel):
    endpoint: Optional[str] = None
    dns: Optional[str] = None
    peer_public_key: Optional[str] = None

    @validator("endpoint")
    def validate_endpoint(cls, v):
        if v is not None:
            # Format: host:port
            if not re.match(r"^[\w\.\-]+:\d+$", v):
                raise ValueError("Invalid endpoint format (expected host:port)")
        return v

    @validator("peer_public_key")
    def validate_peer_key(cls, v):
        if v is not None:
            v = v.strip()
            # WireGuard public keys are 44 chars base64
            if not re.match(r"^[A-Za-z0-9+/]{42,44}=?={0,2}$", v):
                raise ValueError("Invalid WireGuard public key")
        return v

    @validator("dns")
    def validate_dns(cls, v):
        if v is not None:
            # Validate IP addresses
            for ip in v.split(","):
                ip = ip.strip()
                if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
                    raise ValueError(f"Invalid DNS IP: {ip}")
        return v


class APConfigUpdate(BaseModel):
    ssid: Optional[str] = Field(None, min_length=1, max_length=32)
    password: Optional[str] = Field(None, min_length=8, max_length=63)

    @validator("ssid")
    def validate_ssid(cls, v):
        if v is not None and not re.match(r"^[\w\s\-]+$", v):
            raise ValueError("SSID contains invalid characters")
        return v


# --- API Endpoints ---

@app.get("/api/health")
async def health_check():
    """Health check endpoint for monitoring."""
    cleanup_expired_sessions()  # Cleanup on health check
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "active_sessions": len(sessions)
    }


@app.get("/api/auth/status")
async def auth_status(request: Request):
    """Check if user is authenticated and if password is set."""
    config = load_config()
    return {
        "authenticated": is_authenticated(request),
        "password_set": config.get("password_hash") is not None
    }


@app.post("/api/auth/login")
async def login(req: LoginRequest, request: Request, response: Response):
    """Authenticate with password."""
    # Rate limiting
    client_ip = request.client.host if request.client else "unknown"
    if not check_rate_limit(client_ip):
        raise HTTPException(status_code=429, detail="Too many login attempts. Try again later.")

    config = load_config()
    stored = config.get("password_hash")

    if not stored:
        raise HTTPException(status_code=400, detail="No password set. Set one first.")

    if not verify_password(req.password, stored):
        raise HTTPException(status_code=401, detail="Invalid password")

    token = secrets.token_urlsafe(32)
    sessions[token] = datetime.now() + SESSION_TIMEOUT
    response.set_cookie("session", token, httponly=True, samesite="strict", max_age=86400)
    return {"success": True}


@app.post("/api/auth/logout")
async def logout(request: Request, response: Response):
    """Log out and clear session."""
    token = get_session_token(request)
    if token and token in sessions:
        del sessions[token]
    response.delete_cookie("session")
    return {"success": True}


@app.post("/api/auth/set-password")
async def set_password(req: SetPasswordRequest, request: Request, response: Response):
    """Set or change the portal password."""
    config = load_config()

    # If password already set, require authentication
    if config.get("password_hash") and not is_authenticated(request):
        raise HTTPException(status_code=401, detail="Must be logged in to change password")

    config["password_hash"] = hash_password(req.password)
    save_config(config)

    # Auto-login after setting password
    token = secrets.token_urlsafe(32)
    sessions[token] = datetime.now() + SESSION_TIMEOUT
    response.set_cookie("session", token, httponly=True, samesite="strict", max_age=86400)
    return {"success": True}


@app.get("/api/status")
async def system_status():
    """Get system overview: uptime, CPU temp, memory, disk."""
    # Uptime
    uptime_raw = run_cmd(["uptime", "-p"]).stdout.strip()

    # CPU temperature
    try:
        temp_raw = Path("/sys/class/thermal/thermal_zone0/temp").read_text().strip()
        cpu_temp = round(int(temp_raw) / 1000, 1)
    except:
        cpu_temp = None

    # Memory
    mem = run_cmd(["free", "-m"]).stdout
    mem_lines = mem.strip().split("\n")
    if len(mem_lines) >= 2:
        mem_parts = mem_lines[1].split()
        mem_total = int(mem_parts[1])
        mem_used = int(mem_parts[2])
    else:
        mem_total = mem_used = 0

    # Disk
    disk = run_cmd(["df", "-h", "/"]).stdout
    disk_lines = disk.strip().split("\n")
    if len(disk_lines) >= 2:
        disk_parts = disk_lines[1].split()
        disk_total = disk_parts[1]
        disk_used = disk_parts[2]
        disk_percent = disk_parts[4]
    else:
        disk_total = disk_used = disk_percent = "?"

    # Load average
    load = Path("/proc/loadavg").read_text().split()[:3]

    return {
        "uptime": uptime_raw,
        "cpu_temp_c": cpu_temp,
        "memory": {"total_mb": mem_total, "used_mb": mem_used},
        "disk": {"total": disk_total, "used": disk_used, "percent": disk_percent},
        "load_avg": load,
        "timestamp": datetime.now().isoformat()
    }


@app.get("/api/vpn/status")
async def vpn_status():
    """Get WireGuard VPN status."""
    # Check if interface exists
    result = run_cmd(["ip", "link", "show", "wg0"])
    interface_up = result.returncode == 0

    if not interface_up:
        return {
            "active": False,
            "interface": "wg0",
            "endpoint": None,
            "latest_handshake": None,
            "transfer": None,
            "public_ip": None
        }

    # Parse wg show output
    wg_out = run_cmd(["wg", "show", "wg0"]).stdout

    endpoint = None
    handshake = None
    transfer_rx = transfer_tx = None

    for line in wg_out.split("\n"):
        line = line.strip()
        if line.startswith("endpoint:"):
            endpoint = line.split(":", 1)[1].strip()
        elif line.startswith("latest handshake:"):
            handshake = line.split(":", 1)[1].strip()
        elif line.startswith("transfer:"):
            parts = line.split(":", 1)[1].strip()
            if "received" in parts and "sent" in parts:
                # "1.23 MiB received, 4.56 MiB sent"
                match = re.match(r"([\d.]+ \w+) received, ([\d.]+ \w+) sent", parts)
                if match:
                    transfer_rx, transfer_tx = match.groups()

    # Get public IP through VPN
    public_ip = None
    try:
        ip_result = run_cmd(["curl", "-s", "--max-time", "5", "ifconfig.me"], timeout=10)
        if ip_result.returncode == 0:
            public_ip = ip_result.stdout.strip()
    except:
        pass

    return {
        "active": True,
        "interface": "wg0",
        "endpoint": endpoint,
        "latest_handshake": handshake,
        "transfer": {"received": transfer_rx, "sent": transfer_tx} if transfer_rx else None,
        "public_ip": public_ip
    }


@app.post("/api/vpn/toggle")
async def vpn_toggle(request: Request, _=Depends(require_auth)):
    """Toggle VPN tunnel on/off."""
    # Check current state
    result = run_cmd(["ip", "link", "show", "wg0"])
    is_up = result.returncode == 0

    if is_up:
        run_cmd(["wg-quick", "down", "wg0"], check=True)
        return {"action": "down", "success": True}
    else:
        run_cmd(["wg-quick", "up", "wg0"], check=True)
        return {"action": "up", "success": True}


@app.get("/api/vpn/config")
async def vpn_config_get(_=Depends(require_auth)):
    """Get current VPN configuration (safe fields only)."""
    if not WG_CONFIG.exists():
        raise HTTPException(status_code=404, detail="WireGuard config not found")

    content = WG_CONFIG.read_text()

    # Parse safe fields
    endpoint = dns = address = peer_public_key = private_key = None
    for line in content.split("\n"):
        line = line.strip()
        if line.startswith("Endpoint"):
            endpoint = line.split("=", 1)[1].strip()
        elif line.startswith("DNS"):
            dns = line.split("=", 1)[1].strip()
        elif line.startswith("Address"):
            address = line.split("=", 1)[1].strip()
        elif line.startswith("PublicKey"):
            peer_public_key = line.split("=", 1)[1].strip()
        elif line.startswith("PrivateKey"):
            private_key = line.split("=", 1)[1].strip()

    # Derive local public key from private key
    local_public_key = None
    if private_key:
        try:
            result = subprocess.run(
                ["wg", "pubkey"],
                input=private_key,
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                local_public_key = result.stdout.strip()
        except Exception:
            pass

    return {
        "endpoint": endpoint,
        "dns": dns,
        "address": address,
        "peer_public_key": peer_public_key,
        "local_public_key": local_public_key
    }


@app.post("/api/vpn/config")
async def vpn_config_update(update: VPNConfigUpdate, _=Depends(require_auth)):
    """Update VPN configuration."""
    if not WG_CONFIG.exists():
        raise HTTPException(status_code=404, detail="WireGuard config not found")

    content = WG_CONFIG.read_text()
    lines = content.split("\n")
    new_lines = []

    for line in lines:
        stripped = line.strip()
        if update.endpoint and stripped.startswith("Endpoint"):
            new_lines.append(f"Endpoint = {update.endpoint}")
        elif update.dns and stripped.startswith("DNS"):
            new_lines.append(f"DNS = {update.dns}")
        elif update.peer_public_key and stripped.startswith("PublicKey"):
            new_lines.append(f"PublicKey = {update.peer_public_key}")
        else:
            new_lines.append(line)

    # Write atomically with backup
    backup = WG_CONFIG.with_suffix(".conf.bak")
    shutil.copy(WG_CONFIG, backup)

    tmp = WG_CONFIG.with_suffix(".tmp")
    tmp.write_text("\n".join(new_lines))
    tmp.rename(WG_CONFIG)

    return {"success": True, "message": "Config updated. Restart VPN to apply changes."}


@app.post("/api/vpn/regen-keys")
async def vpn_regen_keys(_=Depends(require_auth)):
    """Regenerate WireGuard keypair."""
    # Generate new keypair
    privkey = run_cmd(["wg", "genkey"]).stdout.strip()
    pubkey_result = subprocess.run(
        ["wg", "pubkey"],
        input=privkey,
        capture_output=True,
        text=True
    )
    pubkey = pubkey_result.stdout.strip()

    # Update config file
    if not WG_CONFIG.exists():
        raise HTTPException(status_code=404, detail="WireGuard config not found")

    content = WG_CONFIG.read_text()
    lines = content.split("\n")
    new_lines = []

    for line in lines:
        stripped = line.strip()
        if stripped.startswith("PrivateKey"):
            new_lines.append(f"PrivateKey = {privkey}")
        else:
            new_lines.append(line)

    # Write atomically with backup
    backup = WG_CONFIG.with_suffix(".conf.bak")
    shutil.copy(WG_CONFIG, backup)

    tmp = WG_CONFIG.with_suffix(".tmp")
    tmp.write_text("\n".join(new_lines))
    tmp.rename(WG_CONFIG)

    return {
        "success": True,
        "public_key": pubkey,
        "message": "New keypair generated. Add this public key to your VPN server and restart the tunnel."
    }


@app.get("/api/wifi/ap")
async def wifi_ap_status():
    """Get AP status and connected clients."""
    # Read hostapd config
    ssid = channel = None
    if HOSTAPD_CONFIG.exists():
        content = HOSTAPD_CONFIG.read_text()
        for line in content.split("\n"):
            if line.startswith("ssid="):
                ssid = line.split("=", 1)[1]
            elif line.startswith("channel="):
                channel = line.split("=", 1)[1]

    # Get connected clients
    clients = []
    result = run_cmd(["iw", "dev", "wlx98038eb6c140", "station", "dump"])
    if result.returncode == 0:
        current_client = {}
        for line in result.stdout.split("\n"):
            if line.startswith("Station"):
                if current_client:
                    clients.append(current_client)
                mac = line.split()[1]
                current_client = {"mac": mac}
            elif "signal:" in line:
                current_client["signal"] = line.split(":")[1].strip()
            elif "connected time:" in line:
                current_client["connected_time"] = line.split(":")[1].strip()
        if current_client:
            clients.append(current_client)

    return {
        "ssid": ssid,
        "channel": channel,
        "interface": "wlx98038eb6c140",
        "clients": clients,
        "client_count": len(clients)
    }


@app.post("/api/wifi/ap")
async def wifi_ap_update(update: APConfigUpdate, _=Depends(require_auth)):
    """Update AP SSID/password."""
    if not HOSTAPD_CONFIG.exists():
        raise HTTPException(status_code=404, detail="hostapd config not found")

    content = HOSTAPD_CONFIG.read_text()
    lines = content.split("\n")
    new_lines = []

    for line in lines:
        if update.ssid and line.startswith("ssid="):
            new_lines.append(f"ssid={update.ssid}")
        elif update.password and line.startswith("wpa_passphrase="):
            new_lines.append(f"wpa_passphrase={update.password}")
        else:
            new_lines.append(line)

    # Write atomically with backup
    backup = HOSTAPD_CONFIG.with_suffix(".conf.bak")
    shutil.copy(HOSTAPD_CONFIG, backup)

    tmp = HOSTAPD_CONFIG.with_suffix(".tmp")
    tmp.write_text("\n".join(new_lines))
    tmp.rename(HOSTAPD_CONFIG)

    # Restart hostapd
    run_cmd(["systemctl", "restart", "hostapd"])

    return {"success": True, "message": "AP config updated and hostapd restarted."}


@app.get("/api/wifi/uplink")
async def wifi_uplink_status():
    """Get uplink WiFi status using iw."""
    # Get connection info from iw
    result = run_cmd(["iw", "dev", "wlan0", "link"])

    ssid = None
    signal = None
    connected = False
    freq = None

    if result.returncode == 0 and "Connected to" in result.stdout:
        connected = True
        for line in result.stdout.split("\n"):
            line = line.strip()
            if line.startswith("SSID:"):
                ssid = line.split(":", 1)[1].strip()
            elif line.startswith("signal:"):
                signal = line.split(":", 1)[1].strip()
            elif line.startswith("freq:"):
                freq = line.split(":", 1)[1].strip()

    # Get IP address from ip command
    ip_result = run_cmd(["ip", "-4", "addr", "show", "wlan0"])
    ip_address = None
    for line in ip_result.stdout.split("\n"):
        if "inet " in line:
            parts = line.strip().split()
            if len(parts) >= 2:
                ip_address = parts[1].split("/")[0]
            break

    return {
        "interface": "wlan0",
        "connected": connected,
        "ssid": ssid,
        "ip_address": ip_address,
        "signal_dbm": signal,
        "frequency": freq
    }


@app.get("/api/wifi/networks")
async def wifi_scan(_=Depends(require_auth)):
    """Scan for available WiFi networks using iw."""
    # Trigger scan
    run_cmd(["iw", "dev", "wlan0", "scan", "trigger"], timeout=5)
    await asyncio.sleep(3)  # Wait for scan

    # Get scan results
    result = run_cmd(["iw", "dev", "wlan0", "scan", "dump"], timeout=30)

    networks = []
    current = {}

    for line in result.stdout.split("\n"):
        line = line.strip()
        if line.startswith("BSS "):
            if current.get("ssid"):
                networks.append(current)
            current = {"bssid": line.split()[1].split("(")[0]}
        elif line.startswith("SSID:"):
            current["ssid"] = line.split(":", 1)[1].strip()
        elif line.startswith("signal:"):
            current["signal"] = line.split(":", 1)[1].strip()
        elif line.startswith("freq:"):
            current["frequency"] = line.split(":", 1)[1].strip()
        elif "WPA" in line or "RSN" in line:
            current["security"] = "WPA"

    if current.get("ssid"):
        networks.append(current)

    # Remove duplicates and sort by signal
    seen = set()
    unique = []
    for n in networks:
        if n.get("ssid") and n["ssid"] not in seen:
            seen.add(n["ssid"])
            n.setdefault("security", "Open")
            unique.append(n)

    unique.sort(key=lambda x: float(x.get("signal", "-100").split()[0]), reverse=True)
    return {"networks": unique}


@app.post("/api/wifi/uplink/connect")
async def wifi_uplink_connect(ssid: str, password: str = None, _=Depends(require_auth)):
    """Connect to a WiFi network by updating netplan config."""
    if not re.match(r"^[\w\s\-]+$", ssid):
        raise HTTPException(status_code=400, detail="Invalid SSID")

    netplan_file = Path("/etc/netplan/30-wifis-dhcp.yaml")

    # Build new netplan config
    config = f'''# Managed by Guardian Portal
network:
  wifis:
    wlan0:
      dhcp4: yes
      dhcp6: yes
      access-points:
        "{ssid}":
'''
    if password:
        config += f'          password: "{password}"\n'

    # Write atomically
    tmp = netplan_file.with_suffix(".tmp")
    tmp.write_text(config)
    tmp.rename(netplan_file)

    # Apply netplan
    result = run_cmd(["netplan", "apply"], timeout=30)
    if result.returncode != 0:
        raise HTTPException(status_code=500, detail=f"Failed to apply netplan: {result.stderr}")

    return {"success": True, "message": f"Connecting to {ssid}..."}


@app.get("/api/logs")
async def get_logs(service: str = "guardian-portal", lines: int = 50, _=Depends(require_auth)):
    """Get recent log entries."""
    allowed_services = ["guardian-portal", "wireguard", "hostapd", "dnsmasq", "wg-quick@wg0"]
    if service not in allowed_services:
        raise HTTPException(status_code=400, detail=f"Service must be one of: {allowed_services}")

    lines = min(max(lines, 10), 200)  # Clamp between 10-200

    result = run_cmd(["journalctl", "-u", service, "-n", str(lines), "--no-pager"])
    return {"service": service, "lines": result.stdout.split("\n")}


@app.post("/api/system/reboot")
async def system_reboot(_=Depends(require_auth)):
    """Reboot the device."""
    # Schedule reboot in 2 seconds to allow response to be sent
    subprocess.Popen(["sleep", "2", "&&", "reboot"], shell=False)
    run_cmd(["shutdown", "-r", "+0"], timeout=5)
    return {"success": True, "message": "Rebooting..."}


@app.post("/api/system/shutdown")
async def system_shutdown(_=Depends(require_auth)):
    """Shutdown the device."""
    run_cmd(["shutdown", "-h", "+0"], timeout=5)
    return {"success": True, "message": "Shutting down..."}


# --- Static Files ---

@app.get("/")
async def root():
    """Serve the main page."""
    return FileResponse("/opt/guardian-portal/static/index.html")


# Mount static files last
app.mount("/static", StaticFiles(directory="/opt/guardian-portal/static"), name="static")
