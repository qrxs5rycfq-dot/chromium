from __future__ import annotations
import asyncio
import base64
import hashlib
import json
import logging
import os
import random
import ssl
import re
import string
import time
import aiohttp
import requests
import sys
import gzip
import brotli
import html
import math
import urllib3
import ipaddress
import atexit
import traceback
import secrets
import warnings
import uuid
import glob
import tempfile
from aiohttp import connector
from pathlib import Path
from colorama import init, Fore, Back, Style
from datetime import datetime
from time import sleep
from urllib.parse import urlencode, urlparse
from http.cookies import SimpleCookie
from typing import Any, Dict, List, Optional, Tuple, Set, Union 

# Optional imports
try:
    import httpx
    HAVE_HTTPX = True
except Exception:
    httpx = None
    HAVE_HTTPX = False

try:
    from faker import Faker
except ImportError:
    print("Faker library tidak ditemukan. Instal dengan: pip install faker")
    sys.exit()

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# OCR for captcha solving
try:
    import pytesseract
    from PIL import Image
    import io
    HAVE_OCR = True
except ImportError:
    HAVE_OCR = False
    print("⚠️ OCR libraries not found. Install with: pip install pytesseract pillow")
    print("   Also install Tesseract OCR: https://github.com/tesseract-ocr/tesseract")

# Init
fake = Faker()
init(autoreset=True)

# Terminal colors
biru = Fore.BLUE
kuning = Fore.YELLOW
merah = Fore.RED
putih = Fore.WHITE
cyan = Fore.CYAN
hijau = Fore.GREEN
hitam = Fore.BLACK
reset = Style.RESET_ALL
bg_merah = Back.RED
bg_kuning = Back.YELLOW
bg_hijau = Back.GREEN
bg_biru = Back.BLUE
bg_putih = Back.WHITE

logger = logging.getLogger("ultraboostedv13")
logger.setLevel(logging.INFO)

warnings.filterwarnings("ignore", category=RuntimeWarning,
                       message=".*HTTPS request is being sent through an HTTPS proxy.*")

# ============================================================================
# FIELD PATTERNS FOR DYNAMIC FORM DETECTION
# Multi-language support for placeholder/aria-label based field mapping
# ============================================================================
FIELD_PATTERNS = {
    # Priority 1: Standard form fields (checked first for input elements)
    'email': ['email', 'phone', 'mobile', 'emailorphone', 'email or phone', 'email address', 
              'phone number', 'email atau telepon', 'correo electrónico', 'e-mail'],
    'password': ['password', 'kata sandi', 'contraseña', 'mot de passe', 'passwort', 'sandi'],
    'username': ['username', 'nama pengguna', 'usuario', 'nom d\'utilisateur', 'benutzername', 
                 'user name'],
    'fullname': ['full name', 'nama lengkap', 'nombre completo', 'nom complet', 'vollständiger name'],
}

# Birthday field patterns - only checked for select/combobox elements
BIRTHDAY_FIELD_PATTERNS = {
    'month': ['month', 'bulan', 'mes', 'mois', 'mm', 'monat', 'mese', 'ماه', '月'],
    'day': ['day', 'hari', 'dia', 'jour', 'dd', 'tag', 'giorno', 'روز', '日'],
    'year': ['year', 'tahun', 'año', 'année', 'yyyy', 'jahr', 'anno', 'سال', '年'],
}

# Month names for smart field value selection
MONTH_NAMES = {
    'en': ['January', 'February', 'March', 'April', 'May', 'June', 
           'July', 'August', 'September', 'October', 'November', 'December'],
    'id': ['Januari', 'Februari', 'Maret', 'April', 'Mei', 'Juni',
           'Juli', 'Agustus', 'September', 'Oktober', 'November', 'Desember'],
    'es': ['Enero', 'Febrero', 'Marzo', 'Abril', 'Mayo', 'Junio',
           'Julio', 'Agosto', 'Septiembre', 'Octubre', 'Noviembre', 'Diciembre'],
    'short': ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 
              'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
}

# Skip words for button filtering (to avoid clicking back/cancel buttons)
BUTTON_SKIP_WORDS = [
    'cancel', 'back', 'batal', 'kembali', 'facebook', 'google', 'apple', 
    'login', 'log in', 'previous', 'return', 'masuk dengan', 'why', 'learn more',
    'help', 'bantuan', 'terms', 'privacy', 'kebijakan', 'ketentuan'
]

# Maximum buttons to show in debug output
MAX_DEBUG_BUTTONS = 10

# Maximum form processing steps to prevent infinite loops
MAX_FORM_STEPS = 5

# Maximum character length for error message display
MAX_ERROR_LENGTH = 100

# Threshold for using slow typing (characters)
SLOW_TYPING_THRESHOLD = 30

# ============================================================================
# ACCOUNT STATUS CODES
# ============================================================================
STATUS_PENDING = 0              # Initial state
STATUS_SUCCESS = 1              # Account created successfully
STATUS_EMAIL_TAKEN = 2          # Email already registered
STATUS_OTP_FAILED = 3           # OTP verification failed
STATUS_ERROR = 4                # General error
STATUS_SUSPENDED = 5            # Account suspended/disabled
STATUS_PHONE_REQUIRED = 6       # Phone verification required - close session
STATUS_OTP_NOT_RECEIVED = 7     # OTP code not received - close session

# ============================================================================
# ADVANCED IP STEALTH SYSTEM 2025
# Enhanced IP spoofing with real-time validation and fingerprint generation
# Based on advanced stealth techniques for Indonesian mobile networks
# ============================================================================
class AdvancedIPStealthSystem2025:
    """Dynamic IP stealth system 2025 with real-time validation and enhanced spoofing"""
    
    def __init__(self):
        self.ip_pool = []
        self.current_ip = None
        self.last_rotation = 0
        self.rotation_interval = 300  # 5 minutes
        self.validator = IPValidator2025()
        
        # Indonesian ISP configurations
        self.isp_configs = {
            "telkomsel": {
                "prefixes": ["110.136", "110.137", "114.122", "114.125", "112.215", "182.253"],
                "cities": ["Jakarta", "Surabaya", "Bandung", "Medan", "Bali", "Semarang", "Makassar"],
                "asn": "AS23693",
                "as_name": "Telkomsel",
                "ttl_range": (54, 64),
                "window_range": (32768, 65535),
                "mss_range": (1360, 1460),
                "packet_loss": (0.0, 0.5)
            },
            "indosat": {
                "prefixes": ["114.120", "114.121", "114.122", "36.68", "36.69", "36.71"],
                "cities": ["Jakarta", "Surabaya", "Bandung", "Yogyakarta", "Semarang", "Palembang"],
                "asn": "AS4761",
                "as_name": "Indosat Ooredoo",
                "ttl_range": (52, 64),
                "window_range": (32768, 65535),
                "mss_range": (1380, 1460),
                "packet_loss": (0.0, 0.8)
            },
            "xl": {
                "prefixes": ["36.85", "36.86", "36.87", "36.88", "118.97", "118.98"],
                "cities": ["Jakarta", "Surabaya", "Bandung", "Medan", "Tangerang", "Bekasi"],
                "asn": "AS24203",
                "as_name": "XL Axiata",
                "ttl_range": (52, 64),
                "window_range": (32768, 65535),
                "mss_range": (1360, 1460),
                "packet_loss": (0.0, 0.6)
            },
            "tri": {
                "prefixes": ["116.206", "116.207", "114.5", "114.6", "180.244", "180.245"],
                "cities": ["Jakarta", "Surabaya", "Bandung", "Yogyakarta", "Depok"],
                "asn": "AS45727",
                "as_name": "Tri Indonesia",
                "ttl_range": (52, 64),
                "window_range": (32768, 65535),
                "mss_range": (1360, 1460),
                "packet_loss": (0.0, 0.7)
            },
            "smartfren": {
                "prefixes": ["202.67", "202.68", "112.198", "112.199"],
                "cities": ["Jakarta", "Surabaya", "Bandung", "Tangerang"],
                "asn": "AS18004",
                "as_name": "Smartfren Telecom",
                "ttl_range": (52, 64),
                "window_range": (32768, 65535),
                "mss_range": (1360, 1460),
                "packet_loss": (0.0, 0.5)
            },
            "biznet": {
                "prefixes": ["103.23", "103.24", "112.78", "180.251"],
                "cities": ["Jakarta", "Surabaya", "Bandung", "Bali"],
                "asn": "AS17451",
                "as_name": "Biznet Networks",
                "ttl_range": (58, 64),
                "window_range": (65535, 65535),
                "mss_range": (1440, 1460),
                "packet_loss": (0.0, 0.2)
            }
        }
        
        # City coordinates
        self.city_coordinates = {
            "Jakarta": {"lat": -6.2088, "lon": 106.8456},
            "Surabaya": {"lat": -7.2575, "lon": 112.7521},
            "Bandung": {"lat": -6.9175, "lon": 107.6191},
            "Medan": {"lat": 3.5952, "lon": 98.6722},
            "Bali": {"lat": -8.4095, "lon": 115.1889},
            "Makassar": {"lat": -5.1477, "lon": 119.4327},
            "Semarang": {"lat": -6.9667, "lon": 110.4167},
            "Palembang": {"lat": -2.9909, "lon": 104.7566},
            "Yogyakarta": {"lat": -7.7956, "lon": 110.3695},
            "Tangerang": {"lat": -6.1783, "lon": 106.6319},
            "Bekasi": {"lat": -6.2383, "lon": 106.9756},
            "Depok": {"lat": -6.4025, "lon": 106.7942}
        }
        
    def get_fresh_ip_config(self) -> Dict[str, Any]:
        """Get fresh IP configuration with full spoofing data"""
        # Select random ISP
        isp_name = random.choice(list(self.isp_configs.keys()))
        config = self.isp_configs[isp_name]
        
        # Generate IP
        ip = self._generate_valid_ip(isp_name, config)
        
        # Determine connection type
        connection_type = random.choice(["mobile", "wifi"]) if isp_name in ["telkomsel", "indosat", "xl", "tri", "smartfren"] else "wifi"
        
        # Create full IP profile
        return self._create_ip_profile(ip, config, isp_name, connection_type)
    
    def _generate_valid_ip(self, isp_name: str, config: Dict[str, Any]) -> str:
        """Generate valid Indonesian IP"""
        prefix = random.choice(config["prefixes"])
        prefix_parts = prefix.split('.')
        
        while len(prefix_parts) < 4:
            prefix_parts.append(str(random.randint(2, 253)))
        
        ip = '.'.join(prefix_parts[:4])
        
        # Validate IP
        if not self._validate_ip(ip):
            # Regenerate with safer values
            ip = f"{prefix}.{random.randint(10, 240)}.{random.randint(10, 240)}"
            
        return ip
    
    def _validate_ip(self, ip: str) -> bool:
        """Validate IP address is not reserved"""
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return False
            
            for part in parts:
                num = int(part)
                if num < 0 or num > 255:
                    return False
            
            ip_obj = ipaddress.ip_address(ip)
            
            # Check not reserved
            if ip_obj.is_private or ip_obj.is_reserved or ip_obj.is_loopback:
                return False
            if ip_obj.is_multicast or ip_obj.is_link_local:
                return False
            
            # Check not suspicious pattern
            if ip.endswith('.0') or ip.endswith('.255') or ip.endswith('.1'):
                return False
                
            return True
        except Exception:
            return False
    
    def _create_ip_profile(self, ip: str, config: Dict[str, Any], isp_name: str, connection_type: str) -> Dict[str, Any]:
        """Create comprehensive IP profile"""
        city = random.choice(config["cities"])
        city_coords = self.city_coordinates.get(city, {"lat": -6.2088, "lon": 106.8456})
        
        # Network metrics based on connection type
        if connection_type == "mobile":
            latency = random.uniform(15, 45)
            jitter = random.uniform(2, 10)
            signal_strength = random.randint(-70, -50)
            bandwidth = random.uniform(10, 100)
            network_type = random.choice(["4G", "5G", "LTE"])
        else:
            latency = random.uniform(5, 20)
            jitter = random.uniform(1, 5)
            signal_strength = random.randint(-40, -20)
            bandwidth = random.uniform(50, 500)
            network_type = "WiFi"
        
        # Generate device fingerprint
        device_fingerprint = self._generate_device_fingerprint(isp_name, connection_type)
        
        # Generate JA3 fingerprint
        ja3, ja3s = self._generate_ja3_fingerprint(connection_type)
        
        # Generate TLS fingerprint
        tls_fingerprint = self._generate_tls_fingerprint(connection_type)
        
        return {
            "ip": ip,
            "type": "residential",
            "isp": isp_name,
            "asn": config["asn"],
            "as_name": config.get("as_name", isp_name.upper()),
            "connection_type": connection_type,
            "network_type": network_type,
            "location": {
                "city": city,
                "country": "Indonesia",
                "country_code": "ID",
                "latitude": round(city_coords["lat"] + random.uniform(-0.01, 0.01), 6),
                "longitude": round(city_coords["lon"] + random.uniform(-0.01, 0.01), 6),
                "timezone": "Asia/Jakarta",
                "carrier": isp_name.upper() if connection_type == "mobile" else "WiFi",
                "mcc": "510",
                "mnc": self._get_mnc(isp_name) if connection_type == "mobile" else ""
            },
            "network_metrics": {
                "latency_ms": round(latency, 2),
                "jitter_ms": round(jitter, 2),
                "packet_loss_percent": round(random.uniform(*config["packet_loss"]), 2),
                "bandwidth_mbps": round(bandwidth, 2),
                "signal_strength": signal_strength
            },
            "tcp_parameters": {
                "ttl": random.randint(*config["ttl_range"]),
                "window_size": random.randint(*config["window_range"]),
                "mss": random.randint(*config["mss_range"]),
                "sack_permitted": random.choice([True, False]),
                "window_scaling": random.randint(0, 14),
                "timestamps": True
            },
            "device_fingerprint": device_fingerprint,
            "fingerprints": {
                "ja3": ja3,
                "ja3s": ja3s,
                "tls": tls_fingerprint,
                "http2": self._generate_http2_settings(),
                "akamai": self._generate_akamai_fingerprint(),
                "cloudflare": self._generate_cloudflare_fingerprint()
            },
            "headers": self._generate_enhanced_headers(device_fingerprint, connection_type),
            "timestamp": int(time.time()),
            "health_score": random.randint(85, 98),
            "session_id": f"ip_{int(time.time())}_{random.randint(1000, 9999)}"
        }
    
    def _get_mnc(self, isp: str) -> str:
        """Get Mobile Network Code for ISP"""
        mnc_map = {
            "telkomsel": "10",
            "indosat": "01",
            "xl": "11",
            "tri": "89",
            "smartfren": "07"
        }
        return mnc_map.get(isp, "10")
    
    def _generate_device_fingerprint(self, isp: str, connection_type: str) -> Dict[str, Any]:
        """Generate device fingerprint based on connection type"""
        if connection_type == "mobile":
            devices = [
                {"brand": "Samsung", "model": "SM-S928B", "market_name": "Galaxy S24 Ultra", 
                 "android_version": "14", "screen_resolution": "1440x3120", "dpi": 510},
                {"brand": "Samsung", "model": "SM-S921B", "market_name": "Galaxy S24",
                 "android_version": "14", "screen_resolution": "1080x2340", "dpi": 425},
                {"brand": "Xiaomi", "model": "23116PN5BC", "market_name": "Xiaomi 14 Pro",
                 "android_version": "14", "screen_resolution": "1440x3200", "dpi": 522},
                {"brand": "OPPO", "model": "CPH2557", "market_name": "Reno 10 Pro+",
                 "android_version": "14", "screen_resolution": "1240x2772", "dpi": 450},
                {"brand": "vivo", "model": "V2303A", "market_name": "X100 Pro",
                 "android_version": "14", "screen_resolution": "1260x2800", "dpi": 460}
            ]
        else:
            devices = [
                {"brand": "Samsung", "model": "SM-X916B", "market_name": "Galaxy Tab S9 Ultra",
                 "android_version": "14", "screen_resolution": "2960x1848", "dpi": 239},
                {"brand": "Lenovo", "model": "TB370FU", "market_name": "Tab P12 Pro",
                 "android_version": "13", "screen_resolution": "2560x1600", "dpi": 280}
            ]
        
        device = random.choice(devices)
        chrome_version = random.choice(["130.0.0.0", "131.0.0.0", "132.0.0.0", "133.0.0.0", "134.0.0.0", "135.0.0.0"])
        
        return {
            **device,
            "chrome_version": chrome_version,
            "user_agent": f"Mozilla/5.0 (Linux; Android {device['android_version']}; {device['model']}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{chrome_version} Mobile Safari/537.36",
            "build_id": f"UP1A.{random.randint(230000, 241000)}.{random.randint(1, 999):03d}",
            "device_id": hashlib.md5(f"{device['model']}{time.time()}{random.random()}".encode()).hexdigest()[:16],
            "android_id": ''.join(random.choices('0123456789abcdef', k=16))
        }
    
    def _generate_ja3_fingerprint(self, connection_type: str) -> Tuple[str, str]:
        """Generate JA3 and JA3S fingerprint"""
        if connection_type == "mobile":
            ja3 = "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53-65037-65038-65039,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21-65041-65042,29-23-24-25-26,0"
            ja3s = "771,4865,65281-0-23-13-5-18-16-11-51-45-43-10-21,29-23-24,0"
        else:
            ja3 = "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24-25,0"
            ja3s = "771,4865,65281-0-23-13-5-18-16-11-51-45-43-10-21,29-23-24,0"
        
        return ja3, ja3s
    
    def _generate_tls_fingerprint(self, connection_type: str) -> Dict[str, Any]:
        """Generate TLS fingerprint"""
        return {
            "version": "TLSv1.3",
            "ciphers": [
                "TLS_AES_128_GCM_SHA256",
                "TLS_AES_256_GCM_SHA384",
                "TLS_CHACHA20_POLY1305_SHA256",
                "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
            ],
            "extensions": [
                "server_name", "supported_groups", "signature_algorithms",
                "application_layer_protocol_negotiation", "signed_certificate_timestamp",
                "key_share", "psk_key_exchange_modes", "supported_versions",
                "compress_certificate", "delegated_credentials"
            ],
            "supported_groups": ["x25519", "secp256r1", "secp384r1"],
            "signature_algorithms": ["ecdsa_secp256r1_sha256", "rsa_pss_rsae_sha256", "rsa_pkcs1_sha256"],
            "alpn": ["h2", "http/1.1"]
        }
    
    def _generate_http2_settings(self) -> Dict[str, Any]:
        """Generate HTTP/2 settings"""
        return {
            "HEADER_TABLE_SIZE": 65536,
            "MAX_CONCURRENT_STREAMS": 1000,
            "INITIAL_WINDOW_SIZE": 6291456,
            "MAX_HEADER_LIST_SIZE": 262144,
            "ENABLE_PUSH": 0
        }
    
    def _generate_akamai_fingerprint(self) -> Dict[str, Any]:
        """Generate Akamai fingerprint"""
        return {
            "bot_detection_bypass": True,
            "sensor_data": hashlib.sha256(f"{time.time()}{random.random()}".encode()).hexdigest()[:32],
            "abck_cookie": f"~-1~-1~-1~{random.randint(100000, 999999)}"
        }
    
    def _generate_cloudflare_fingerprint(self) -> Dict[str, Any]:
        """Generate Cloudflare fingerprint"""
        return {
            "turnstile_bypass": True,
            "ray_id": ''.join(random.choices('0123456789abcdef', k=16)),
            "challenge_token": hashlib.sha256(f"{time.time()}{random.random()}".encode()).hexdigest()[:24]
        }
    
    def _generate_enhanced_headers(self, device_fp: Dict[str, Any], connection_type: str) -> Dict[str, str]:
        """Generate enhanced HTTP headers"""
        brand = device_fp.get("brand", "Samsung")
        
        # Generate sec-ch-ua
        sec_ch_ua = '"Chromium";v="135", "Google Chrome";v="135", "Not-A.Brand";v="99"'
        
        return {
            "User-Agent": device_fp.get("user_agent", ""),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
            "Accept-Language": "id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7",
            "Accept-Encoding": "gzip, deflate, br",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
            "Sec-CH-UA": sec_ch_ua,
            "Sec-CH-UA-Mobile": "?1" if connection_type == "mobile" else "?0",
            "Sec-CH-UA-Platform": '"Android"',
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Upgrade-Insecure-Requests": "1",
            "DNT": "1"
        }
    
    def should_rotate_ip(self) -> bool:
        """Check if IP should be rotated"""
        return time.time() - self.last_rotation > self.rotation_interval
    
    def rotate_ip(self) -> Dict[str, Any]:
        """Rotate to new IP configuration"""
        self.current_ip = self.get_fresh_ip_config()
        self.last_rotation = time.time()
        return self.current_ip


class IPValidator2025:
    """IP Validator for 2025 with enhanced checks"""
    
    def validate(self, ip: str, strict: bool = True) -> Dict[str, Any]:
        """Validate IP address"""
        result = {
            "valid": True,
            "score": 100,
            "warnings": [],
            "errors": []
        }
        
        try:
            # Basic validation
            ip_obj = ipaddress.ip_address(ip)
            
            # Check reserved
            if ip_obj.is_private:
                result["valid"] = False
                result["errors"].append("Private IP")
                result["score"] = 0
            
            if ip_obj.is_reserved:
                result["valid"] = False
                result["errors"].append("Reserved IP")
                result["score"] = 0
            
            if ip_obj.is_loopback:
                result["valid"] = False
                result["errors"].append("Loopback IP")
                result["score"] = 0
            
            # Suspicious patterns
            parts = ip.split('.')
            if parts[-1] in ['0', '1', '255', '254']:
                result["warnings"].append("Suspicious last octet")
                result["score"] -= 20
            
            if all(p == parts[0] for p in parts):
                result["warnings"].append("All octets same")
                result["score"] -= 30
                
        except Exception as e:
            result["valid"] = False
            result["errors"].append(str(e))
            result["score"] = 0
        
        return result


# ============================================================================
# WEBRTC & WEBGL SPOOFING 2025
# Enhanced WebRTC and WebGL spoofing with more device profiles
# ============================================================================
class WebRTCWebGL_Spoofing2025:
    """Enhanced WebRTC and WebGL spoofing"""
    
    def __init__(self):
        self.webrtc_configs = self._generate_webrtc_configs()
        self.webgl_configs = self._generate_webgl_configs()
        self.canvas_configs = self._generate_canvas_configs()
        self.audio_configs = self._generate_audio_configs()
        self.font_configs = self._generate_font_configs()
        self.screen_configs = self._generate_screen_configs()
    
    def _generate_webrtc_configs(self) -> Dict[str, Any]:
        """Generate WebRTC configurations"""
        return {
            "android_chrome_samsung": {
                "ice_servers": [
                    {"urls": ["stun:stun.l.google.com:19302", "stun:stun1.l.google.com:19302"]},
                    {"urls": "turn:turn.bistri.com:80", "username": "homeo", "credential": "homeo"}
                ],
                "ice_transport_policy": "all",
                "bundle_policy": "max-bundle",
                "rtcp_mux_policy": "require",
                "sdp_semantics": "unified-plan",
                "encoded_insertable_streams": True,
                "force_codec": "VP9"
            },
            "android_chrome_xiaomi": {
                "ice_servers": [
                    {"urls": ["stun:stun.l.google.com:19302"]},
                    {"urls": "turn:turn.anyfirewall.com:443", "username": "webrtc", "credential": "webrtc"}
                ],
                "ice_transport_policy": "all",
                "bundle_policy": "max-bundle",
                "rtcp_mux_policy": "require",
                "sdp_semantics": "unified-plan",
                "encoded_insertable_streams": True,
                "force_codec": "H264"
            },
            "ios_safari": {
                "ice_servers": [
                    {"urls": ["stun:stun.l.google.com:19302"]}
                ],
                "ice_transport_policy": "all",
                "bundle_policy": "max-bundle",
                "rtcp_mux_policy": "require",
                "sdp_semantics": "unified-plan",
                "encoded_insertable_streams": False,
                "force_codec": "H264"
            }
        }
    
    def _generate_webgl_configs(self) -> Dict[str, Any]:
        """Generate WebGL configurations"""
        return {
            "adreno_750": {
                "vendor": "Qualcomm",
                "renderer": "Adreno (TM) 750",
                "unmasked_vendor": "Qualcomm",
                "unmasked_renderer": "Adreno (TM) 750",
                "version": "WebGL 2.0 (OpenGL ES 3.2 Qualcomm)",
                "shading_language": "WebGL GLSL ES 3.00",
                "max_texture_size": 16384,
                "max_viewport_dims": [16384, 16384],
                "max_renderbuffer_size": 16384,
                "max_combined_texture_image_units": 80,
                "max_vertex_texture_image_units": 16,
                "max_texture_image_units": 16,
                "max_vertex_attribs": 32,
                "max_varying_vectors": 32,
                "max_vertex_uniform_vectors": 1024,
                "max_fragment_uniform_vectors": 1024,
                "aliased_line_width_range": [1, 511],
                "aliased_point_size_range": [1, 2047]
            },
            "mali_g710": {
                "vendor": "ARM",
                "renderer": "Mali-G710 MC10",
                "unmasked_vendor": "ARM",
                "unmasked_renderer": "Mali-G710 MC10",
                "version": "WebGL 2.0 (OpenGL ES 3.2 ARM)",
                "shading_language": "WebGL GLSL ES 3.00",
                "max_texture_size": 8192,
                "max_viewport_dims": [8192, 8192],
                "max_renderbuffer_size": 8192,
                "max_combined_texture_image_units": 64,
                "max_vertex_texture_image_units": 16,
                "max_texture_image_units": 16,
                "max_vertex_attribs": 16,
                "max_varying_vectors": 16,
                "max_vertex_uniform_vectors": 256,
                "max_fragment_uniform_vectors": 256,
                "aliased_line_width_range": [1, 127],
                "aliased_point_size_range": [1, 1024]
            },
            "apple_gpu": {
                "vendor": "Apple Inc.",
                "renderer": "Apple GPU",
                "unmasked_vendor": "Apple Inc.",
                "unmasked_renderer": "Apple GPU",
                "version": "WebGL 2.0 (OpenGL ES 3.0)",
                "shading_language": "WebGL GLSL ES 3.00",
                "max_texture_size": 16384,
                "max_viewport_dims": [16384, 16384],
                "max_renderbuffer_size": 16384,
                "max_combined_texture_image_units": 80,
                "max_vertex_texture_image_units": 16,
                "max_texture_image_units": 16,
                "max_vertex_attribs": 31,
                "max_varying_vectors": 30,
                "max_vertex_uniform_vectors": 1024,
                "max_fragment_uniform_vectors": 1024,
                "aliased_line_width_range": [1, 1],
                "aliased_point_size_range": [1, 511]
            }
        }
    
    def _generate_canvas_configs(self) -> Dict[str, Any]:
        """Generate canvas configurations"""
        return {
            "samsung_galaxy_s24": {
                "width": 1440, "height": 3120, "color_depth": 24, "pixel_ratio": 3.0,
                "font_smoothing": "subpixel-antialiased", "text_rendering": "optimizeLegibility",
                "image_smoothing": True, "global_alpha": 1.0
            },
            "xiaomi_14_pro": {
                "width": 1440, "height": 3200, "color_depth": 30, "pixel_ratio": 3.5,
                "font_smoothing": "subpixel-antialiased", "text_rendering": "optimizeLegibility",
                "image_smoothing": True, "global_alpha": 1.0
            },
            "iphone_16_pro": {
                "width": 1170, "height": 2532, "color_depth": 30, "pixel_ratio": 3.0,
                "font_smoothing": "subpixel-antialiased", "text_rendering": "optimizeLegibility",
                "image_smoothing": True, "global_alpha": 1.0
            }
        }
    
    def _generate_audio_configs(self) -> Dict[str, Any]:
        """Generate audio configurations"""
        return {
            "android_samsung": {
                "sample_rate": 48000, "channel_count": 2, "buffer_size": 4096,
                "latency": 0.01, "fft_size": 2048, "smoothing_time_constant": 0.8
            },
            "android_xiaomi": {
                "sample_rate": 48000, "channel_count": 2, "buffer_size": 2048,
                "latency": 0.02, "fft_size": 1024, "smoothing_time_constant": 0.9
            },
            "ios": {
                "sample_rate": 44100, "channel_count": 2, "buffer_size": 2048,
                "latency": 0.02, "fft_size": 1024, "smoothing_time_constant": 0.9
            }
        }
    
    def _generate_font_configs(self) -> Dict[str, Any]:
        """Generate font configurations"""
        return {
            "android_samsung": {
                "fonts": ["Roboto", "SamsungOne", "Noto Sans", "Google Sans", "Arial", "Helvetica"]
            },
            "android_xiaomi": {
                "fonts": ["MiSans", "Roboto", "Noto Sans", "Google Sans", "Arial"]
            },
            "ios": {
                "fonts": ["San Francisco", "Helvetica Neue", "Arial", "Times New Roman"]
            }
        }
    
    def _generate_screen_configs(self) -> Dict[str, Any]:
        """Generate screen configurations"""
        return {
            "samsung_galaxy_s24": {
                "width": 1440, "height": 3120, "avail_width": 1440, "avail_height": 3060,
                "color_depth": 24, "pixel_depth": 24, "device_pixel_ratio": 3.0,
                "touch_support": True, "max_touch_points": 10
            },
            "xiaomi_14_pro": {
                "width": 1440, "height": 3200, "avail_width": 1440, "avail_height": 3140,
                "color_depth": 30, "pixel_depth": 30, "device_pixel_ratio": 3.5,
                "touch_support": True, "max_touch_points": 10
            },
            "iphone_16_pro": {
                "width": 1170, "height": 2532, "avail_width": 1170, "avail_height": 2472,
                "color_depth": 30, "pixel_depth": 30, "device_pixel_ratio": 3.0,
                "touch_support": True, "max_touch_points": 5
            }
        }
    
    def get_complete_fingerprint(self, device_type: str = "android", brand: str = "samsung", 
                                  connection_type: str = "mobile") -> Dict[str, Any]:
        """Get complete spoofing fingerprint"""
        if device_type == "ios":
            webrtc_profile = "ios_safari"
            webgl_profile = "apple_gpu"
            canvas_profile = "iphone_16_pro"
            audio_profile = "ios"
            font_profile = "ios"
            screen_profile = "iphone_16_pro"
        elif brand.lower() == "xiaomi":
            webrtc_profile = "android_chrome_xiaomi"
            webgl_profile = "mali_g710"
            canvas_profile = "xiaomi_14_pro"
            audio_profile = "android_xiaomi"
            font_profile = "android_xiaomi"
            screen_profile = "xiaomi_14_pro"
        else:
            webrtc_profile = "android_chrome_samsung"
            webgl_profile = "adreno_750"
            canvas_profile = "samsung_galaxy_s24"
            audio_profile = "android_samsung"
            font_profile = "android_samsung"
            screen_profile = "samsung_galaxy_s24"
        
        return {
            "webrtc": self.webrtc_configs.get(webrtc_profile, {}),
            "webgl": self.webgl_configs.get(webgl_profile, {}),
            "canvas": self.canvas_configs.get(canvas_profile, {}),
            "audio": self.audio_configs.get(audio_profile, {}),
            "fonts": self.font_configs.get(font_profile, {}),
            "screen": self.screen_configs.get(screen_profile, {}),
            "device_type": device_type,
            "brand": brand,
            "connection_type": connection_type,
            "timestamp": int(time.time()),
            "fingerprint_id": f"fp_{int(time.time())}_{random.randint(1000, 9999)}",
            "noise_factors": {
                "canvas_noise": random.uniform(0.001, 0.005),
                "audio_noise": random.uniform(0.0001, 0.001),
                "timing_noise": random.uniform(0.1, 0.5)
            }
        }
    
    def get_stealth_injection_script(self, fingerprint: Dict[str, Any]) -> str:
        """Generate JavaScript injection script for fingerprint spoofing"""
        webgl_config = fingerprint.get("webgl", {})
        screen_config = fingerprint.get("screen", {})
        audio_config = fingerprint.get("audio", {})
        noise = fingerprint.get("noise_factors", {})
        
        return f"""
        // === COMPREHENSIVE FINGERPRINT SPOOFING 2025 ===
        
        const SPOOF_CONFIG = {{
            webgl: {{
                vendor: '{webgl_config.get("vendor", "Qualcomm")}',
                renderer: '{webgl_config.get("renderer", "Adreno (TM) 750")}',
                unmaskedVendor: '{webgl_config.get("unmasked_vendor", "Qualcomm")}',
                unmaskedRenderer: '{webgl_config.get("unmasked_renderer", "Adreno (TM) 750")}',
                version: '{webgl_config.get("version", "WebGL 2.0")}',
                shadingLanguage: '{webgl_config.get("shading_language", "WebGL GLSL ES 3.00")}'
            }},
            screen: {{
                width: {screen_config.get("width", 1440)},
                height: {screen_config.get("height", 3120)},
                availWidth: {screen_config.get("avail_width", 1440)},
                availHeight: {screen_config.get("avail_height", 3060)},
                colorDepth: {screen_config.get("color_depth", 24)},
                pixelDepth: {screen_config.get("pixel_depth", 24)},
                devicePixelRatio: {screen_config.get("device_pixel_ratio", 3.0)},
                maxTouchPoints: {screen_config.get("max_touch_points", 10)}
            }},
            audio: {{
                sampleRate: {audio_config.get("sample_rate", 48000)},
                channelCount: {audio_config.get("channel_count", 2)}
            }},
            noise: {{
                canvas: {noise.get("canvas_noise", 0.003)},
                audio: {noise.get("audio_noise", 0.0005)}
            }}
        }};
        
        // === WEBDRIVER REMOVAL ===
        Object.defineProperty(navigator, 'webdriver', {{
            get: () => undefined,
            configurable: true
        }});
        delete navigator.__proto__.webdriver;
        
        // === AUTOMATION CONTROLLED REMOVAL ===
        Object.defineProperty(navigator, 'automationControlled', {{
            get: () => undefined,
            configurable: true
        }});
        
        // === WEBGL SPOOFING ===
        const spoofWebGL = (contextType) => {{
            const originalGetParameter = contextType.prototype.getParameter;
            contextType.prototype.getParameter = function(parameter) {{
                if (parameter === 37445) return SPOOF_CONFIG.webgl.unmaskedVendor;
                if (parameter === 37446) return SPOOF_CONFIG.webgl.unmaskedRenderer;
                if (parameter === 7937) return SPOOF_CONFIG.webgl.vendor;
                if (parameter === 7938) return SPOOF_CONFIG.webgl.renderer;
                if (parameter === 35724) return SPOOF_CONFIG.webgl.shadingLanguage;
                return originalGetParameter.call(this, parameter);
            }};
        }};
        
        if (typeof WebGLRenderingContext !== 'undefined') spoofWebGL(WebGLRenderingContext);
        if (typeof WebGL2RenderingContext !== 'undefined') spoofWebGL(WebGL2RenderingContext);
        
        // === SCREEN SPOOFING ===
        const screenProps = ['width', 'height', 'availWidth', 'availHeight', 'colorDepth', 'pixelDepth'];
        screenProps.forEach(prop => {{
            const configKey = prop;
            if (SPOOF_CONFIG.screen[configKey] !== undefined) {{
                Object.defineProperty(screen, prop, {{
                    get: () => SPOOF_CONFIG.screen[configKey],
                    configurable: true
                }});
            }}
        }});
        
        Object.defineProperty(window, 'devicePixelRatio', {{
            get: () => SPOOF_CONFIG.screen.devicePixelRatio,
            configurable: true
        }});
        
        Object.defineProperty(navigator, 'maxTouchPoints', {{
            get: () => SPOOF_CONFIG.screen.maxTouchPoints,
            configurable: true
        }});
        
        // === CANVAS FINGERPRINT PROTECTION ===
        const originalToDataURL = HTMLCanvasElement.prototype.toDataURL;
        HTMLCanvasElement.prototype.toDataURL = function(type, quality) {{
            const ctx = this.getContext('2d');
            if (ctx && this.width > 0 && this.height > 0) {{
                try {{
                    const imageData = ctx.getImageData(0, 0, this.width, this.height);
                    for (let i = 0; i < imageData.data.length; i += 100) {{
                        imageData.data[i] = Math.max(0, Math.min(255, 
                            imageData.data[i] + Math.floor((Math.random() - 0.5) * SPOOF_CONFIG.noise.canvas * 100)));
                    }}
                    ctx.putImageData(imageData, 0, 0);
                }} catch(e) {{}}
            }}
            return originalToDataURL.call(this, type, quality);
        }};
        
        const originalGetImageData = CanvasRenderingContext2D.prototype.getImageData;
        CanvasRenderingContext2D.prototype.getImageData = function() {{
            const imageData = originalGetImageData.apply(this, arguments);
            for (let i = 0; i < imageData.data.length; i += 100) {{
                imageData.data[i] = Math.max(0, Math.min(255,
                    imageData.data[i] + Math.floor((Math.random() - 0.5) * SPOOF_CONFIG.noise.canvas * 100)));
            }}
            return imageData;
        }};
        
        // === AUDIO FINGERPRINT PROTECTION ===
        if (typeof AudioBuffer !== 'undefined') {{
            const originalGetChannelData = AudioBuffer.prototype.getChannelData;
            AudioBuffer.prototype.getChannelData = function() {{
                const data = originalGetChannelData.apply(this, arguments);
                for (let i = 0; i < data.length; i += 100) {{
                    data[i] += (Math.random() - 0.5) * SPOOF_CONFIG.noise.audio;
                }}
                return data;
            }};
        }}
        
        // === WEBRTC IP LEAK PROTECTION ===
        if (typeof RTCPeerConnection !== 'undefined') {{
            const originalRTCPeerConnection = window.RTCPeerConnection;
            window.RTCPeerConnection = function(config) {{
                if (config && config.iceServers) {{
                    config.iceServers = config.iceServers.filter(server => 
                        !server.urls || !server.urls.toString().includes('stun.l.google.com'));
                }}
                return new originalRTCPeerConnection(config);
            }};
            window.RTCPeerConnection.prototype = originalRTCPeerConnection.prototype;
        }}
        
        // Disable WebRTC candidates leak
        if (typeof RTCPeerConnection !== 'undefined') {{
            const originalAddEventListener = RTCPeerConnection.prototype.addEventListener;
            RTCPeerConnection.prototype.addEventListener = function(type, listener, options) {{
                if (type === 'icecandidate') {{
                    const wrappedListener = function(event) {{
                        if (event.candidate && event.candidate.candidate) {{
                            // Filter out local IP candidates
                            if (event.candidate.candidate.includes('typ host')) {{
                                return;
                            }}
                        }}
                        listener.call(this, event);
                    }};
                    return originalAddEventListener.call(this, type, wrappedListener, options);
                }}
                return originalAddEventListener.call(this, type, listener, options);
            }};
        }}
        
        // === CHROME RUNTIME MOCK ===
        window.chrome = {{
            runtime: {{
                id: undefined,
                connect: () => ({{}}),
                sendMessage: () => {{}},
                onMessage: {{ addListener: () => {{}} }}
            }},
            loadTimes: () => ({{}}),
            csi: () => ({{}})
        }};
        
        // === PERMISSIONS API OVERRIDE ===
        const originalQuery = navigator.permissions.query;
        navigator.permissions.query = (parameters) => {{
            if (parameters.name === 'notifications') return Promise.resolve({{ state: 'denied' }});
            if (parameters.name === 'geolocation') return Promise.resolve({{ state: 'prompt' }});
            if (parameters.name === 'camera') return Promise.resolve({{ state: 'prompt' }});
            if (parameters.name === 'microphone') return Promise.resolve({{ state: 'prompt' }});
            return originalQuery.call(navigator.permissions, parameters);
        }};
        
        // === PLUGINS MOCK ===
        Object.defineProperty(navigator, 'plugins', {{
            get: () => {{
                const plugins = [
                    {{ name: 'Chrome PDF Plugin', filename: 'internal-pdf-viewer', description: 'Portable Document Format' }},
                    {{ name: 'Chrome PDF Viewer', filename: 'mhjfbmdgcfjbbpaeojofohoefgiehjai', description: '' }},
                    {{ name: 'Native Client', filename: 'internal-nacl-plugin', description: '' }}
                ];
                plugins.length = 3;
                return plugins;
            }},
            configurable: true
        }});
        
        // === BATTERY API DISABLE ===
        if (navigator.getBattery) {{
            navigator.getBattery = undefined;
        }}
        
        console.log('🛡️ Comprehensive Fingerprint Spoofing 2025 Active');
        """


# Global instances
IP_STEALTH_SYSTEM = AdvancedIPStealthSystem2025()
WEBRTC_WEBGL_SPOOFER = WebRTCWebGL_Spoofing2025()

# ============================================================================
# DYNAMIC FINGERPRINT GENERATOR - Fully Synchronized
# All components (UA, headers, device info, WebGL, canvas) are consistent
# ============================================================================
class DynamicFingerprintGenerator:
    """
    Generate fully synchronized, realistic fingerprints that match across:
    - User Agent
    - HTTP Headers (Sec-CH-UA, Accept-Language, etc.)
    - Navigator properties
    - Screen/viewport
    - WebGL renderer
    - Canvas fingerprint seed
    - Audio context
    - Timezone
    """
    
    # Real device profiles with synchronized data
    DEVICE_PROFILES = [
        # Windows Chrome profiles
        {
            'os': 'Windows',
            'os_version': '10.0',
            'browser': 'Chrome',
            'browser_versions': ['120', '121', '122', '123', '124'],
            'platform': 'Win32',
            'vendor': 'Google Inc.',
            'renderer_base': 'ANGLE (NVIDIA, NVIDIA GeForce',
            'gpu_models': ['GTX 1650', 'GTX 1660', 'RTX 2060', 'RTX 3060', 'RTX 3070', 'RTX 4060'],
            'screens': [
                {'width': 1920, 'height': 1080, 'depth': 24, 'dpr': 1},
                {'width': 2560, 'height': 1440, 'depth': 24, 'dpr': 1},
                {'width': 1366, 'height': 768, 'depth': 24, 'dpr': 1},
                {'width': 1536, 'height': 864, 'depth': 24, 'dpr': 1.25},
            ],
            'memory': [8, 16, 32],
            'cores': [4, 6, 8, 12, 16],
            'languages': ['en-US', 'en'],
        },
        {
            'os': 'Windows',
            'os_version': '10.0',
            'browser': 'Chrome',
            'browser_versions': ['120', '121', '122', '123', '124'],
            'platform': 'Win32',
            'vendor': 'Google Inc.',
            'renderer_base': 'ANGLE (AMD, AMD Radeon',
            'gpu_models': ['RX 580', 'RX 5600 XT', 'RX 6600', 'RX 6700 XT', 'RX 7600'],
            'screens': [
                {'width': 1920, 'height': 1080, 'depth': 24, 'dpr': 1},
                {'width': 2560, 'height': 1440, 'depth': 24, 'dpr': 1},
            ],
            'memory': [8, 16],
            'cores': [6, 8, 12],
            'languages': ['en-US', 'en'],
        },
        # Mac Chrome profiles
        {
            'os': 'macOS',
            'os_version': '10_15_7',
            'browser': 'Chrome',
            'browser_versions': ['120', '121', '122', '123', '124'],
            'platform': 'MacIntel',
            'vendor': 'Google Inc.',
            'renderer_base': 'ANGLE (Apple, Apple M',
            'gpu_models': ['1', '1 Pro', '2', '2 Pro', '3', '3 Pro'],
            'screens': [
                {'width': 1440, 'height': 900, 'depth': 30, 'dpr': 2},
                {'width': 1680, 'height': 1050, 'depth': 30, 'dpr': 2},
                {'width': 2560, 'height': 1600, 'depth': 30, 'dpr': 2},
            ],
            'memory': [8, 16, 32],
            'cores': [8, 10, 12],
            'languages': ['en-US', 'en'],
        },
        # Mac Safari profiles
        {
            'os': 'macOS',
            'os_version': '10_15_7',
            'browser': 'Safari',
            'browser_versions': ['17.1', '17.2', '17.3', '17.4'],
            'platform': 'MacIntel',
            'vendor': 'Apple Computer, Inc.',
            'renderer_base': 'Apple GPU',
            'gpu_models': [''],
            'screens': [
                {'width': 1440, 'height': 900, 'depth': 30, 'dpr': 2},
                {'width': 1680, 'height': 1050, 'depth': 30, 'dpr': 2},
            ],
            'memory': [8, 16],
            'cores': [8, 10],
            'languages': ['en-US', 'en'],
        },
        # Windows Firefox profiles
        {
            'os': 'Windows',
            'os_version': '10.0',
            'browser': 'Firefox',
            'browser_versions': ['121', '122', '123', '124', '125'],
            'platform': 'Win32',
            'vendor': '',
            'renderer_base': 'NVIDIA GeForce',
            'gpu_models': ['GTX 1650', 'GTX 1660', 'RTX 2060', 'RTX 3060'],
            'screens': [
                {'width': 1920, 'height': 1080, 'depth': 24, 'dpr': 1},
                {'width': 1366, 'height': 768, 'depth': 24, 'dpr': 1},
            ],
            'memory': [8, 16],
            'cores': [4, 6, 8],
            'languages': ['en-US', 'en'],
        },
    ]
    
    TIMEZONES = {
        'America/New_York': {'offset': -5, 'locale': 'en-US'},
        'America/Chicago': {'offset': -6, 'locale': 'en-US'},
        'America/Denver': {'offset': -7, 'locale': 'en-US'},
        'America/Los_Angeles': {'offset': -8, 'locale': 'en-US'},
        'Europe/London': {'offset': 0, 'locale': 'en-GB'},
        'Europe/Paris': {'offset': 1, 'locale': 'fr-FR'},
        'Europe/Berlin': {'offset': 1, 'locale': 'de-DE'},
        'Asia/Tokyo': {'offset': 9, 'locale': 'ja-JP'},
        'Asia/Singapore': {'offset': 8, 'locale': 'en-SG'},
        'Australia/Sydney': {'offset': 11, 'locale': 'en-AU'},
    }
    
    def __init__(self):
        self.current_fingerprint = None
        self.fingerprint_created_at = 0
        self.session_id = str(uuid.uuid4())
    
    def generate(self, force_new: bool = False) -> Dict[str, Any]:
        """Generate a complete synchronized fingerprint"""
        # Rotate fingerprint every 30-60 minutes or if forced
        if (not force_new and self.current_fingerprint and 
            time.time() - self.fingerprint_created_at < random.randint(1800, 3600)):
            return self.current_fingerprint
        
        # Select random device profile
        profile = random.choice(self.DEVICE_PROFILES)
        browser_version = random.choice(profile['browser_versions'])
        screen = random.choice(profile['screens'])
        gpu_model = random.choice(profile['gpu_models'])
        memory = random.choice(profile['memory'])
        cores = random.choice(profile['cores'])
        
        # Select timezone
        tz_name = random.choice(list(self.TIMEZONES.keys()))
        tz_info = self.TIMEZONES[tz_name]
        
        # Generate synchronized user agent
        if profile['browser'] == 'Chrome':
            if profile['os'] == 'Windows':
                user_agent = f"Mozilla/5.0 (Windows NT {profile['os_version']}; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{browser_version}.0.0.0 Safari/537.36"
            else:
                user_agent = f"Mozilla/5.0 (Macintosh; Intel Mac OS X {profile['os_version']}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{browser_version}.0.0.0 Safari/537.36"
        elif profile['browser'] == 'Firefox':
            user_agent = f"Mozilla/5.0 (Windows NT {profile['os_version']}; Win64; x64; rv:{browser_version}.0) Gecko/20100101 Firefox/{browser_version}.0"
        else:  # Safari
            user_agent = f"Mozilla/5.0 (Macintosh; Intel Mac OS X {profile['os_version']}) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/{browser_version} Safari/605.1.15"
        
        # Generate WebGL info
        if profile['renderer_base'].startswith('ANGLE'):
            webgl_vendor = 'Google Inc. (NVIDIA)' if 'NVIDIA' in profile['renderer_base'] else 'Google Inc. (AMD)'
            webgl_renderer = f"{profile['renderer_base']} {gpu_model}, Direct3D11)"
        elif profile['renderer_base'] == 'Apple GPU':
            webgl_vendor = 'Apple Inc.'
            webgl_renderer = 'Apple GPU'
        else:
            webgl_vendor = 'Google Inc.'
            webgl_renderer = f"{profile['renderer_base']} {gpu_model}"
        
        # Generate canvas noise seed (consistent per session)
        canvas_seed = hashlib.md5(f"{self.session_id}{user_agent}".encode()).hexdigest()[:8]
        audio_seed = hashlib.md5(f"{self.session_id}audio{user_agent}".encode()).hexdigest()[:8]
        
        # Generate synchronized headers
        if profile['browser'] == 'Chrome':
            sec_ch_ua = f'"Chromium";v="{browser_version}", "Google Chrome";v="{browser_version}", "Not-A.Brand";v="99"'
        elif profile['browser'] == 'Firefox':
            sec_ch_ua = None  # Firefox doesn't send Sec-CH-UA
        else:
            sec_ch_ua = None  # Safari doesn't send Sec-CH-UA
        
        sec_ch_ua_platform = f'"{profile["os"]}"' if profile['browser'] == 'Chrome' else None
        
        fingerprint = {
            # Basic info
            'session_id': self.session_id,
            'created_at': time.time(),
            
            # Device profile
            'os': profile['os'],
            'os_version': profile['os_version'],
            'browser': profile['browser'],
            'browser_version': browser_version,
            'platform': profile['platform'],
            
            # User Agent
            'user_agent': user_agent,
            
            # Screen
            'screen_width': screen['width'],
            'screen_height': screen['height'],
            'screen_depth': screen['depth'],
            'device_pixel_ratio': screen['dpr'],
            'viewport_width': screen['width'],
            'viewport_height': screen['height'] - random.randint(80, 150),  # Account for browser chrome
            
            # Hardware
            'hardware_concurrency': cores,
            'device_memory': memory,
            
            # WebGL
            'webgl_vendor': webgl_vendor,
            'webgl_renderer': webgl_renderer,
            
            # Canvas/Audio seeds for consistent noise
            'canvas_seed': canvas_seed,
            'audio_seed': audio_seed,
            
            # Timezone
            'timezone': tz_name,
            'timezone_offset': tz_info['offset'] * -60,  # JS uses inverted minutes
            
            # Language
            'languages': profile['languages'],
            'locale': tz_info['locale'],
            
            # HTTP Headers (synchronized with UA)
            'headers': {
                'User-Agent': user_agent,
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
                'Accept-Language': ','.join(profile['languages']) + ';q=0.9',
                'Accept-Encoding': 'gzip, deflate, br',
                'Cache-Control': 'max-age=0',
                'Sec-Fetch-Dest': 'document',
                'Sec-Fetch-Mode': 'navigate',
                'Sec-Fetch-Site': 'none',
                'Sec-Fetch-User': '?1',
                'Upgrade-Insecure-Requests': '1',
            },
            
            # Connection info
            'connection_type': random.choice(['wifi', 'ethernet']),
            'effective_type': '4g',
            'downlink': round(random.uniform(5, 50), 1),
            'rtt': random.randint(25, 100),
        }
        
        # Add Chrome-specific headers
        if profile['browser'] == 'Chrome':
            fingerprint['headers']['Sec-CH-UA'] = sec_ch_ua
            fingerprint['headers']['Sec-CH-UA-Mobile'] = '?0'
            fingerprint['headers']['Sec-CH-UA-Platform'] = sec_ch_ua_platform
        
        self.current_fingerprint = fingerprint
        self.fingerprint_created_at = time.time()
        
        return fingerprint
    
    def get_stealth_script(self, fingerprint: Dict[str, Any]) -> str:
        """Generate stealth script synchronized with fingerprint"""
        return f"""
        // === SYNCHRONIZED STEALTH MODE ===
        // All values match the fingerprint and headers
        
        const FINGERPRINT = {{
            platform: '{fingerprint['platform']}',
            languages: {json.dumps(fingerprint['languages'])},
            hardwareConcurrency: {fingerprint['hardware_concurrency']},
            deviceMemory: {fingerprint['device_memory']},
            screenWidth: {fingerprint['screen_width']},
            screenHeight: {fingerprint['screen_height']},
            screenDepth: {fingerprint['screen_depth']},
            devicePixelRatio: {fingerprint['device_pixel_ratio']},
            timezoneOffset: {fingerprint['timezone_offset']},
            webglVendor: '{fingerprint['webgl_vendor']}',
            webglRenderer: '{fingerprint['webgl_renderer']}',
            canvasSeed: '{fingerprint['canvas_seed']}',
            audioSeed: '{fingerprint['audio_seed']}',
            connectionType: '{fingerprint['connection_type']}',
            effectiveType: '{fingerprint['effective_type']}',
            downlink: {fingerprint['downlink']},
            rtt: {fingerprint['rtt']},
        }};
        
        // === WEBDRIVER REMOVAL ===
        Object.defineProperty(navigator, 'webdriver', {{
            get: () => undefined,
            configurable: true
        }});
        delete navigator.__proto__.webdriver;
        
        // === NAVIGATOR PROPERTIES (Synchronized) ===
        Object.defineProperty(navigator, 'platform', {{
            get: () => FINGERPRINT.platform,
            configurable: true
        }});
        
        Object.defineProperty(navigator, 'languages', {{
            get: () => FINGERPRINT.languages,
            configurable: true
        }});
        
        Object.defineProperty(navigator, 'language', {{
            get: () => FINGERPRINT.languages[0],
            configurable: true
        }});
        
        Object.defineProperty(navigator, 'hardwareConcurrency', {{
            get: () => FINGERPRINT.hardwareConcurrency,
            configurable: true
        }});
        
        Object.defineProperty(navigator, 'deviceMemory', {{
            get: () => FINGERPRINT.deviceMemory,
            configurable: true
        }});
        
        // === SCREEN PROPERTIES (Synchronized) ===
        Object.defineProperty(screen, 'width', {{
            get: () => FINGERPRINT.screenWidth,
            configurable: true
        }});
        
        Object.defineProperty(screen, 'height', {{
            get: () => FINGERPRINT.screenHeight,
            configurable: true
        }});
        
        Object.defineProperty(screen, 'availWidth', {{
            get: () => FINGERPRINT.screenWidth,
            configurable: true
        }});
        
        Object.defineProperty(screen, 'availHeight', {{
            get: () => FINGERPRINT.screenHeight - 40,
            configurable: true
        }});
        
        Object.defineProperty(screen, 'colorDepth', {{
            get: () => FINGERPRINT.screenDepth,
            configurable: true
        }});
        
        Object.defineProperty(screen, 'pixelDepth', {{
            get: () => FINGERPRINT.screenDepth,
            configurable: true
        }});
        
        Object.defineProperty(window, 'devicePixelRatio', {{
            get: () => FINGERPRINT.devicePixelRatio,
            configurable: true
        }});
        
        // === TIMEZONE (Synchronized) ===
        Date.prototype.getTimezoneOffset = function() {{
            return FINGERPRINT.timezoneOffset;
        }};
        
        // === WEBGL (Synchronized with hardware) ===
        if (typeof WebGLRenderingContext !== 'undefined') {{
            const getParameter = WebGLRenderingContext.prototype.getParameter;
            WebGLRenderingContext.prototype.getParameter = function(parameter) {{
                if (parameter === 37445) return FINGERPRINT.webglVendor;
                if (parameter === 37446) return FINGERPRINT.webglRenderer;
                return getParameter.call(this, parameter);
            }};
        }}
        
        if (typeof WebGL2RenderingContext !== 'undefined') {{
            const getParameter2 = WebGL2RenderingContext.prototype.getParameter;
            WebGL2RenderingContext.prototype.getParameter = function(parameter) {{
                if (parameter === 37445) return FINGERPRINT.webglVendor;
                if (parameter === 37446) return FINGERPRINT.webglRenderer;
                return getParameter2.call(this, parameter);
            }};
        }}
        
        // === CANVAS FINGERPRINT (Seeded noise for consistency) ===
        const seedRandom = (seed) => {{
            let x = Math.sin(parseInt(seed, 16)) * 10000;
            return x - Math.floor(x);
        }};
        
        const canvasNoise = seedRandom(FINGERPRINT.canvasSeed);
        
        const originalToDataURL = HTMLCanvasElement.prototype.toDataURL;
        HTMLCanvasElement.prototype.toDataURL = function(type, quality) {{
            const ctx = this.getContext('2d');
            if (ctx) {{
                const imageData = ctx.getImageData(0, 0, this.width, this.height);
                for (let i = 0; i < imageData.data.length; i += 100) {{
                    imageData.data[i] = imageData.data[i] + Math.floor((canvasNoise - 0.5) * 4);
                }}
                ctx.putImageData(imageData, 0, 0);
            }}
            return originalToDataURL.call(this, type, quality);
        }};
        
        // === AUDIO FINGERPRINT (Seeded noise) ===
        if (typeof AudioBuffer !== 'undefined') {{
            const audioNoise = seedRandom(FINGERPRINT.audioSeed);
            const originalGetChannelData = AudioBuffer.prototype.getChannelData;
            AudioBuffer.prototype.getChannelData = function() {{
                const data = originalGetChannelData.apply(this, arguments);
                for (let i = 0; i < data.length; i += 100) {{
                    data[i] += (audioNoise - 0.5) * 0.0001;
                }}
                return data;
            }};
        }}
        
        // === NETWORK INFO (Synchronized) ===
        Object.defineProperty(navigator, 'connection', {{
            get: () => ({{
                type: FINGERPRINT.connectionType,
                effectiveType: FINGERPRINT.effectiveType,
                downlink: FINGERPRINT.downlink,
                rtt: FINGERPRINT.rtt,
                saveData: false,
                onchange: null,
                addEventListener: () => {{}},
                removeEventListener: () => {{}}
            }}),
            configurable: true
        }});
        
        // === PERMISSIONS (Consistent behavior) ===
        const originalQuery = window.navigator.permissions.query;
        window.navigator.permissions.query = (parameters) => {{
            if (parameters.name === 'notifications') return Promise.resolve({{ state: 'denied' }});
            if (parameters.name === 'geolocation') return Promise.resolve({{ state: 'prompt' }});
            return originalQuery(parameters);
        }};
        
        // === PLUGINS (Realistic) ===
        Object.defineProperty(navigator, 'plugins', {{
            get: () => {{
                const plugins = [
                    {{ name: 'Chrome PDF Plugin', filename: 'internal-pdf-viewer', description: 'Portable Document Format' }},
                    {{ name: 'Chrome PDF Viewer', filename: 'mhjfbmdgcfjbbpaeojofohoefgiehjai', description: '' }},
                    {{ name: 'Native Client', filename: 'internal-nacl-plugin', description: '' }}
                ];
                plugins.length = 3;
                return plugins;
            }},
            configurable: true
        }});
        
        // === CHROME OBJECT ===
        window.chrome = {{
            runtime: {{
                id: undefined,
                connect: () => {{}},
                sendMessage: () => {{}},
                onMessage: {{ addListener: () => {{}} }}
            }},
            loadTimes: () => ({{}}),
            csi: () => ({{}})
        }};
        
        console.log('🛡️ Synchronized Stealth Mode Active');
        """
    
    def rotate(self):
        """Force fingerprint rotation"""
        self.session_id = str(uuid.uuid4())
        self.current_fingerprint = None
        self.fingerprint_created_at = 0
        return self.generate(force_new=True)

# Global fingerprint generator instance
FINGERPRINT_GENERATOR = DynamicFingerprintGenerator()

class AdvancedSecurityManager:
    """Enhanced security manager tanpa menghilangkan fitur existing"""
    
    def __init__(self):
        self.encryption_key = self._generate_key()
        self.request_fingerprints = {}
        self.security_level = "MAXIMUM"
        self.fingerprint_gen = FINGERPRINT_GENERATOR
        
    def _generate_key(self) -> str:
        """Generate encryption key"""
        return base64.urlsafe_b64encode(hashlib.sha256(str(time.time()).encode()).digest()).decode()
    
    def encrypt_sensitive_data(self, data: str) -> str:
        """Encrypt sensitive data"""
        return hashlib.sha256(f"{data}{self.encryption_key}".encode()).hexdigest()
    
    def generate_request_fingerprint(self) -> Dict[str, Any]:
        """Generate unique request fingerprint"""
        fp = self.fingerprint_gen.generate()
        fingerprint = {
            'timestamp': int(time.time() * 1000),
            'session_id': fp['session_id'],
            'random_seed': random.randint(100000, 999999),
            'user_agent': fp['user_agent'],
            'headers': fp['headers'],
        }
        return fingerprint
    
    def get_synchronized_fingerprint(self) -> Dict[str, Any]:
        """Get fully synchronized fingerprint"""
        return self.fingerprint_gen.generate()
    
    def get_stealth_script(self) -> str:
        """Get stealth script for current fingerprint"""
        fp = self.fingerprint_gen.generate()
        return self.fingerprint_gen.get_stealth_script(fp)
    
    def rotate_fingerprint(self):
        """Rotate to new fingerprint"""
        return self.fingerprint_gen.rotate()

class AntiDetectionManager:
    """Enhanced anti-detection tanpa menghilangkan fitur existing"""
    
    def __init__(self):
        self.request_timestamps = []
        self.suspicion_level = 0
        self.last_rotation = time.time()
        
    def calculate_smart_delay(self) -> float:
        """Calculate intelligent delay based on request patterns"""
        now = time.time()
        
        # Clean old timestamps
        self.request_timestamps = [ts for ts in self.request_timestamps if now - ts < 60]
        
        recent_requests = len(self.request_timestamps)
        
        # Base delay based on recent activity
        if recent_requests > 10:
            base_delay = random.uniform(3.0, 6.0)
        elif recent_requests > 5:
            base_delay = random.uniform(1.5, 3.0)
        else:
            base_delay = random.uniform(0.5, 1.5)
        
        # Add jitter
        jitter = random.uniform(0.7, 1.3)
        final_delay = base_delay * jitter
        
        # Record this request
        self.request_timestamps.append(now)
        
        return final_delay
    
    def should_rotate_fingerprint(self) -> bool:
        """Determine if fingerprint should be rotated"""
        time_since_rotation = time.time() - self.last_rotation
        return time_since_rotation > 300 or self.suspicion_level > 0.7 

# ---------------------- Utilities & small helpers ----------------------
def _now() -> float:
    return time.time()

def _random_hex(n: int = 8) -> str:
    return ''.join(random.choice('0123456789abcdef') for _ in range(n))

def _randint(a: int, b: int) -> int:
    return random.randint(a, b)

# ---------------------- SafeCookieJar ----------------------
class SafeCookieJar:
    def __init__(self):
        self._jar: Dict[str, Dict[str, Dict[str, Any]]] = {}
        self._lock = asyncio.Lock()

    def _normalize_domain(self, domain: Optional[str]) -> str:
        if not domain:
            return ""
        dom = domain.lower()
        if dom.startswith("."):
            dom = dom[1:]
        return dom

    async def set_cookie(self, domain: str, name: str, value: str, **attrs):
        domain = self._normalize_domain(domain)
        async with self._lock:
            d = self._jar.setdefault(domain, {})
            entry = {"value": value}
            entry["path"] = attrs.get("path", "/")
            entry["domain"] = self._normalize_domain(attrs.get("domain", domain))
            entry["secure"] = bool(attrs.get("secure", False))
            entry["httponly"] = bool(attrs.get("httponly", False))
            if "expires" in attrs:
                entry["expires"] = attrs["expires"]
            d[name] = entry

    async def update_from_set_cookie_header(self, domain: str, sc_header: str):
        domain_norm = self._normalize_domain(domain)
        cookie = SimpleCookie()
        try:
            cookie.load(sc_header)
        except Exception:
            return
        async with self._lock:
            parts = [p.strip() for p in re.split(r';\s*', sc_header) if p.strip()]
            attr_map: Dict[str, Any] = {}
            for part in parts[1:]:
                if "=" in part:
                    k, v = part.split("=", 1)
                    attr_map[k.strip().lower()] = v.strip()
                else:
                    attr_map[part.strip().lower()] = True
            for k, morsel in cookie.items():
                name = k
                value = morsel.value
                path = attr_map.get("path", "/")
                domain_attr = attr_map.get("domain")
                secure = "secure" in attr_map
                httponly = "httponly" in attr_map
                store_domain = self._normalize_domain(domain_attr or domain_norm)
                d = self._jar.setdefault(store_domain, {})
                d[name] = {"value": value, "path": path, "domain": store_domain, "secure": secure, "httponly": httponly}

    async def get_cookie_header(self, domain: str) -> Optional[str]:
        domain = self._normalize_domain(domain)
        async with self._lock:
            parts = domain.split(".")
            candidates = []
            for i in range(len(parts)):
                sub = ".".join(parts[i:])
                if sub in self._jar:
                    candidates.append(sub)
            candidates = sorted(candidates, key=lambda x: len(x), reverse=True)
            pairs = []
            for dom in candidates:
                for k, v in self._jar.get(dom, {}).items():
                    pairs.append(f"{k}={v['value']}")
            return "; ".join(pairs) if pairs else None

    async def get_cookie_value(self, domain_or_url: str, name: str) -> Optional[str]:
        from urllib.parse import urlparse
        if domain_or_url.startswith("http://") or domain_or_url.startswith("https://"):
            domain = urlparse(domain_or_url).hostname or domain_or_url
        else:
            domain = domain_or_url
        domain = self._normalize_domain(domain)
        async with self._lock:
            if domain in self._jar and name in self._jar[domain]:
                return self._jar[domain][name]["value"]
            parts = domain.split(".")
            for i in range(len(parts)):
                sub = ".".join(parts[i:])
                if sub in self._jar and name in self._jar[sub]:
                    return self._jar[sub][name]["value"]
        return None

    async def to_dict(self) -> Dict[str, Any]:
        async with self._lock:
            return json.loads(json.dumps(self._jar))

    async def merge_from_dict(self, payload: Dict[str, Any]):
        async with self._lock:
            for domain, cookies in (payload or {}).items():
                d = self._jar.setdefault(self._normalize_domain(domain), {})
                for k, v in cookies.items():
                    d[k] = v

# ---------------------- Proxy manager ----------------------
class ProxyManager:
    def __init__(self, verbose: bool = False):
        self._proxies: List[str] = []
        self._scores: Dict[str, float] = {}
        self._bad: set = set()
        self.verbose = verbose
        self._lock = asyncio.Lock()
        self._last_used: Dict[str, float] = {}
        self._ttl_seconds = 60 * 60
        # Enhanced features
        self.security_manager = AdvancedSecurityManager()
        self.anti_detection = AntiDetectionManager()

    async def add(self, p: str):
        async with self._lock:
            if p not in self._proxies:
                self._proxies.append(p)
                self._scores[p] = 100.0
                self._last_used[p] = _now()
                if self.verbose:
                    print("[ProxyManager] added %s", p)

    async def remove(self, p: str):
        async with self._lock:
            if p in self._proxies:
                self._proxies.remove(p)
                self._scores.pop(p, None)
                self._bad.discard(p)
                self._last_used.pop(p, None)
                if self.verbose:
                    print("[ProxyManager] removed %s", p)

    async def mark_bad(self, p: Optional[str], penalty: float = 30.0):
        if not p:
            return
        async with self._lock:
            self._bad.add(p)
            self._scores[p] = max(self._scores.get(p, 100.0) - penalty, 0.0)
            self._last_used[p] = _now()
            if self.verbose:
                logger.warning("[ProxyManager] marked bad %s score=%.1f", p, self._scores[p])

    async def score_success(self, p: Optional[str], bonus: float = 5.0):
        if not p:
            return
        async with self._lock:
            self._scores[p] = min(self._scores.get(p, 50.0) + bonus, 100.0)
            self._last_used[p] = _now()

    async def pick(self, auto_rotate: bool = True) -> Optional[str]:
        async with self._lock:
            candidates = [p for p in self._proxies if p not in self._bad]
            now = _now()
            for p in list(self._proxies):
                if p in self._last_used and (now - self._last_used[p]) > self._ttl_seconds:
                    try:
                        self._proxies.remove(p)
                        self._scores.pop(p, None)
                        self._last_used.pop(p, None)
                        if self.verbose:
                            print("[ProxyManager] evicted unused proxy %s", p)
                    except Exception:
                        pass
            if not candidates:
                return None
            candidates.sort(key=lambda x: self._scores.get(x, 0.0), reverse=True)
            top = candidates[:3] if len(candidates) > 3 and auto_rotate else candidates
            choice = random.choice(top)
            self._last_used[choice] = _now()
            return choice

    async def benchmark(self, urls: List[str], concurrency: int = 8, timeout: int = 6):
        if not self._proxies or not urls:
            return
        sem = asyncio.Semaphore(concurrency)
        async def _test(p):
            async with sem:
                start = _now()
                try:
                    async with aiohttp.ClientSession() as s:
                        async with s.get(urls[0], proxy=p, timeout=aiohttp.ClientTimeout(total=timeout)) as r:
                            await r.read()
                            t = _now() - start
                            return (p, t, r.status)
                except Exception as e:
                    return (p, None, str(e))
        tasks = [asyncio.create_task(_test(p)) for p in self._proxies]
        results = await asyncio.gather(*tasks, return_exceptions=False)
        async with self._lock:
            latencies = [r[1] for r in results if r[1] is not None]
            if latencies:
                max_lat = max(latencies)
                for p, t, status in results:
                    if t is None:
                        self._scores[p] = max(self._scores.get(p, 100.0) - 50.0, 0.0)
                    else:
                        score = max(1.0, 100.0 * (1.0 - (t / (max_lat * 1.2))))
                        self._scores[p] = (self._scores.get(p, 50.0) * 0.3) + (score * 0.7)
        if self.verbose:
            print("[ProxyManager] benchmark results: %s", self._scores)

# ---------------------- Header builder / Browser-like emulation ----------------------
COMMON_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36",
]
BROWSER_LIKE_BASE_HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
    "Cache-Control": "max-age=0",
}
OBFUSCATION_WHITELIST = set([
    "User-Agent", "Accept", "Accept-Language", "Referer", "Origin", "DNT", "X-Requested-With", "X-Client-Time"
])

class HeaderBuilder:
    def __init__(self, non_standard_obfuscation: bool = False, smart_headers_mode: Optional[str] = None):
        self.non_standard_obfuscation = non_standard_obfuscation
        self.smart_headers_mode = smart_headers_mode
        self._parent = None
        # Enhanced features
        self.security_manager = AdvancedSecurityManager()
        self.anti_detection = AntiDetectionManager()

    def _random_case(self, s: str) -> str:
        return ''.join(c.upper() if random.random() > 0.5 else c.lower() for c in s)

    def _fragment_value(self, v: str) -> str:
        if len(v) < 8:
            return v
        n = random.choice([1, 2])
        if n == 1:
            return v
        cut = max(1, len(v) // (n + 1))
        pieces = [v[i:i+cut] for i in range(0, len(v), cut)]
        return ", ".join(pieces[:n])

    def build(self, extra: Optional[Dict[str, str]] = None, common: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        ua = random.choice(COMMON_UAS)
        base = dict(BROWSER_LIKE_BASE_HEADERS)
        base["User-Agent"] = ua
        if common:
            base.update(common)
        if extra:
            base.update(extra)

        headers = {}
        for k, v in base.items():
            key_out = self._random_case(k) if self.non_standard_obfuscation and k in OBFUSCATION_WHITELIST and random.random() > 0.8 else k
            if self.non_standard_obfuscation and k in OBFUSCATION_WHITELIST and random.random() > 0.6:
                v_out = self._fragment_value(v)
            else:
                v_out = v
            headers[key_out] = v_out

        headers.setdefault("Connection", "keep-alive")
        
        # Enhanced: Add security headers
        fingerprint = self.security_manager.generate_request_fingerprint()
        headers["X-Session-ID"] = fingerprint['session_id']
        headers["X-Timestamp"] = str(fingerprint['timestamp'])
        
        return headers

# Attach effective UA behavior
def _generate_random_chrome_ua(self, platform: str = "windows") -> str:
    major = _randint(115, 130)
    build = _randint(3000, 9999)
    patch = _randint(0, 399)
    if platform == "android":
        device = random.choice(["SM-G991B","Pixel 7","Pixel 6","SM-A536B","Mi 11"])
        return f"Mozilla/5.0 (Linux; Android 13; {device}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{major}.0.{build}.{patch} Mobile Safari/537.36"
    if platform == "iphone":
        iosv = f"{_randint(15,17)}_{_randint(0,5)}"
        return f"Mozilla/5.0 (iPhone; CPU iPhone OS {iosv} like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/{_randint(15,17)}.0 Mobile/15E148 Safari/604.1"
    arch = random.choice(["Win64; x64","WOW64"])
    return f"Mozilla/5.0 (Windows NT 10.0; {arch}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{major}.0.{build}.{patch} Safari/537.36"

def _effective_user_agent(self, force_mode: Optional[str] = None) -> str:
    if getattr(self, "user_agent", None):
        return self.user_agent
    mode = (force_mode or getattr(self, "ua_mode", None) or "A").upper()
    if mode == "A":
        return COMMON_UAS[0]
    if mode == "B":
        return "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36"
    if mode == "C":
        return "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1"
    if mode == "D":
        return random.choice(COMMON_UAS + [_generate_random_chrome_ua(self, "windows"), _generate_random_chrome_ua(self, "android"), _generate_random_chrome_ua(self, "iphone")])
    if mode == "E":
        p = random.choice(["windows","android","iphone"])
        return _generate_random_chrome_ua(self, p)
    return COMMON_UAS[0]

setattr(HeaderBuilder, "_parent", None)
setattr(HeaderBuilder, "_generate_random_chrome_ua", _generate_random_chrome_ua)
setattr(HeaderBuilder, "_effective_user_agent", _effective_user_agent)

# -------------------- Playwright integration (optional) --------------------
try:
    from playwright.async_api import async_playwright, Browser, BrowserContext, Playwright
    HAVE_PLAYWRIGHT = True
except Exception:
    async_playwright = None
    Browser = None
    BrowserContext = None
    Playwright = None
    HAVE_PLAYWRIGHT = False

# ============================================================================
# CHROMIUM MANAGER - FIXED VERSION
# Updated: 2025-11-24 09:53:04 UTC
# Fixes: user_agent support, launch args, persistent context
# Author: qrxs5rycfq-dot
# ============================================================================

class UserAgentRotator:
    """Manage random user agent rotation"""
    
    def __init__(self):
        self.user_agents = [
            # Windows Chrome
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
            
            # Mac Chrome
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            
            # Linux Chrome
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
            
            # Edge
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
        ]
        self.used_agents = set()
    
    def get_random_ua(self):
        """Get random user agent yang belum digunakan baru-baru ini"""
        available_agents = [ua for ua in self.user_agents if ua not in self.used_agents]
        
        if not available_agents:
            # Reset jika semua sudah digunakan
            self.used_agents.clear()
            available_agents = self.user_agents
        
        selected_ua = random.choice(available_agents)
        self.used_agents.add(selected_ua)
        
        # Keep only last 5 used agents
        if len(self.used_agents) > 5:
            self.used_agents = set(list(self.used_agents)[-5:])
        
        return selected_ua

class ChromiumManager:
    """
    Enhanced ChromiumManager dengan security features tambahan
    """

    def __init__(self, verbose: bool = False, headless: bool = True, 
                 use_proxy: bool = False, proxy_url: Optional[str] = None):
        self._pw: Optional[Playwright] = None
        self._browser: Optional[Browser] = None
        self._browser_contexts: Dict[str, BrowserContext] = {}
        self._verbose = verbose
        self._lock = asyncio.Lock()
        self._headless = headless
        self._use_proxy = use_proxy
        self._proxy_url = proxy_url
        self._ua_rotator = UserAgentRotator()
        self._launched_browsers: List[Browser] = []
        # Enhanced security
        self.security_manager = AdvancedSecurityManager()
        self.anti_detection = AntiDetectionManager()

    async def start_playwright(self) -> bool:
        """Start Playwright instance dengan enhanced security"""
        if not HAVE_PLAYWRIGHT:
            raise RuntimeError("playwright not installed; run `pip install playwright` and `playwright install chromium`")
        
        try:
            if self._pw is None:
                self._pw = await async_playwright().start()
                if self._verbose:
                    print("[ChromiumManager] Playwright started with enhanced security")
            return True
        except Exception as e:
            logger.error("[ChromiumManager] Failed to start Playwright: %s", e)
            return False

    async def stop_playwright(self) -> bool:
        """Stop Playwright instance"""
        try:
            if self._pw:
                try:
                    await self._pw.stop()
                except Exception:
                    pass
                self._pw = None
                if self._verbose:
                    print("[ChromiumManager] Playwright stopped")
            return True
        except Exception as e:
            logger.error("[ChromiumManager] Error stopping Playwright: %s", e)
            return False

    def _get_launch_args(self) -> List[str]:
        """Get Chromium launch arguments dengan enhanced security"""
        
        args = [
            "--disable-dev-shm-usage",
            "--no-sandbox",
            "--disable-gpu",
            "--disable-web-resources",
            "--disable-sync",
            "--disable-extensions",
            "--disable-default-apps",
            "--disable-plugins",
            "--disable-plugins-power-saver",
            "--disable-popup-blocking",
            "--disable-prompt-on-repost",
            "--disable-background-networking",
            "--disable-default-apps",
            "--disable-hang-monitor",
            "--disable-preconnect",
            "--disable-translate",
            "--metrics-recording-only",
            "--mute-audio",
            "--no-default-browser-check",
            "--no-first-run",
            "--password-store=basic",
            "--use-mock-keychain",
            "--enable-automation",
            "--disable-component-extension-with-background-page",
            "--disable-breakpad",
            "--disable-client-side-phishing-detection",
            "--disable-component-extensions-with-background-pages",
            "--disable-default-apps",
            "--disable-device-discovery-notifications",
            "--disable-feature=IsolateOrigins,site-per-process",
            # Enhanced security args
            "--disable-blink-features=AutomationControlled",
            "--disable-features=VizDisplayCompositor",
            "--disable-ipc-flooding-protection",
            "--disable-renderer-backgrounding",
            "--disable-backgrounding-occluded-windows",
        ]
        
        return args

    async def new_browser_context(self, user_agent: Optional[str] = None,
                                 viewport: Optional[Dict[str, int]] = None,
                                 proxy: Optional[str] = None,
                                 locale: str = "en-US",
                                 timezone: str = "America/New_York",
                                 context_id: Optional[str] = None) -> Optional[BrowserContext]:
        """
        Create new non-persistent browser context dengan UA rotation
        """
        
        try:
            await self.start_playwright()
            
            async with self._lock:
                # Launch browser jika belum
                if self._browser is None:
                    launch_args = self._get_launch_args()
                    
                    launch_options = {
                        "headless": self._headless,
                        "args": launch_args,
                    }
                    
                    proxy_to_use = proxy or self._proxy_url
                    if proxy_to_use:
                        launch_options["proxy"] = {"server": proxy_to_use}
                    
                    self._browser = await self._pw.chromium.launch(**launch_options)
                    self._launched_browsers.append(self._browser)
                
                # FORCE UA ROTATION - selalu gunakan random UA
                if user_agent is None:
                    user_agent = self._ua_rotator.get_random_ua()
                
                self._session_counter += 1
                print(f"   🔄 Session {self._session_counter} - UA: {user_agent[:50]}...")
                
                # Create context options
                context_options = {
                    "user_agent": user_agent,
                    "locale": locale,
                    "timezone_id": timezone,
                }
                
                if viewport is None:
                    context_options["viewport"] = viewport
                else:
                    # Random viewport juga
                    viewports = [
                        {"width": 1920, "height": 1080},
                        {"width": 1366, "height": 768},
                        {"width": 1440, "height": 900},
                        {"width": 1536, "height": 864}
                    ]
                    context_options["viewport"] = random.choice(viewports)
                
                if proxy and not self._proxy_url:
                    context_options["proxy"] = {"server": proxy}
                
                # Create context
                context = await self._browser.new_context(**context_options)
                
                # Store with ID
                ctx_id = context_id or f"session_{self._session_counter}_{int(time.time())}"
                self._browser_contexts[ctx_id] = context
                
                # Enhanced stealth
                await self._add_enhanced_stealth_scripts(context)
                
                if self._verbose:
                    print(f"[ChromiumManager] ✅ Browser context created: {ctx_id}")
                    print(f"[ChromiumManager] 🔄 User Agent: {user_agent[:80]}...")
                    print(f"[ChromiumManager] 📐 Viewport: {context_options['viewport']}")
                
                return context
        
        except Exception as e:
            logger.error(f"[ChromiumManager] Failed to create browser context: {e}", exc_info=True)
            return None

    async def new_persistent_context(self, profile_dir: str, 
                                     user_agent: Optional[str] = None, 
                                     viewport: Optional[Dict[str, int]] = None,
                                     proxy: Optional[str] = None,
                                     locale: str = "en-US",
                                     timezone: str = "America/New_York") -> Optional[BrowserContext]:
        """
        Create new persistent context dengan enhanced security
        """
        
        try:
            await self.start_playwright()
            
            async with self._lock:
                if profile_dir in self._browser_contexts:
                    if self._verbose:
                        logger.debug("[ChromiumManager] Returning existing context for %s", profile_dir)
                    return self._browser_contexts[profile_dir]
                
                if self._verbose:
                    print("[ChromiumManager] Creating persistent context: %s", profile_dir)
                
                os.makedirs(profile_dir, exist_ok=True)
                
                launch_args = self._get_launch_args()
                
                context_options = {
                    "headless": self._headless,
                    "args": launch_args,
                    "user_data_dir": profile_dir,
                }
                
                if user_agent:
                    context_options["user_agent"] = user_agent
                    if self._verbose:
                        logger.debug("[ChromiumManager] User-Agent: %s", user_agent[:50])
                
                if viewport:
                    context_options["viewport"] = viewport
                    if self._verbose:
                        logger.debug("[ChromiumManager] Viewport: %dx%d", 
                                   viewport.get("width", 1440), viewport.get("height", 900))
                
                proxy_to_use = proxy or self._proxy_url
                if proxy_to_use:
                    context_options["proxy"] = {
                        "server": proxy_to_use
                    }
                    if self._verbose:
                        logger.debug("[ChromiumManager] Proxy: %s", proxy_to_use[:50])
                
                context_options["locale"] = locale
                context_options["timezone_id"] = timezone
                
                if self._verbose:
                    logger.debug("[ChromiumManager] Locale: %s, Timezone: %s", locale, timezone)
                
                chromium = self._pw.chromium
                context = await chromium.launch_persistent_context(**context_options)
                
                # Enhanced: Add stealth scripts
                await self._add_stealth_scripts(context)
                
                self._browser_contexts[profile_dir] = context
                
                if self._verbose:
                    print("[ChromiumManager] ✅ Persistent context created: %s", profile_dir)
                
                return context
        
        except Exception as e:
            logger.error("[ChromiumManager] Failed to create persistent context: %s", e, exc_info=True)
            return None

    async def _add_stealth_scripts(self, context: BrowserContext):
        """Add enhanced stealth scripts to context with comprehensive fingerprint spoofing"""
        try:
            # Get IP configuration with comprehensive spoofing data
            ip_config = IP_STEALTH_SYSTEM.get_fresh_ip_config()
            device_fp = ip_config.get("device_fingerprint", {})
            
            # Get WebRTC/WebGL fingerprint
            brand = device_fp.get("brand", "Samsung").lower()
            device_type = "android"
            connection_type = ip_config.get("connection_type", "mobile")
            webrtc_webgl_fp = WEBRTC_WEBGL_SPOOFER.get_complete_fingerprint(device_type, brand, connection_type)
            
            # Add comprehensive stealth injection script
            comprehensive_script = WEBRTC_WEBGL_SPOOFER.get_stealth_injection_script(webrtc_webgl_fp)
            await context.add_init_script(comprehensive_script)
            
            print(f"🛡️ [ChromiumManager] Comprehensive fingerprint spoofing applied")
        except Exception as e:
            # Fallback to basic stealth script
            stealth_script = """
            // Remove webdriver property
            Object.defineProperty(navigator, 'webdriver', {
                get: () => undefined,
            });

            // Remove automation controlled
            Object.defineProperty(navigator, 'automationControlled', {
                get: () => undefined,
            });

            // Mock permissions
            const originalQuery = window.navigator.permissions.query;
            window.navigator.permissions.query = (parameters) => (
                parameters.name === 'notifications' ?
                    Promise.resolve({ state: Notification.permission }) :
                    originalQuery(parameters)
            );

            // Mock plugins
            Object.defineProperty(navigator, 'plugins', {
                get: () => [1, 2, 3, 4, 5],
            });

            // Mock languages
            Object.defineProperty(navigator, 'languages', {
                get: () => ['en-US', 'en'],
            });

            // Mock hardware concurrency
            Object.defineProperty(navigator, 'hardwareConcurrency', {
                get: () => 8,
            });

            console.log('Stealth mode activated');
            """
            
            await context.add_init_script(stealth_script)

    async def new_browser_context(self, user_agent: Optional[str] = None,
                                 viewport: Optional[Dict[str, int]] = None,
                                 proxy: Optional[str] = None,
                                 locale: str = "en-US",
                                 timezone: str = "America/New_York",
                                 context_id: Optional[str] = None) -> Optional[BrowserContext]:
        """
        Create new non-persistent browser context
        
        ✅ For cases where profile persistence not needed
        """
        
        try:
            await self.start_playwright()
            
            async with self._lock:
                # Launch browser jika belum
                if self._browser is None:
                    launch_args = self._get_launch_args()
                    
                    launch_options = {
                        "headless": self._headless,
                        "args": launch_args,
                    }
                    
                    # Add proxy jika provided
                    proxy_to_use = proxy or self._proxy_url
                    if proxy_to_use:
                        launch_options["proxy"] = {
                            "server": proxy_to_use
                        }
                    
                    self._browser = await self._pw.chromium.launch(**launch_options)
                    self._launched_browsers.append(self._browser)
                
                # Create context options
                context_options = {}
                
                if user_agent:
                    context_options["user_agent"] = user_agent
                
                if viewport:
                    context_options["viewport"] = viewport
                
                if proxy and not self._proxy_url:  # Only if not set globally
                    context_options["proxy"] = {
                        "server": proxy
                    }
                
                context_options["locale"] = locale
                context_options["timezone_id"] = timezone
                
                # Create context
                context = await self._browser.new_context(**context_options)
                
                # Store with ID
                ctx_id = context_id or str(uuid.uuid4())
                self._browser_contexts[ctx_id] = context
                
                if self._verbose:
                    print("[ChromiumManager] ✅ Browser context created: %s", ctx_id)
                
                return context
        
        except Exception as e:
            logger.error("[ChromiumManager] Failed to create browser context: %s", e, exc_info=True)
            return None

    async def close_context(self, profile_dir: str) -> bool:
        """Close specific context"""
        try:
            async with self._lock:
                ctx = self._browser_contexts.pop(profile_dir, None)
                if ctx:
                    try:
                        await ctx.close()
                    except Exception:
                        pass
                    
                    if self._verbose:
                        print("[ChromiumManager] Closed context: %s", profile_dir)
                    
                    return True
            
            return False
        
        except Exception as e:
            logger.error("[ChromiumManager] Error closing context: %s", e)
            return False

    async def close_all(self) -> bool:
        """Close all contexts & stop Playwright"""
        try:
            async with self._lock:
                for profile_dir, ctx in list(self._browser_contexts.items()):
                    try:
                        await ctx.close()
                    except Exception:
                        pass
                
                self._browser_contexts.clear()
                
                for browser in self._launched_browsers:
                    try:
                        await browser.close()
                    except Exception:
                        pass
                
                self._launched_browsers.clear()
                self._browser = None
            
            await self.stop_playwright()
            
            if self._verbose:
                print("[ChromiumManager] ✅ All contexts & Playwright closed")
            
            return True
        
        except Exception as e:
            logger.error("[ChromiumManager] Error closing all: %s", e)
            return False

    def get_context(self, profile_dir: str) -> Optional[BrowserContext]:
        """Get context synchronously"""
        return self._browser_contexts.get(profile_dir)

    async def get_context_async(self, profile_dir: str) -> Optional[BrowserContext]:
        """Get context asynchronously"""
        async with self._lock:
            return self._browser_contexts.get(profile_dir)

    def list_contexts(self) -> List[str]:
        """List all active contexts"""
        return list(self._browser_contexts.keys())

    async def get_context_info(self, profile_dir: str) -> Optional[Dict[str, Any]]:
        """Get context information"""
        ctx = self.get_context(profile_dir)
        if not ctx:
            return None
        
        try:
            return {
                "profile_dir": profile_dir,
                "pages": len(ctx.pages),
                "cookies": len(await ctx.cookies()),
                "storage_state_available": True,
            }
        except Exception as e:
            logger.error("[ChromiumManager] Error getting context info: %s", e)
            return None

    async def save_storage_state(self, profile_dir: str, state_file: str) -> bool:
        """Save context storage state (cookies, storage, etc.)"""
        try:
            ctx = self.get_context(profile_dir)
            if not ctx:
                logger.error("[ChromiumManager] Context not found: %s", profile_dir)
                return False
            
            storage_state = await ctx.storage_state()
            
            os.makedirs(os.path.dirname(state_file) or ".", exist_ok=True)
            
            with open(state_file, "w", encoding="utf-8") as f:
                json.dump(storage_state, f, ensure_ascii=False, indent=2)
            
            if self._verbose:
                print("[ChromiumManager] Storage state saved: %s", state_file)
            
            return True
        
        except Exception as e:
            logger.error("[ChromiumManager] Error saving storage state: %s", e)
            return False

    async def load_storage_state(self, profile_dir: str, state_file: str) -> bool:
        """Load context storage state"""
        try:
            ctx = self.get_context(profile_dir)
            if not ctx:
                logger.error("[ChromiumManager] Context not found: %s", profile_dir)
                return False
            
            if not os.path.exists(state_file):
                logger.error("[ChromiumManager] Storage state file not found: %s", state_file)
                return False
            
            with open(state_file, "r", encoding="utf-8") as f:
                storage_state = json.load(f)
            
            # Add cookies
            if "cookies" in storage_state:
                await ctx.add_cookies(storage_state["cookies"])
            
            # Add local storage, session storage, etc. via script
            if "origins" in storage_state:
                for origin_data in storage_state["origins"]:
                    page = await ctx.new_page()
                    try:
                        await page.goto(origin_data.get("origin", "about:blank"))
                        
                        # Set local storage
                        if "localStorage" in origin_data:
                            for item in origin_data["localStorage"]:
                                await page.evaluate(
                                    f"localStorage.setItem('{item['name']}', '{item['value']}')"
                                )
                    finally:
                        await page.close()
            
            if self._verbose:
                print("[ChromiumManager] Storage state loaded: %s", state_file)
            
            return True
        
        except Exception as e:
            logger.error("[ChromiumManager] Error loading storage state: %s", e)
            return False

    async def take_screenshot(self, profile_dir: str, output_file: str) -> bool:
        """Take screenshot dari context"""
        try:
            ctx = self.get_context(profile_dir)
            if not ctx or not ctx.pages:
                logger.error("[ChromiumManager] No pages in context: %s", profile_dir)
                return False
            
            page = ctx.pages[0]
            
            os.makedirs(os.path.dirname(output_file) or ".", exist_ok=True)
            try:
                await page.screenshot(path=output_file, full_page=True)
            except Exception as e:
                logger.error("[ChromiumManager] Screenshot failed: %s", e)
                return False
            
            if self._verbose:
                print("[ChromiumManager] Screenshot saved: %s", output_file)
            
            return True
        
        except Exception as e:
            logger.error("[ChromiumManager] Error taking screenshot: %s", e)
            return False

    def get_browser_info(self) -> Dict[str, Any]:
        """Get browser information"""
        return {
            "headless": self._headless,
            "use_proxy": self._use_proxy,
            "proxy_url": self._proxy_url,
            "contexts_count": len(self._browser_contexts),
            "contexts": self.list_contexts(),
            "browsers_count": len(self._launched_browsers),
        }


# ============================================================================
# UPDATE Account class untuk use enhanced ChromiumManager
# ============================================================================

# DALAM class Account.__init__(), update bagian Chromium initialization:

        # ========== CHROMIUM SPECIFIC (UPDATED) ==========
        self.chromium_manager: Optional[ChromiumManager] = None
        self.use_chromium_for_signup: bool = use_chromium
        self.chromium_profile_dir: str = "./chromium_profiles/account"

# REPLACE METHOD _init_chromium_manager():

    async def _init_chromium_manager(self) -> bool:
        """Initialize ChromiumManager dengan enhanced features"""
        try:
            if not self.chromium_manager:
                self.chromium_manager = ChromiumManager(
                    verbose=self.verbose,
                    headless=True,
                    use_proxy=self.bound_proxy is not None,
                    proxy_url=self.bound_proxy
                )
            
            if self.verbose:
                print("[_init_chromium_manager] ✅ ChromiumManager initialized")
            
            return True
        except Exception as e:
            logger.error("[_init_chromium_manager] Error: %s", e)
            return False

# REPLACE METHOD start_chromium():

    async def start_chromium(self, profile_dir: Optional[str] = None) -> bool:
        """Start Chromium dengan ChromiumManager enhanced"""
        
        if self.chromium_started:
            logger.warning("[start_chromium] Chromium already started")
            return True
        
        try:
            # Initialize manager
            if not await self._init_chromium_manager():
                return False
            
            profile_dir = profile_dir or self.chromium_profile_dir
            os.makedirs(profile_dir, exist_ok=True)
            
            # ✅ Use fingerprint dari HTTP session
            user_agent = self._ua_rotator.get_random_ua()
            
            # Get viewport dari header builder
            viewport = None
            if self.hb:
                viewports = random.choice([
                        {"width": 1920, "height": 1080},
                        {"width": 1366, "height": 768},
                        {"width": 1440, "height": 900},
                        {"width": 1536, "height": 864}
                    ])
            
            if self.verbose:
                print("[start_chromium] Starting with:")
                print("  - UA: %s", user_agent[:50] if user_agent else "default")
                print("  - Viewport: %s", viewport)
                print("  - Proxy: %s", self.bound_proxy[:50] if self.bound_proxy else "none")
            
            # Create persistent context
            self.browser_context = await self.chromium_manager.new_persistent_context(
                profile_dir=profile_dir,
                user_agent=user_agent,
                viewport=viewport,
                proxy=self.bound_proxy,
                locale="en-US",
                timezone="America/New_York"
            )
            
            if not self.browser_context:
                logger.error("[start_chromium] Failed to create context")
                return False
            
            # ✅ Inject stealth script
            await self.browser_context.add_init_script(self._get_stealth_script())
            
            self.chromium_started = True
            
            if self.verbose:
                print("[start_chromium] ✅ Chromium started successfully")
                print("[start_chromium] Context info: %s", 
                          await self.chromium_manager.get_context_info(profile_dir))
            
            return True
        
        except Exception as e:
            logger.error("[start_chromium] Error: %s", e, exc_info=True)
            self.chromium_started = False
            return False

# REPLACE METHOD stop_chromium():

    async def stop_chromium(self) -> bool:
        """Stop Chromium gracefully"""
        
        try:
            if self.chromium_manager:
                # Save storage state sebelum close
                if self.username:
                    try:
                        state_file = f"./chromium_profiles/states/{self.username}.json"
                        await self.chromium_manager.save_storage_state(
                            self.chromium_profile_dir, state_file
                        )
                    except Exception:
                        pass
                
                # Close all contexts
                await self.chromium_manager.close_all()
                self.chromium_started = False
                
                if self.verbose:
                    print("[stop_chromium] ✅ Chromium stopped")
            
            return True
        except Exception as e:
            logger.error("[stop_chromium] Error: %s", e)
            return False

class UltimateAntiDetectionManager:
    """Ultimate anti-detection manager untuk semua scenario (proxy/no-proxy)"""
    
    def __init__(self):
        self.behavior_patterns = []
        self.fingerprint_rotation_count = 0
        self.last_rotation = time.time()
    
    def generate_ultimate_fingerprint(self, is_proxy: bool = False):
        """Generate ultimate fingerprint dengan residential patterns"""
        
        # Residential viewports (real user devices)
        residential_viewports = [
            {'width': 1920, 'height': 1080},  # Desktop
            {'width': 1366, 'height': 768},   # Laptop
            {'width': 1536, 'height': 864},   # Modern Laptop
            {'width': 1440, 'height': 900},   # Macbook
            {'width': 1280, 'height': 720},   # Lower res
            {'width': 1600, 'height': 900},   # Desktop
        ]
        
        # Real residential user agents (updated 2024)
        residential_user_agents = [
            # Chrome Windows (most common)
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36',
            
            # Chrome Mac
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
            
            # Firefox Windows
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0',
            
            # Safari Mac
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15',
        ]
        
        # Residential timezones (global distribution)
        residential_timezones = [
            'America/New_York', 'America/Chicago', 'America/Denver', 'America/Los_Angeles',
            'Europe/London', 'Europe/Paris', 'Europe/Berlin', 'Europe/Moscow',
            'Asia/Tokyo', 'Asia/Shanghai', 'Asia/Singapore', 'Asia/Dubai',
            'Australia/Sydney', 'Australia/Melbourne'
        ]
        
        # Residential locales
        residential_locales = ['en-US', 'en-GB', 'en-CA', 'en-AU', 'fr-FR', 'de-DE', 'ja-JP', 'zh-CN']
        
        # Hardware profiles (realistic combinations)
        hardware_profiles = [
            {'concurrency': 4, 'memory': 4, 'platform': 'Win32'},
            {'concurrency': 8, 'memory': 8, 'platform': 'Win32'},
            {'concurrency': 12, 'memory': 16, 'platform': 'Win32'},
            {'concurrency': 8, 'memory': 8, 'platform': 'MacIntel'},
            {'concurrency': 12, 'memory': 16, 'platform': 'MacIntel'},
        ]
        
        hardware = random.choice(hardware_profiles)
        
        return {
            'viewport': random.choice(residential_viewports),
            'user_agent': random.choice(residential_user_agents),
            'timezone': random.choice(residential_timezones),
            'locale': random.choice(residential_locales),
            'hardware_concurrency': hardware['concurrency'],
            'device_memory': hardware['memory'],
            'platform': hardware['platform'],
            'connection_type': random.choice(['wifi', 'ethernet', 'cellular']),
            'effective_type': random.choice(['4g', '3g', '2g']),
        }
    
    def calculate_behavior_delay(self, action_type: str, is_proxy: bool = False) -> float:
        """Calculate intelligent delays berdasarkan action type"""
        
        base_delays = {
            'navigation': (3.0, 8.0),
            'form_fill': (0.5, 2.0),
            'click': (0.2, 1.0),
            'page_load': (2.0, 5.0),
            'otp_wait': (10.0, 20.0),
        }
        
        min_delay, max_delay = base_delays.get(action_type, (1.0, 3.0))
        
        # Add variation untuk pattern avoidance
        if len(self.behavior_patterns) > 2:
            recent_avg = sum(self.behavior_patterns[-3:]) / 3
            # Avoid repetitive patterns
            if abs((max_delay + min_delay) / 2 - recent_avg) < 0.5:
                min_delay += random.uniform(0.5, 1.5)
                max_delay += random.uniform(0.5, 1.5)
        
        delay = random.uniform(min_delay, max_delay)
        self.behavior_patterns.append(delay)
        
        # Keep only recent patterns
        if len(self.behavior_patterns) > 10:
            self.behavior_patterns.pop(0)
        
        return delay
    
    def should_rotate_fingerprint(self) -> bool:
        """Determine jika perlu rotate fingerprint"""
        current_time = time.time()
        time_since_rotation = current_time - self.last_rotation
        
        # Rotate setiap 30-60 menit atau setelah 10 actions
        if (time_since_rotation > random.randint(1800, 3600) or 
            self.fingerprint_rotation_count >= 10):
            return True
        return False
    
    def record_rotation(self):
        """Record fingerprint rotation"""
        self.fingerprint_rotation_count = 0
        self.last_rotation = time.time()
    
    def record_action(self):
        """Record action untuk rotation logic"""
        self.fingerprint_rotation_count += 1

class UltimateChromiumManager:
    """
    Ultimate ChromiumManager dengan comprehensive anti-detection
    Bekerja efektif DENGAN atau TANPA proxy
    """

    def __init__(self, 
                 verbose: bool = False, 
                 headless: bool = True,
                 use_proxy: bool = False, 
                 proxy_url: Optional[str] = None,
                 enable_ultimate_stealth: bool = True,
                 max_contexts: int = 5):
        
        self._pw: Optional[Playwright] = None
        self._browser: Optional[Browser] = None
        self._browser_contexts: Dict[str, BrowserContext] = {}
        self._verbose = verbose
        self._lock = asyncio.Lock()
        self._headless = headless
        self._use_proxy = use_proxy
        self._proxy_url = proxy_url
        self._enable_ultimate_stealth = enable_ultimate_stealth
        self._max_contexts = max_contexts
        self._launched_browsers: List[Browser] = []
        
        # Ultimate anti-detection components
        self.anti_detection = UltimateAntiDetectionManager()
        self.security_metrics = {
            'total_rotations': 0,
            'blocked_requests': 0,
            'successful_navigations': 0,
            'detection_events': 0
        }

    def _get_ultimate_launch_args(self, is_proxy: bool = False) -> List[str]:
        """Get ultimate launch arguments untuk anti-detection"""
        
        base_args = [
            # === CORE SECURITY ===
            "--disable-dev-shm-usage",
            "--no-sandbox",
            "--disable-gpu",
            "--disable-web-resources",
            "--disable-sync",
            "--disable-extensions",
            "--disable-default-apps",
            "--disable-plugins",
            "--disable-plugins-power-saver",
            "--disable-popup-blocking",
            "--disable-prompt-on-repost",
            "--disable-background-networking",
            "--disable-hang-monitor",
            "--disable-preconnect",
            "--disable-translate",
            "--metrics-recording-only",
            "--mute-audio",
            "--no-default-browser-check",
            "--no-first-run",
            "--password-store=basic",
            "--use-mock-keychain",
            
            # === ADVANCED ANTI-DETECTION ===
            "--disable-blink-features=AutomationControlled",
            "--disable-features=VizDisplayCompositor,IsolateOrigins,site-per-process",
            "--disable-ipc-flooding-protection",
            "--disable-renderer-backgrounding",
            "--disable-backgrounding-occluded-windows",
            "--disable-component-update",
            "--disable-background-timer-throttling",
            "--disable-client-side-phishing-detection",
            "--disable-component-extensions-with-background-pages",
            "--disable-device-discovery-notifications",
            
            # === NETWORK OPTIMIZATION ===
            "--aggressive-cache-discard",
            "--max_old_space_size=4096",
            "--disable-web-gl",
            "--disable-threaded-animation",
            "--disable-threaded-scrolling",
            "--disable-checker-imaging",
            "--disable-partial-raster",
            "--disable-skia-runtime-opts",
            
            # === FINGERPRINT EVASION ===
            "--disable-features=AudioServiceOutOfProcess,TranslateUI,BlinkGenPropertyTrees",
            "--disable-site-isolation-trials",
            "--disable-web-security",
            "--allow-running-insecure-content",
            "--hide-scrollbars",
            "--disable-remote-fonts",
            "--disable-logging",
            "--disable-java",
        ]
        
        # Additional args untuk residential realism
        residential_args = [
            "--enable-features=NetworkService,NetworkServiceInProcess",
            "--disable-features=msPerformanceManagerMetricsCollection",
            "--disable-back-forward-cache",
            "--disable-component-extensions-with-background-pages",
            "--disable-default-apps",
            "--disable-print-preview",
        ]
        
        return base_args + residential_args

    def _get_ultimate_stealth_script(self) -> str:
        """Return ultimate stealth script dengan comprehensive protection"""
        return """
        // === ULTIMATE STEALTH MODE - COMPREHENSIVE PROTECTION ===
        
        // === WEBDRIVER DETECTION REMOVAL ===
        Object.defineProperty(navigator, 'webdriver', {
            get: () => undefined,
            configurable: true,
            enumerable: true
        });
        
        // Remove all automation properties
        delete navigator.__proto__.webdriver;
        window.cdc_adoQpoasnfa76pfcZLmcfl_Array = undefined;
        window.cdc_adoQpoasnfa76pfcZLmcfl_Promise = undefined;
        window.cdc_adoQpoasnfa76pfcZLmcfl_Symbol = undefined;
        
        // === CHROME RUNTIME MOCKING ===
        const randomChromeVersion = '120.0.0.' + Math.floor(Math.random() * 1000);
        window.chrome = {
            runtime: {
                id: 'mock' + Math.random().toString(36).substring(2, 15),
                getManifest: () => ({ 
                    version: randomChromeVersion,
                    manifest_version: 3 
                }),
                onInstalled: { addListener: () => {} },
                onMessage: { addListener: () => {} },
                onConnect: { addListener: () => {} },
                onStartup: { addListener: () => {} },
                connect: () => ({ 
                    postMessage: () => {},
                    onMessage: { addListener: () => {} },
                    onDisconnect: { addListener: () => {} },
                    name: 'mock_connection'
                }),
                sendMessage: () => Promise.resolve({}),
                getURL: (path) => 'chrome-extension://mock/' + path,
            },
            loadTimes: () => ({
                requestTime: Date.now() - Math.random() * 10000,
                firstPaintTime: Date.now() - Math.random() * 5000,
                finishDocumentLoadTime: Date.now() - Math.random() * 3000,
                finishLoadTime: Date.now() - Math.random() * 2000,
                navigationType: 'Reload',
                commitLoadTime: Date.now() - Math.random() * 4000,
                firstPaintAfterLoadTime: 0,
                wasFetchedViaSpdy: false,
                wasNpnNegotiated: true,
                npnNegotiatedProtocol: 'h2',
                wasAlternateProtocolAvailable: false,
                connectionInfo: 'h2'
            }),
            csi: () => ({
                onloadT: Date.now() - Math.random() * 5000,
                pageT: Math.random() * 1000 + 500,
                startE: Date.now() - Math.random() * 10000,
                tran: Math.random() > 0.5 ? 15 : 25
            }),
            app: {
                isInstalled: false,
                InstallState: 'DISABLED',
                RunningState: 'STOPPED',
                getDetails: () => null
            },
            tabs: {
                getCurrent: () => Promise.resolve({ id: Math.floor(Math.random() * 1000) })
            }
        };

        // === PERMISSIONS API OVERRIDE ===
        const originalQuery = window.navigator.permissions.query;
        window.navigator.permissions.query = (parameters) => {
            // Block automation detection
            if (parameters.name === 'notifications') {
                return Promise.resolve({ state: 'denied' });
            }
            if (parameters.name === 'geolocation') {
                return Promise.resolve({ state: 'prompt' });
            }
            return originalQuery(parameters);
        };

        // === PLUGINS & MIMETYPES RANDOMIZATION ===
        const pluginNames = ['Chrome PDF Plugin', 'Chrome PDF Viewer', 'Native Client'];
        Object.defineProperty(navigator, 'plugins', {
            get: () => {
                const plugins = [];
                const count = Math.floor(Math.random() * 2) + 2; // 2-3 plugins
                for (let i = 0; i < count; i++) {
                    plugins.push({
                        name: pluginNames[i] || `Plugin ${i}`,
                        filename: `internal-pdf-viewer`,
                        description: `Portable Document Format`,
                        length: 1
                    });
                }
                return plugins;
            },
            configurable: true,
            enumerable: true
        });

        Object.defineProperty(navigator, 'mimeTypes', {
            get: () => {
                const mimeTypes = [];
                const types = ['application/pdf', 'text/pdf'];
                for (let type of types) {
                    mimeTypes.push({
                        type: type,
                        suffixes: 'pdf',
                        description: 'Portable Document Format',
                        enabledPlugin: navigator.plugins[0]
                    });
                }
                return mimeTypes;
            },
            configurable: true,
            enumerable: true
        });

        // === HARDWARE FINGERPRINT RANDOMIZATION ===
        const hardwareConcurrencies = [4, 6, 8, 12, 16];
        Object.defineProperty(navigator, 'hardwareConcurrency', {
            get: () => hardwareConcurrencies[Math.floor(Math.random() * hardwareConcurrencies.length)],
            configurable: true,
            enumerable: true
        });

        const deviceMemories = [4, 8, 16];
        Object.defineProperty(navigator, 'deviceMemory', {
            get: () => deviceMemories[Math.floor(Math.random() * deviceMemories.length)],
            configurable: true,
            enumerable: true
        });

        const platforms = ['Win32', 'MacIntel', 'Linux x86_64'];
        Object.defineProperty(navigator, 'platform', {
            get: () => platforms[Math.floor(Math.random() * platforms.length)],
            configurable: true,
            enumerable: true
        });

        // === NETWORK INFORMATION RANDOMIZATION ===
        Object.defineProperty(navigator, 'connection', {
            get: () => ({
                downlink: Math.random() * 10 + 5,
                effectiveType: ["4g", "3g", "2g"][Math.floor(Math.random() * 3)],
                rtt: Math.floor(Math.random() * 100) + 50,
                saveData: false,
                type: ['wifi', 'ethernet', 'cellular'][Math.floor(Math.random() * 3)],
                onchange: null,
                addEventListener: () => {},
                removeEventListener: () => {}
            }),
            configurable: true,
            enumerable: true
        });

        // === CANVAS FINGERPRINT PROTECTION ===
        const originalGetContext = HTMLCanvasElement.prototype.getContext;
        HTMLCanvasElement.prototype.getContext = function(contextType, ...args) {
            const context = originalGetContext.call(this, contextType, ...args);
            
            if (contextType === '2d') {
                // Override toDataURL
                const originalToDataURL = context.toDataURL;
                context.toDataURL = function(type, quality) {
                    const canvas = document.createElement('canvas');
                    canvas.width = this.canvas.width;
                    canvas.height = this.canvas.height;
                    const ctx = canvas.getContext('2d');
                    ctx.drawImage(this.canvas, 0, 0);
                    
                    // Add slight noise
                    const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
                    for (let i = 0; i < imageData.data.length; i += 10) {
                        imageData.data[i] = imageData.data[i] + (Math.random() * 10 - 5);
                    }
                    ctx.putImageData(imageData, 0, 0);
                    
                    return originalToDataURL.call(canvas, type, quality);
                };
                
                // Add noise to fillText
                const originalFillText = context.fillText;
                context.fillText = function(...args) {
                    args[1] = args[1] + (Math.random() * 0.5 - 0.25);
                    args[2] = args[2] + (Math.random() * 0.5 - 0.25);
                    return originalFillText.apply(this, args);
                };
            }
            return context;
        };

        // === WEBGL FINGERPRINT PROTECTION ===
        if (typeof WebGLRenderingContext !== 'undefined') {
            const getParameter = WebGLRenderingContext.prototype.getParameter;
            WebGLRenderingContext.prototype.getParameter = function(parameter) {
                if (parameter === 37445) return 'Google Inc. (NVIDIA)';
                if (parameter === 37446) return 'ANGLE (NVIDIA, NVIDIA GeForce RTX 3060)';
                if (parameter === 3415) return 'WebKit WebGL';
                if (parameter === 3414) return 'WebKit WebGL';
                return getParameter.call(this, parameter);
            };
        }

        // === AUDIO CONTEXT FINGERPRINT PROTECTION ===
        if (typeof AudioContext !== 'undefined') {
            const originalGetChannelData = AudioBuffer.prototype.getChannelData;
            AudioBuffer.prototype.getChannelData = function() {
                const data = originalGetChannelData.apply(this, arguments);
                // Add minimal noise
                for (let i = 0; i < data.length; i += 100) {
                    data[i] += (Math.random() - 0.5) * 0.0001;
                }
                return data;
            };
        }

        // === TIMEZONE & LOCALE PROTECTION ===
        const originalGetTimezoneOffset = Date.prototype.getTimezoneOffset;
        Date.prototype.getTimezoneOffset = function() {
            const offset = originalGetTimezoneOffset.call(this);
            return offset + Math.floor(Math.random() * 60 - 30);
        };

        // === CONSOLE CLEANUP ===
        const originalLog = console.log;
        console.log = function(...args) {
            if (args[0] && typeof args[0] === 'string') {
                if (args[0].includes('webdriver') || 
                    args[0].includes('automation') ||
                    args[0].includes('chromedriver')) {
                    return;
                }
            }
            originalLog.apply(console, args);
        };

        // === NOTIFICATION API OVERRIDE ===
        const OriginalNotification = window.Notification;
        window.Notification = function(title, options) {
            // Block notification requests
            return null;
        };
        window.Notification.permission = 'denied';
        window.Notification.requestPermission = () => Promise.resolve('denied');

        // === LANGUAGES RANDOMIZATION ===
        Object.defineProperty(navigator, 'languages', {
            get: () => ['en-US', 'en', 'es', 'fr'],
            configurable: true,
            enumerable: true
        });

        console.log('🛡️ Ultimate Stealth Mode Activated');
        """

    async def create_ultimate_context(self, 
                                    profile_dir: str,
                                    use_proxy: bool = False,
                                    proxy_url: Optional[str] = None,
                                    enable_stealth: bool = True) -> Optional[BrowserContext]:
        """
        Create ultimate context dengan comprehensive anti-detection
        """
        
        try:
            await self.start_playwright()
            
            async with self._lock:
                # Context management
                if len(self._browser_contexts) >= self._max_contexts:
                    await self._cleanup_old_contexts()
                
                if profile_dir in self._browser_contexts:
                    ctx = self._browser_contexts[profile_dir]
                    if not ctx.is_closed():
                        return ctx
                    else:
                        del self._browser_contexts[profile_dir]
                
                if self._verbose:
                    print(f"🚀 [UltimateChromiumManager] Creating ultimate context: {profile_dir}")
                
                os.makedirs(profile_dir, exist_ok=True)
                
                # Generate ultimate fingerprint
                fingerprint = self.anti_detection.generate_ultimate_fingerprint(use_proxy)
                
                # Prepare launch options
                launch_args = self._get_ultimate_launch_args(use_proxy)
                
                context_options = {
                    "headless": self._headless,
                    "args": launch_args,
                    "user_data_dir": profile_dir,
                    "user_agent": fingerprint['user_agent'],
                    "viewport": fingerprint['viewport'],
                    "locale": fingerprint['locale'],
                    "timezone_id": fingerprint['timezone'],
                    "ignore_https_errors": True,
                    "bypass_csp": True,
                    "java_script_enabled": True,
                    "has_touch": False,
                }
                
                # Proxy configuration (jika digunakan)
                final_proxy_url = proxy_url if use_proxy else None
                if final_proxy_url:
                    context_options["proxy"] = {"server": final_proxy_url}
                    if self._verbose:
                        print(f"🔌 [UltimateChromiumManager] Using proxy: {final_proxy_url[:50]}...")
                
                if self._verbose:
                    print(f"🎭 [UltimateChromiumManager] Ultimate fingerprint applied")
                
                # Launch context
                chromium = self._pw.chromium
                context = await chromium.launch_persistent_context(**context_options)
                
                # Apply ultimate stealth
                if enable_stealth:
                    await self._apply_ultimate_stealth(context)
                
                # Apply additional protections
                await self._apply_ultimate_protections(context, fingerprint)
                
                # Store context
                self._browser_contexts[profile_dir] = context
                self.security_metrics['successful_navigations'] += 1
                
                if self._verbose:
                    print(f"✅ [UltimateChromiumManager] Ultimate context created: {profile_dir}")
                
                return context
                
        except Exception as e:
            logger.error(f"❌ [UltimateChromiumManager] Failed to create ultimate context: {e}")
            self.security_metrics['detection_events'] += 1
            return None

    async def _apply_ultimate_stealth(self, context: BrowserContext):
        """Apply ultimate stealth scripts dan protections with comprehensive fingerprint spoofing"""
        try:
            # Get IP configuration with comprehensive spoofing data
            ip_config = IP_STEALTH_SYSTEM.get_fresh_ip_config()
            device_fp = ip_config.get("device_fingerprint", {})
            
            # Get WebRTC/WebGL fingerprint
            brand = device_fp.get("brand", "Samsung").lower()
            device_type = "android"  # or ios based on brand
            connection_type = ip_config.get("connection_type", "mobile")
            webrtc_webgl_fp = WEBRTC_WEBGL_SPOOFER.get_complete_fingerprint(device_type, brand, connection_type)
            
            # Add comprehensive stealth injection script
            comprehensive_script = WEBRTC_WEBGL_SPOOFER.get_stealth_injection_script(webrtc_webgl_fp)
            await context.add_init_script(comprehensive_script)
            
            # Add main stealth script
            stealth_script = self._get_ultimate_stealth_script()
            await context.add_init_script(stealth_script)
            
            # Set realistic headers from IP config
            headers = ip_config.get("headers", {})
            await context.set_extra_http_headers({
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                'Accept-Language': headers.get('Accept-Language', 'id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7'),
                'Accept-Encoding': 'gzip, deflate, br',
                'Cache-Control': 'no-cache',
                'DNT': '1',
                'Sec-CH-UA': headers.get('Sec-CH-UA', '"Chromium";v="135", "Google Chrome";v="135", "Not-A.Brand";v="99"'),
                'Sec-CH-UA-Mobile': headers.get('Sec-CH-UA-Mobile', '?1'),
                'Sec-CH-UA-Platform': headers.get('Sec-CH-UA-Platform', '"Android"'),
                'Sec-Fetch-Dest': 'document',
                'Sec-Fetch-Mode': 'navigate',
                'Sec-Fetch-Site': 'none',
                'Sec-Fetch-User': '?1',
                'Upgrade-Insecure-Requests': '1',
            })
            
            # Configure timeouts untuk realism
            context.set_default_timeout(45000)
            context.set_default_navigation_timeout(60000)
            
            if self._verbose:
                print(f"🛡️ [UltimateChromiumManager] Comprehensive fingerprint spoofing applied")
                print(f"   📍 IP: {ip_config.get('ip')} ({ip_config.get('isp')})")
                print(f"   📱 Device: {device_fp.get('market_name', 'Unknown')}")
                print(f"   🔗 Connection: {connection_type}")
            
        except Exception as e:
            logger.debug(f"Stealth application warning: {e}")

    async def _apply_ultimate_protections(self, context: BrowserContext, fingerprint: Dict):
        """Apply additional ultimate protections"""
        try:
            # Route blocking untuk analytics dan tracking
            await context.route("**/*", lambda route: self._handle_route(route))
            
            # Clear initial storage
            pages = context.pages
            for page in pages:
                try:
                    await page.evaluate("() => { localStorage.clear(); sessionStorage.clear(); }")
                except:
                    pass
                    
        except Exception as e:
            logger.debug(f"Protection application warning: {e}")

    async def _handle_route(self, route):
        """Handle route requests untuk block tracking"""
        request = route.request
        url = request.url.lower()
        
        # Block common tracking domains
        tracking_domains = [
            'google-analytics', 'googletag', 'doubleclick', 'facebook.com/tr',
            'connect.facebook.net', 'analytics.twitter.com', 'scorecardresearch',
            'hotjar.com', 'amplitude.com', 'mixpanel.com', 'segment.com',
            'mouseflow.com', 'pingdom.net', 'newrelic.com', 'datadoghq.com'
        ]
        
        if any(domain in url for domain in tracking_domains):
            self.security_metrics['blocked_requests'] += 1
            await route.abort()
        else:
            await route.continue_()

    async def _cleanup_old_contexts(self):
        """Cleanup old contexts untuk memory management"""
        try:
            if len(self._browser_contexts) > self._max_contexts:
                # Close oldest contexts
                contexts_to_remove = list(self._browser_contexts.keys())[:2]  # Remove 2 oldest
                for profile_dir in contexts_to_remove:
                    ctx = self._browser_contexts.pop(profile_dir, None)
                    if ctx:
                        try:
                            await ctx.close()
                        except:
                            pass
        except Exception as e:
            logger.debug(f"Context cleanup warning: {e}")

    async def rotate_fingerprint_ultimate(self, profile_dir: str) -> bool:
        """Ultimate fingerprint rotation dengan comprehensive reset"""
        try:
            if not self.anti_detection.should_rotate_fingerprint():
                return False
                
            context = self._browser_contexts.get(profile_dir)
            if not context:
                return False
            
            # Close existing context
            await context.close()
            del self._browser_contexts[profile_dir]
            
            # Clear profile directory
            try:
                import shutil
                if os.path.exists(profile_dir):
                    shutil.rmtree(profile_dir)
            except:
                pass
            
            # Create new context dengan fingerprint baru
            new_context = await self.create_ultimate_context(
                profile_dir=profile_dir,
                use_proxy=self._use_proxy,
                proxy_url=self._proxy_url,
                enable_stealth=True
            )
            
            if new_context:
                self.anti_detection.record_rotation()
                self.security_metrics['total_rotations'] += 1
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Ultimate fingerprint rotation failed: {e}")
            return False

    async def navigate_with_ultimate_protection(self, 
                                              profile_dir: str, 
                                              url: str,
                                              wait_until: str = "networkidle") -> bool:
        """Navigate dengan ultimate protection layers"""
        try:
            context = self._browser_contexts.get(profile_dir)
            if not context:
                return False
            
            page = await context.new_page()
            
            try:
                # Pre-navigation delay
                delay = self.anti_detection.calculate_behavior_delay('navigation', self._use_proxy)
                await asyncio.sleep(delay)
                
                # Navigate dengan protection
                await page.goto(url, wait_until=wait_until, timeout=60000)
                
                # Post-navigation delay
                await asyncio.sleep(self.anti_detection.calculate_behavior_delay('page_load', self._use_proxy))
                
                # Record action
                self.anti_detection.record_action()
                
                return True
                
            finally:
                await page.close()
                
        except Exception as e:
            logger.error(f"Ultimate navigation failed: {e}")
            return False

    # Compatibility methods
    async def new_persistent_context(self, profile_dir: str, **kwargs) -> Optional[BrowserContext]:
        return await self.create_ultimate_context(profile_dir, **kwargs)
    
    async def close_all(self) -> bool:
        """Ultimate cleanup"""
        try:
            async with self._lock:
                for profile_dir, ctx in list(self._browser_contexts.items()):
                    try:
                        await ctx.close()
                    except:
                        pass
                
                self._browser_contexts.clear()
                
                for browser in self._launched_browsers:
                    try:
                        await browser.close()
                    except:
                        pass
                
                self._launched_browsers.clear()
                self._browser = None
            
            await self.stop_playwright()
            
            if self._verbose:
                print("✅ [UltimateChromiumManager] Ultimate cleanup completed")
            
            return True
            
        except Exception as e:
            logger.error(f"Ultimate cleanup failed: {e}")
            return False

    def get_ultimate_metrics(self) -> Dict[str, Any]:
        """Get comprehensive security metrics"""
        return {
            **self.security_metrics,
            'contexts_count': len(self._browser_contexts),
            'fingerprint_rotations': self.anti_detection.fingerprint_rotation_count,
            'behavior_patterns_count': len(self.anti_detection.behavior_patterns),
            'using_proxy': self._use_proxy,
            'ultimate_stealth_enabled': self._enable_ultimate_stealth,
        }

# -------------------- Fingerprint & helper classes --------------------
class ChromeFingerprintSuperRealistic:
    MILESTONES = list(range(118, 151))
    BASELINE = {
        118: (5370, 80),
        120: (5400, 90),
        125: (5550, 110),
        130: (5700, 120),
        135: (5850, 130),
        140: (6000, 140),
        145: (6150, 150),
        150: (6300, 160),
    }
    MAC_OS = ["10_15_7", "11_7_10", "12_7_5", "13_6_2", "14_4_1", "15_0"]
    WIN_OS = ["10.0", "11.0"]
    ANDROID_DEVICES = [
        ("Android 12", "Pixel 6"),
        ("Android 13", "Pixel 7"),
        ("Android 14", "Pixel 8"),
        ("Android 15", "Pixel 9"),
    ]

    def __init__(self, os_name: str = "mac", stable: bool = True, seed: Optional[int] = None):
        self.os_name = os_name.lower()
        self.stable = stable
        if seed is not None:
            self.seed = int(seed)
        else:
            self.seed = int(time.time()) // 3600 if stable else random.SystemRandom().randint(1, 1_000_000_000)
        self.rng = random.Random(self.seed)
        self._cache: Dict[str, object] = {}

    def _closest_baseline(self, m: int) -> Tuple[int, int]:
        keys = sorted(self.BASELINE.keys())
        chosen = keys[0]
        for k in keys:
            if m >= k:
                chosen = k
        return self.BASELINE[chosen]

    def _stable_val(self, key: str, fn):
        if not self.stable:
            local_rng = random.Random(random.SystemRandom().randint(1, 1_000_000_000))
            return fn(local_rng)
        if key not in self._cache:
            self._cache[key] = fn(self.rng)
        return self._cache[key]

    def milestone(self) -> int:
        return self._stable_val("milestone", lambda rng: rng.choice(self.MILESTONES))

    def chrome_version(self) -> str:
        def gen(rng):
            m = self.milestone()
            main_base, base = self._closest_baseline(m)
            build_delta = rng.randint(0, 180)
            patch = rng.randint(0, 14)
            return f"{m}.0.{main_base + build_delta}.{base + patch}"
        return self._stable_val("chrome_version", gen)

    def platform_string(self) -> str:
        def gen(rng):
            if self.os_name == "mac":
                v = rng.choice(self.MAC_OS)
                return f"Macintosh; Intel Mac OS X {v}"
            if self.os_name == "windows":
                v = rng.choice(self.WIN_OS)
                return f"Windows NT {v}; Win64; x64"
            if self.os_name == "linux":
                return "X11; Linux x86_64"
            if self.os_name == "android":
                a, d = rng.choice(self.ANDROID_DEVICES)
                return f"{a}; {d}"
            return "X11; Linux x86_64"
        return self._stable_val("platform_string", gen)

    def user_agent(self) -> str:
        def gen(rng):
            cv = self.chrome_version()
            pf = self.platform_string()
            if self.os_name == "android":
                return f"Mozilla/5.0 (Linux; {pf}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{cv} Mobile Safari/537.36"
            return f"Mozilla/5.0 ({pf}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{cv} Safari/537.36"
        return self._stable_val("user_agent", gen)

    def mobile_flag(self) -> bool:
        return self.os_name == "android"

    def platform_label(self) -> str:
        if self.os_name == "mac":
            return "macOS"
        if self.os_name == "windows":
            return "Windows"
        if self.os_name == "linux":
            return "Linux"
        if self.os_name == "android":
            return "Android"
        return "Unknown"

    def arch(self) -> Optional[str]:
        if self.os_name == "android":
            return None
        return "x86"

    def bitness(self) -> Optional[str]:
        if self.os_name == "android":
            return None
        return "64"

    def model(self) -> Optional[str]:
        if self.os_name == "android":
            return self.platform_string().split(";")[-1].strip()
        return None

    def revision_id(self) -> str:
        def gen(rng):
            base = f"{self.user_agent()}_{self.seed}"
            return hashlib.sha1(base.encode()).hexdigest()[:16]
        return self._stable_val("revision_id", gen)

    def fingerprint(self) -> Dict[str, object]:
        return {
            "milestone": self.milestone(),
            "chrome": self.chrome_version(),
            "platform": self.platform_string(),
            "ua": self.user_agent(),
            "mobile": self.mobile_flag(),
            "arch": self.arch(),
            "bitness": self.bitness(),
            "model": self.model(),
            "platform_label": self.platform_label(),
            "revision": self.revision_id(),
            "seed": self.seed,
        }

class InstagramHeaderAutoSync:
    APP_IDS = [
        "936619743392459", "878587922602823", "192313041724948",
        "124024574287414", "1217981644879628", "157046581995844",
        "256357684841271", "1823059991408764"
    ]
    ASBD_IDS = [
        "229513", "264560", "291365", "341125",
        "359341", "377302", "407353", "438175",
        "451989", "466174", "494603", "529302",
    ]

    def __init__(self, fp: ChromeFingerprintSuperRealistic, seed_offset: int = 7777):
        self.fp = fp
        self.seed = fp.seed
        self.rng = random.Random(self.seed + seed_offset)

    def ajax(self) -> str:
        return str(self.rng.randint(1_000_000_000, 1_999_999_999))

    def generate(self) -> Dict[str, str]:
        chrome_ver = self.fp.chrome_version()
        ua = self.fp.user_agent()
        sec_ua = f'"Chromium";v="{chrome_ver.split(".")[0]}", "Not-A.Brand";v="99"'
        return {
            "app_id": str(self.rng.choice(self.APP_IDS)),
            "asbd_id": str(self.rng.choice(self.ASBD_IDS)),
            "ajax": self.ajax(),
            "ua": ua,
            "sec_ua": sec_ua,
        }

class HeaderBuilderV5:
    DEVICE_PROFILES = {
        "macbook": {"os": "mac", "label": "MacBook Pro", "viewport": (1440, 900), "accept_lang": "en-US,en;q=0.9"},
        "pixel7":  {"os": "android", "label": "Pixel 7", "viewport": (412, 915), "accept_lang": "en-US,en;q=0.9"},
        "galaxy":  {"os": "android", "label": "SM-S918B", "viewport": (412, 915), "accept_lang": "id-ID,id;q=0.9,en-US;q=0.8"},
        "windows": {"os": "windows", "label": "Surface", "viewport": (1366, 768), "accept_lang": "en-US,en;q=0.9"},
    }
    
    def __init__(self, device: str = "macbook", stable_session: bool = True, seed: Optional[int] = None):
        dev = device if device in self.DEVICE_PROFILES else "macbook"
        profile = self.DEVICE_PROFILES[dev]
        self.device_profile = profile
        self.fp = ChromeFingerprintSuperRealistic(os_name=profile["os"], stable=stable_session, seed=seed)
        self.ig_meta = InstagramHeaderAutoSync(self.fp)
        self.locale = profile["accept_lang"]

    def _timezone_offset_minutes(self) -> int:
        if time.localtime().tm_isdst and time.daylight:
            offset_secs = -time.altzone
        else:
            offset_secs = -time.timezone
        return int(offset_secs // 60)

    def _sec_ch_ua(self, chrome_ver: str) -> str:
        major = chrome_ver.split(".")[0]
        return f'"Chromium";v="{major}", "Google Chrome";v="{major}", "Not:A-Brand";v="99"'

    def build_base(self, referer: Optional[str] = None, add_random_referer: bool = False) -> Dict[str, str]:
        f = self.fp.fingerprint()
        ua = f["ua"]
        chrome_ver = f["chrome"]
        base = {
            "User-Agent": ua,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": self.locale,
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Cache-Control": "max-age=0",
            "Sec-Ch-Ua": self._sec_ch_ua(chrome_ver),
            "Sec-Ch-Ua-Mobile": "?1" if f["mobile"] else "?0",
            "Sec-Ch-Ua-Platform": f'"{f["platform_label"]}"',
            "Sec-Ch-Ua-Full-Version": f'"{f["chrome"]}"',
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-User": "?1",
            "Sec-Fetch-Dest": "document",
            "Viewport-Width": str(self.device_profile["viewport"][0]),
            "Priority": "u=2",
            "DNT": "1",
            "X-Request-Id": hashlib.sha1(f"{f['revision']}-{time.time()}".encode()).hexdigest()[:24],
            "X-Timezone-Offset-Minutes": str(self._timezone_offset_minutes()),
        }
        if referer:
            base["Referer"] = referer
        elif add_random_referer:
            base["Referer"] = f"https://example.test/{hashlib.sha1(str(time.time()).encode()).hexdigest()[:8]}"
        order = [
            "User-Agent", "Accept", "Accept-Language", "Accept-Encoding", "Referer",
            "Connection", "Upgrade-Insecure-Requests", "Cache-Control",
            "Sec-Ch-Ua", "Sec-Ch-Ua-Mobile", "Sec-Ch-Ua-Platform", "Sec-Ch-Ua-Full-Version",
            "Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-User", "Sec-Fetch-Dest",
            "Viewport-Width", "Priority", "DNT", "X-Request-Id", "X-Timezone-Offset-Minutes"
        ]
        ordered = {k: base[k] for k in order if k in base}
        for k, v in base.items():
            if k not in ordered:
                ordered[k] = v
        return ordered

    def build_with_ig_meta(self, referer: Optional[str] = None) -> Dict[str, str]:
        headers = self.build_base(referer=referer)
        meta = self.ig_meta.generate()
        headers["X-Ig-App-Id"] = meta["app_id"]
        headers["X-Asbd-Id"] = meta["asbd_id"]
        headers["X-Instagram-Ajax"] = meta["ajax"]
        headers["Sec-Ch-Ua"] = meta["sec_ua"]
        return headers

    def export_profile(self) -> str:
        p = {
            "device_profile": self.device_profile,
            "fingerprint": self.fp.fingerprint(),
            "ig_meta_seeded": {"ajax": self.ig_meta.ajax(), "seed": self.ig_meta.rng.randint(0, 1<<30)},
            "locale": self.locale
        }
        return json.dumps(p, indent=2)

# -------------------- Simple generator utilities --------------------
class AppID_IGLike_V6:
    def __init__(self, mode="nextgen"):
        self.mode = mode
        self.weights = {
            '1': 0.18, '2': 0.16, '3': 0.14,
            '4': 0.12, '5': 0.10, '6': 0.08,
            '7': 0.06, '8': 0.05, '9': 0.05, '0': 0.06
        }
        self.digits = list(self.weights.keys())
        self.probs = list(self.weights.values())
        self.cluster_bank = {
            "legacy": ["11", "22", "33", "44", "121", "232", "343", "454"],
            "modern": ["55", "66", "77", "88", "99", "565", "676", "787", "898"],
            "nextgen": ["113", "224", "331", "442", "557", "668", "779", "881", "992"]
        }

    def _digit(self):
        return random.choices(self.digits, self.probs)[0]

    def _ts_block(self):
        t = int(time.time() * 1000)
        return str((t % 90000) + 10000)

    def _evolve_cluster(self):
        base = self.cluster_bank[self.mode]
        if random.random() < 0.3:
            d = random.choice("123456789")
            c = d + random.choice("0123456789") + d
            base = base + [c]
        return random.choice(base)

    def _fold_checksum(self, s):
        total = sum(ord(c) for c in s)
        folded = (total % 997) + 100
        return str(folded)

    def generate(self, length=16):
        lead = random.choice("123456789")
        ts = self._ts_block()
        middle = ""
        while len(middle) < length - len(ts) - 1 - 3:
            if random.random() < 0.25:
                middle += self._evolve_cluster()
            else:
                middle += self._digit()
        middle = middle[:length - len(ts) - 1 - 3]
        chk = self._fold_checksum(lead + ts + middle)
        return lead + ts + middle + chk

class ASBD_V6:
    def __init__(self):
        self.epoch_seeds = [
            129000, 198000, 229000, 264000, 291365,
            341000, 377302, 407000, 438000, 466000,
            529000, 565000, 597000, 618000, 647000,
            678000, 712000, 736000, 759000, 789000
        ]

    def _choose_seed(self):
        if random.random() < 0.7:
            return random.choice(self.epoch_seeds[-6:])
        else:
            return random.choice(self.epoch_seeds)

    def _micro_noise(self):
        return random.randint(-250, 250)

    def _evolve_jump(self):
        if random.random() < 0.15:
            return random.randint(500, 2500)
        return 0

    def generate(self):
        seed = self._choose_seed()
        noise = self._micro_noise()
        jump = self._evolve_jump()
        val = seed + noise + jump
        val = max(110000, min(val, 999999))
        return str(val)

class UUDI_V6:
    prefix = "Y"
    charset = string.ascii_letters + string.digits + "_-"
    core_segments = [
        "ABAA", "AABF", "AAEF", "ABAF", "AAE1", "AAB1",
        "ABF0", "AACF", "AAE0", "AAF0",
    ]
    block_heads = [
        "C", "V", "p", "r", "t", "x", "z", "_",
        "k", "m", "n", "q", "B", "D", "F", "H", "J",
    ]
    def _rand_chars(self, n):
        return "".join(random.choice(self.charset) for _ in range(n))
    def generate(self):
        head = self.prefix + random.choice(self.block_heads)
        cluster = self._rand_chars(random.randint(1, 2))
        core = random.choice(self.core_segments)
        flag_num = random.randint(10, 99)
        tail = self._rand_chars(random.randint(3, 5))
        result = f"{head}{cluster}{flag_num}AB{core}{self._rand_chars(2)}{tail}"
        return result

# -------------------- Human behavior / Traffic shaping / Anti-detection --------------------
class HumanBehaviorSimulator:
    def __init__(self):
        self.behavior_profiles = {
            "casual": {"delay_range": (2.0, 8.0), "scroll_speed": "slow", "action_variance": 0.3},
            "active": {"delay_range": (1.0, 4.0), "scroll_speed": "medium", "action_variance": 0.2},
            "power": {"delay_range": (0.5, 2.0), "scroll_speed": "fast", "action_variance": 0.1}
        }
        self.session_activities = {}

    async def simulate_human_flow(self, session, account_data, behavior_type="casual"):
        profile = self.behavior_profiles.get(behavior_type, self.behavior_profiles["casual"])
        await self.pre_creation_warmup(session, profile)
        await self.instagram_exploration(session, profile)
        await self.account_creation_simulation(session, profile)

    async def pre_creation_warmup(self, session, profile):
        warmup_urls = [
            "https://www.google.com/",
            "https://www.youtube.com/",
            "https://www.facebook.com/",
            "https://www.twitter.com/",
        ]
        for url in random.sample(warmup_urls, random.randint(2, 3)):
            try:
                await session.get(url)
                await self.random_delay(profile["delay_range"][0], profile["delay_range"][1])
            except Exception:
                continue

    async def instagram_exploration(self, session, profile):
        exploration_paths = [
            ["/", "/explore/", "/accounts/login/"],
            ["/", "/direct/inbox/", "/accounts/emailsignup/"],
            ["/explore/", "/", "/accounts/emailsignup/"]
        ]
        path = random.choice(exploration_paths)
        for endpoint in path:
            try:
                url = f"https://www.instagram.com{endpoint}"
                await session.get(url)
                scroll_time = random.uniform(3.0, 12.0)
                await asyncio.sleep(scroll_time)
                await self.random_delay(profile["delay_range"][0], profile["delay_range"][1])
            except Exception:
                continue

    async def account_creation_simulation(self, session, profile):
        field_delays = [random.uniform(1.0, 3.0) for _ in range(6)]
        for delay in field_delays:
            await asyncio.sleep(delay)

    async def random_delay(self, min_seconds=0.5, max_seconds=3.0):
        base_delay = random.uniform(min_seconds, max_seconds)
        variance = base_delay * 0.3
        final_delay = max(0.1, random.uniform(base_delay - variance, base_delay + variance))
        await asyncio.sleep(final_delay)

    async def typing_delay(self, text):
        chars = len(text)
        base_delay = chars * 0.08
        jitter = random.uniform(0.7, 1.5)
        await asyncio.sleep(base_delay * jitter)

class TrafficShaper:
    def __init__(self):
        self.request_times = []
        self.session_start = time.time()
        self.request_pattern = []

    async def shape_traffic(self, request_type="api"):
        now = time.time()
        self.request_times = [t for t in self.request_times if now - t < 120]
        self.request_pattern.append((now, request_type))
        if len(self.request_pattern) > 50:
            self.request_pattern = self.request_pattern[-50:]
        if self._is_rate_limited():
            delay = random.uniform(15.0, 30.0)
            await asyncio.sleep(delay)
            self.request_times.clear()
        recent_requests = len([t for t in self.request_times if now - t < 30])
        base_delay = self._calculate_dynamic_delay(recent_requests, request_type)
        jitter = random.uniform(0.7, 1.3)
        final_delay = base_delay * jitter
        await asyncio.sleep(final_delay)
        self.request_times.append(time.time())

    def _is_rate_limited(self) -> bool:
        now = time.time()
        recent_minute = len([t for t in self.request_times if now - t < 60])
        recent_5min = len([t for t in self.request_times if now - t < 300])
        return recent_minute > 20 or recent_5min > 60

    def _calculate_dynamic_delay(self, recent_requests: int, request_type: str) -> float:
        base_delays = {
            "navigation": (1.0, 3.0),
            "api": (2.0, 5.0),
            "signup": (3.0, 8.0),
            "critical": (5.0, 12.0)
        }
        min_delay, max_delay = base_delays.get(request_type, (2.0, 5.0))
        if recent_requests > 10:
            scale_factor = min(2.0, 1.0 + (recent_requests - 10) * 0.1)
            min_delay *= scale_factor
            max_delay *= scale_factor
        return random.uniform(min_delay, max_delay)

# -------------------- AdvancedFingerprintManager --------------------
class AdvancedFingerprintManager:
    def __init__(self):
        self.fingerprint_pool = []
        self.used_fingerprints = set()
        self.load_realistic_fingerprints()

    def load_realistic_fingerprints(self):
        self.fingerprint_pool = [
            {
                "type": "mobile",
                "user_agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
                "screen": {"width": 390, "height": 844, "availWidth": 390, "availHeight": 844, "devicePixelRatio": 3.0},
                "device_memory": 4,
                "hardware_concurrency": 6,
                "webgl_vendor": "Apple Inc.",
                "webgl_renderer": "Apple GPU",
                "platform": "iPhone",
                "fonts": ["SF-Pro", "Helvetica", "San Francisco"],
                "timezone": "America/Los_Angeles",
                "locale": "en-US",
                "languages": ["en-US", "en"],
                "accept_language": "en-US,en;q=0.9"
            },
            {
                "type": "mobile",
                "user_agent": "Mozilla/5.0 (Linux; Android 13; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Mobile Safari/537.36",
                "screen": {"width": 412, "height": 915, "availWidth": 412, "availHeight": 870, "devicePixelRatio": 2.6},
                "device_memory": 12,
                "hardware_concurrency": 8,
                "webgl_vendor": "Google Inc.",
                "webgl_renderer": "ANGLE (Qualcomm, Adreno (TM) 740, OpenGL ES 3.2)",
                "platform": "Linux armv8l",
                "fonts": ["Roboto", "Noto Sans", "Arial"],
                "timezone": "Europe/London",
                "locale": "en-GB",
                "languages": ["en-GB", "en"],
                "accept_language": "en-GB,en;q=0.9"
            },
            {
                "type": "desktop",
                "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
                "screen": {"width": 1440, "height": 900, "availWidth": 1440, "availHeight": 900, "devicePixelRatio": 2.0},
                "device_memory": 8,
                "hardware_concurrency": 12,
                "webgl_vendor": "Intel Inc.",
                "webgl_renderer": "Intel Iris OpenGL Engine",
                "platform": "MacIntel",
                "fonts": ["Helvetica", "Arial", "Times New Roman", "Courier New"],
                "timezone": "America/New_York",
                "locale": "en-US",
                "languages": ["en-US", "en"],
                "accept_language": "en-US,en;q=0.9"
            },
            {
                "type": "desktop",
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
                "screen": {"width": 1920, "height": 1080, "availWidth": 1920, "availHeight": 1040, "devicePixelRatio": 1.0},
                "device_memory": 16,
                "hardware_concurrency": 16,
                "webgl_vendor": "Google Inc.",
                "webgl_renderer": "ANGLE (Intel, Intel(R) UHD Graphics 630, OpenGL 4.1)",
                "platform": "Win32",
                "fonts": ["Arial", "Segoe UI", "Times New Roman", "Microsoft Sans Serif"],
                "timezone": "Europe/Paris",
                "locale": "fr-FR",
                "languages": ["fr-FR", "fr", "en-US"],
                "accept_language": "fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7"
            }
        ]

    def get_fingerprint(self, device_type=None):
        available = [fp for fp in self.fingerprint_pool if str(fp) not in self.used_fingerprints]
        if device_type:
            available = [fp for fp in available if fp.get("type") == device_type]
        if not available:
            self.used_fingerprints.clear()
            available = self.fingerprint_pool
        fingerprint = random.choice(available)
        self.used_fingerprints.add(str(fingerprint))
        return fingerprint

# -------------------- SmartProxyManager / EnhancedProxyManager --------------------
class SmartProxyManager(ProxyManager):
    def __init__(self, verbose: bool = False):
        super().__init__(verbose)
        self.proxy_pool = []
        self.used_proxies = set()
        self.failed_proxies = set()
        self.proxy_locations = {}
        self.location_cache = {}
        self.proxy_scores = {}

    async def detect_proxy_location(self, proxy: str) -> Optional[Dict]:
        if proxy in self.location_cache:
            return self.location_cache[proxy]
        try:
            async with aiohttp.ClientSession() as session:
                services = [
                    "https://ipapi.co/json/",
                    "https://ipinfo.io/json",
                    "http://ip-api.com/json/"
                ]
                for service in services:
                    try:
                        async with session.get(service, proxy=proxy, timeout=8, ssl=False) as resp:
                            if resp.status == 200:
                                data = await resp.json()
                                location = {
                                    'country': data.get('country_name') or data.get('country'),
                                    'country_code': data.get('country_code') or data.get('countryCode'),
                                    'city': data.get('city'),
                                    'timezone': data.get('timezone') or data.get('time_zone'),
                                    'isp': data.get('org') or data.get('isp'),
                                }
                                self.location_cache[proxy] = location
                                self.proxy_locations[proxy] = location
                                return location
                    except Exception:
                        continue
        except Exception as e:
            if self.verbose:
                logger.warning(f"Proxy location detection failed for {proxy}: {e}")
        return None

    async def add_proxy(self, proxy: str):
        await super().add(proxy)
        self.proxy_pool.append(proxy)
        self.proxy_scores[proxy] = 100
        asyncio.create_task(self.detect_proxy_location(proxy))
        asyncio.create_task(self.health_check_proxy(proxy))

    async def health_check_proxy(self, proxy: str) -> bool:
        try:
            async with aiohttp.ClientSession() as session:
                test_urls = [
                    "https://www.instagram.com/",
                    "https://httpbin.org/ip",
                    "https://api.ipify.org?format=json"
                ]
                success_count = 0
                for url in test_urls:
                    try:
                        async with session.get(url, proxy=proxy, timeout=10, ssl=False) as resp:
                            if resp.status == 200:
                                success_count += 1
                                self.proxy_scores[proxy] = min(100, self.proxy_scores.get(proxy, 50) + 5)
                    except Exception:
                        continue
                if success_count >= 2:
                    return True
                else:
                    self.proxy_scores[proxy] = max(0, self.proxy_scores.get(proxy, 50) - 20)
                    if self.proxy_scores[proxy] < 30:
                        self.failed_proxies.add(proxy)
                    return False
        except Exception:
            self.proxy_scores[proxy] = max(0, self.proxy_scores.get(proxy, 50) - 15)
            if self.proxy_scores[proxy] < 30:
                self.failed_proxies.add(proxy)
            return False

    async def get_optimal_proxy(self, country=None, min_score=50):
        available = [
            p for p in self.proxy_pool
            if p not in self.used_proxies
            and p not in self.failed_proxies
            and self.proxy_scores.get(p, 0) >= min_score
        ]
        if country and available:
            country_proxies = []
            for proxy in available:
                location = self.proxy_locations.get(proxy)
                if location and location.get('country_code') == country:
                    country_proxies.append(proxy)
            if country_proxies:
                available = country_proxies
        if not available:
            self.used_proxies.clear()
            available = [p for p in self.proxy_pool if p not in self.failed_proxies]
        if available:
            available.sort(key=lambda p: self.proxy_scores.get(p, 0), reverse=True)
            proxy = available[0]
            self.used_proxies.add(proxy)
            return proxy
        return None

    def get_proxy_location(self, proxy: str) -> Optional[Dict]:
        return self.proxy_locations.get(proxy)

    async def cleanup_proxy(self, proxy: str):
        if proxy in self.used_proxies:
            self.used_proxies.remove(proxy)

class EnhancedProxyManager:
    """Enhanced proxy manager dengan health checking"""
    
    def __init__(self, verbose: bool = False):
        self._proxies: List[str] = []
        self._scores: Dict[str, float] = {}
        self._bad: set = set()
        self.verbose = verbose
        self._lock = asyncio.Lock()
        self._last_used: Dict[str, float] = {}
        self._ttl_seconds = 60 * 60
        self.health_check_tasks = {}
        
    async def add_with_health_check(self, proxy: str):
        """Add proxy dengan health check"""
        async with self._lock:
            if proxy not in self._proxies:
                self._proxies.append(proxy)
                self._scores[proxy] = 100.0
                self._last_used[proxy] = _now()
                
                # Start background health check
                self.health_check_tasks[proxy] = asyncio.create_task(self._health_check_proxy(proxy))
                
                if self.verbose:
                    print(f"[EnhancedProxyManager] Added proxy with health check: {proxy}")

    async def _health_check_proxy(self, proxy: str):
        """Background health check untuk proxy"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get('https://httpbin.org/ip', 
                                     proxy=proxy, 
                                     timeout=10,
                                     ssl=False) as response:
                    if response.status == 200:
                        await self.score_success(proxy, 5.0)
                    else:
                        await self.mark_bad(proxy, 10.0)
        except Exception:
            await self.mark_bad(proxy, 15.0)

    async def get_optimal_proxy(self) -> Optional[str]:
        """Get optimal proxy berdasarkan score dan health"""
        async with self._lock:
            # Filter out bad proxies and sort by score
            candidates = [p for p in self._proxies if p not in self._bad]
            if not candidates:
                return None
                
            candidates.sort(key=lambda x: self._scores.get(x, 0.0), reverse=True)
            
            # Pick from top 3 untuk variety
            top_candidates = candidates[:3]
            if top_candidates:
                selected = random.choice(top_candidates)
                self._last_used[selected] = _now()
                return selected
                
            return None

# -------------------- Encryption helpers (optional) --------------------
try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
    HAVE_CRYPTO = True
except Exception:
    Fernet = None
    PBKDF2HMAC = None
    HAVE_CRYPTO = False

def _derive_key_from_password(password: str, salt: Optional[bytes] = None) -> bytes:
    if not HAVE_CRYPTO:
        raise RuntimeError('cryptography not available')
    salt = salt or b'ultraboosted_salt'
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=390000, backend=default_backend())
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def save_encrypted_session_file(path: str, payload: dict, password: Optional[str] = None):
    data = json.dumps(payload, ensure_ascii=False).encode('utf-8')
    if password and HAVE_CRYPTO:
        key = _derive_key_from_password(password)
        f = Fernet(key)
        token = f.encrypt(data)
        with open(path, 'wb') as f_out:
            f_out.write(token)
        print("[UltraBoostedV13] encrypted session file saved to %s", path)
    else:
        if password and not HAVE_CRYPTO:
            logger.warning("[UltraBoostedV13] cryptography not available - saving plaintext session file")
        with open(path, 'w', encoding='utf-8') as f_out:
            json.dump(payload, f_out, ensure_ascii=False, indent=2)
        print("[UltraBoostedV13] session file saved (plaintext) to %s", path)

def load_encrypted_session_file(path: str, password: Optional[str] = None) -> dict:
    if not os.path.exists(path):
        raise FileNotFoundError(path)
    if password and HAVE_CRYPTO:
        with open(path, 'rb') as f:
            token = f.read()
        key = _derive_key_from_password(password)
        f = Fernet(key)
        data = f.decrypt(token)
        return json.loads(data.decode('utf-8'))
    else:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)

class UnifiedProxyManager:
    """
    ✅ UNIFIED PROXY MANAGER - Menggabungkan semua fitur proxy management
    """
    
    def __init__(self, verbose: bool = False):
        self._proxies: List[str] = []
        self._scores: Dict[str, float] = {}
        self._bad: set = set()
        self.verbose = verbose
        self._lock = asyncio.Lock()
        self._last_used: Dict[str, float] = {}
        self._ttl_seconds = 60 * 60
        
        # Fitur tambahan dari SmartProxyManager
        self.proxy_pool: List[str] = []
        self.used_proxies: Set[str] = set()
        self.failed_proxies: Set[str] = set()
        self.proxy_locations: Dict[str, Dict] = {}
        self.location_cache: Dict[str, Dict] = {}
        self.proxy_scores: Dict[str, float] = {}
        self.health_check_tasks: Dict[str, asyncio.Task] = {}

    async def add(self, p: str):
        """Add proxy dengan health check background"""
        async with self._lock:
            if p not in self._proxies:
                self._proxies.append(p)
                self._scores[p] = 100.0
                self._last_used[p] = _now()
                
                # Tambahkan ke pool unified
                if p not in self.proxy_pool:
                    self.proxy_pool.append(p)
                    self.proxy_scores[p] = 100.0
                
                if self.verbose:
                    print("[UnifiedProxyManager] added %s", p)
                
                # Start background health check
                self.health_check_tasks[p] = asyncio.create_task(self._background_health_check(p))

    async def add_proxy(self, p: str):
        """Alias untuk add()"""
        return await self.add(p)

    async def remove(self, p: str):
        """Remove proxy dari semua pools"""
        async with self._lock:
            if p in self._proxies:
                self._proxies.remove(p)
                self._scores.pop(p, None)
                self._bad.discard(p)
                self._last_used.pop(p, None)
                
            if p in self.proxy_pool:
                self.proxy_pool.remove(p)
                self.proxy_scores.pop(p, None)
                self.used_proxies.discard(p)
                self.failed_proxies.discard(p)
                self.proxy_locations.pop(p, None)
                self.location_cache.pop(p, None)
                
            # Cancel health check task
            if p in self.health_check_tasks:
                self.health_check_tasks[p].cancel()
                self.health_check_tasks.pop(p, None)
                
            if self.verbose:
                print("[UnifiedProxyManager] removed %s", p)

    async def mark_bad(self, p: Optional[str], penalty: float = 30.0):
        if not p:
            return
        async with self._lock:
            self._bad.add(p)
            self._scores[p] = max(self._scores.get(p, 100.0) - penalty, 0.0)
            self._last_used[p] = _now()
            
            # Juga mark di unified pool
            self.failed_proxies.add(p)
            self.proxy_scores[p] = max(self.proxy_scores.get(p, 50.0) - penalty, 0.0)
            
            if self.verbose:
                logger.warning("[UnifiedProxyManager] marked bad %s score=%.1f", p, self._scores[p])

    async def score_success(self, p: Optional[str], bonus: float = 5.0):
        if not p:
            return
        async with self._lock:
            self._scores[p] = min(self._scores.get(p, 50.0) + bonus, 100.0)
            self._last_used[p] = _now()
            
            # Juga update di unified pool
            self.proxy_scores[p] = min(self.proxy_scores.get(p, 50.0) + bonus, 100.0)
            self.failed_proxies.discard(p)

    async def pick(self, auto_rotate: bool = True) -> Optional[str]:
        async with self._lock:
            candidates = [p for p in self._proxies if p not in self._bad]
            now = _now()
            
            # Cleanup expired proxies
            for p in list(self._proxies):
                if p in self._last_used and (now - self._last_used[p]) > self._ttl_seconds:
                    try:
                        await self.remove(p)
                        if self.verbose:
                            print("[UnifiedProxyManager] evicted unused proxy %s", p)
                    except Exception:
                        pass
            
            if not candidates:
                return None
                
            candidates.sort(key=lambda x: self._scores.get(x, 0.0), reverse=True)
            top = candidates[:3] if len(candidates) > 3 and auto_rotate else candidates
            choice = random.choice(top)
            self._last_used[choice] = _now()
            return choice

    async def get_optimal_proxy(self, country: Optional[str] = None, min_score: float = 50.0) -> Optional[str]:
        """Get optimal proxy dengan filtering"""
        async with self._lock:
            available = [
                p for p in self.proxy_pool
                if p not in self.used_proxies
                and p not in self.failed_proxies
                and self.proxy_scores.get(p, 0) >= min_score
            ]
            
            if country and available:
                country_proxies = [
                    p for p in available 
                    if self.proxy_locations.get(p, {}).get('country_code') == country
                ]
                if country_proxies:
                    available = country_proxies
            
            if not available:
                self.used_proxies.clear()
                available = [p for p in self.proxy_pool if p not in self.failed_proxies]
            
            if available:
                available.sort(key=lambda p: self.proxy_scores.get(p, 0), reverse=True)
                proxy = available[0]
                self.used_proxies.add(proxy)
                return proxy
            
            return None

    async def _background_health_check(self, proxy: str):
        """Background health check untuk proxy"""
        try:
            is_healthy = await self._health_check_proxy(proxy)
            if not is_healthy:
                await self.mark_bad(proxy)
        except Exception as e:
            if self.verbose:
                logger.warning("[UnifiedProxyManager] Health check failed for %s: %s", proxy, e)

    async def _health_check_proxy(self, proxy: str) -> bool:
        """Health check untuk proxy dengan criteria lebih relaxed"""
        try:
            async with aiohttp.ClientSession() as session:
                # Test dengan endpoint yang lebih tolerant
                test_urls = [
                    "https://httpbin.org/ip",  # Simple IP check
                    "https://www.google.com/favicon.ico",  # Small file
                    "https://httpbin.org/user-agent"  # Simple API
                ]
                
                success_count = 0
                for url in test_urls:
                    try:
                        async with session.get(
                            url, 
                            proxy=proxy, 
                            timeout=8,  # Increased timeout
                            ssl=False
                        ) as resp:
                            if resp.status in [200, 301, 302]:  # Accept redirects too
                                success_count += 1
                                if success_count >= 1:  # Only need 1 success
                                    await self.score_success(proxy, 10.0)
                                    return True
                    except asyncio.TimeoutError:
                        continue
                    except Exception:
                        continue
                
                # Jika tidak ada yang berhasil, jangan langsung mark as bad
                if success_count == 0:
                    current_score = self.proxy_scores.get(proxy, 50)
                    self.proxy_scores[proxy] = max(20, current_score - 5)  # Minor penalty
                    return False
                return True
                
        except Exception:
            # Error dalam health check, minor penalty saja
            current_score = self.proxy_scores.get(proxy, 50)
            self.proxy_scores[proxy] = max(20, current_score - 10)
            return False

    async def detect_proxy_location(self, proxy: str) -> Optional[Dict]:
        """Detect proxy location"""
        if proxy in self.location_cache:
            return self.location_cache[proxy]
        try:
            async with aiohttp.ClientSession() as session:
                services = [
                    "https://ipapi.co/json/",
                    "https://ipinfo.io/json",
                    "http://ip-api.com/json/"
                ]
                for service in services:
                    try:
                        async with session.get(service, proxy=proxy, timeout=8, ssl=False) as resp:
                            if resp.status == 200:
                                data = await resp.json()
                                location = {
                                    'country': data.get('country_name') or data.get('country'),
                                    'country_code': data.get('country_code') or data.get('countryCode'),
                                    'city': data.get('city'),
                                    'timezone': data.get('timezone') or data.get('time_zone'),
                                    'isp': data.get('org') or data.get('isp'),
                                }
                                self.location_cache[proxy] = location
                                self.proxy_locations[proxy] = location
                                return location
                    except Exception:
                        continue
        except Exception as e:
            if self.verbose:
                logger.warning(f"Proxy location detection failed for {proxy}: {e}")
        return None

    async def cleanup_proxy(self, proxy: str):
        """Cleanup proxy dari used_proxies"""
        if proxy in self.used_proxies:
            self.used_proxies.remove(proxy)

    def whitelist_proxy(self, proxy: str):
        """Whitelist proxy"""
        self.failed_proxies.discard(proxy)

    def get_proxy_scores(self) -> Dict[str, float]:
        """Get semua proxy scores"""
        return self.proxy_scores.copy()

    def get_proxy_stats(self) -> Dict[str, Any]:
        """Get detailed proxy statistics"""
        if not self.use_proxy or not hasattr(self.session, 'proxy_manager'):
            return {"proxy_enabled": False}
        
        try:
            proxy_manager = self.session.proxy_manager
            stats = proxy_manager.get_proxy_stats()
            
            return {
                "proxy_enabled": True,
                "current_proxy": self.bound_proxy[:50] + "..." if self.bound_proxy else None,
                "total_proxies": stats.get('total_proxies', 0),
                "available_proxies": stats.get('available_proxies', 0),
                "failed_proxies": stats.get('failed_proxies', 0),
                "average_score": stats.get('average_score', 0),
                "proxy_scores": proxy_manager.proxy_scores,
                "used_proxies_count": len(proxy_manager.used_proxies),
                "suspicion_level": self.suspicion_level,
            }
        except Exception as e:
            logger.error("[get_proxy_stats] Error: %s", e)
            return {"proxy_enabled": False, "error": str(e)}

    async def add_custom_proxies(self, proxies: List[str]):
        """Add custom proxies ke UnifiedProxyManager"""
        if not self.use_proxy:
            print("⚠️ Proxy not enabled, enabling proxy system...")
            self.use_proxy = True
        
        try:
            proxy_manager = self.session.proxy_manager
            added_count = 0
            
            for proxy in proxies:
                if proxy and proxy.strip():
                    await proxy_manager.add_proxy(proxy.strip())
                    added_count += 1
                    print("[add_custom_proxies] ✅ Added proxy: %s", proxy[:50])
            
            print("[add_custom_proxies] ✅ Total %d proxies added", added_count)
            return added_count
            
        except Exception as e:
            logger.error("[add_custom_proxies] Error: %s", e)
            return 0

    async def cleanup_proxy_resources(self):
        """Cleanup proxy resources"""
        if not self.use_proxy:
            return
        
        try:
            proxy_manager = self.session.proxy_manager
            
            if self.bound_proxy and self.bound_proxy in proxy_manager.used_proxies:
                await proxy_manager.cleanup_proxy(self.bound_proxy)
            
            self.bound_proxy = None
            
            print("[cleanup_proxy_resources] ✅ Proxy resources cleaned up")
            
        except Exception as e:
            logger.error("[cleanup_proxy_resources] Error: %s", e)

    async def benchmark(self, urls: List[str], concurrency: int = 8, timeout: int = 6):
        """Benchmark semua proxies"""
        if not self._proxies or not urls:
            return
            
        sem = asyncio.Semaphore(concurrency)
        
        async def _test(p):
            async with sem:
                start = _now()
                try:
                    async with aiohttp.ClientSession() as s:
                        async with s.get(urls[0], proxy=p, timeout=aiohttp.ClientTimeout(total=timeout)) as r:
                            await r.read()
                            t = _now() - start
                            return (p, t, r.status)
                except Exception as e:
                    return (p, None, str(e))
                    
        tasks = [asyncio.create_task(_test(p)) for p in self._proxies]
        results = await asyncio.gather(*tasks, return_exceptions=False)
        
        async with self._lock:
            latencies = [r[1] for r in results if r[1] is not None]
            if latencies:
                max_lat = max(latencies)
                for p, t, status in results:
                    if t is None:
                        self._scores[p] = max(self._scores.get(p, 100.0) - 50.0, 0.0)
                        self.proxy_scores[p] = max(self.proxy_scores.get(p, 50.0) - 50.0, 0.0)
                    else:
                        score = max(1.0, 100.0 * (1.0 - (t / (max_lat * 1.2))))
                        self._scores[p] = (self._scores.get(p, 50.0) * 0.3) + (score * 0.7)
                        self.proxy_scores[p] = (self.proxy_scores.get(p, 50.0) * 0.3) + (score * 0.7)
                        
        if self.verbose:
            print("[UnifiedProxyManager] benchmark results: %s", self._scores)

# ---------------------- Circuit Breaker ----------------------
class CircuitBreaker:
    def __init__(self, fail_threshold: int = 6, base_cooldown: int = 5):
        self.fail_count = 0
        self.fail_threshold = fail_threshold
        self.base_cooldown = base_cooldown
        self._lock = asyncio.Lock()
        self._break_until = 0.0
        self._half_open_probe = False

    async def record_failure(self):
        async with self._lock:
            self.fail_count += 1
            if self.fail_count >= self.fail_threshold:
                self._break_until = _now() + self.base_cooldown
                self._half_open_probe = False

    async def record_success(self):
        async with self._lock:
            self.fail_count = 0
            self._break_until = 0.0
            self._half_open_probe = False

    async def can_request(self) -> bool:
        async with self._lock:
            now = _now()
            if now < self._break_until:
                return False
            if self.fail_count >= self.fail_threshold and not self._half_open_probe:
                self._half_open_probe = True
                return True
            return True

# ---------------------- UltraBoostedV13 main class ----------------------
class UltraBoostedV13:
    def __init__(self,
                 timeout: int = 30,
                 max_retries: int = 4,
                 use_proxy: bool = False,
                 max_concurrency: int = 12,
                 verbose: bool = True,
                 rotate_ja3: bool = True,
                 non_standard_header_obfuscation: bool = False,
                 bypass_fragmentation: bool = False,
                 auto_rotate_proxy: bool = True,
                 http2_priority_hint: bool = True,
                 anti_detect: bool = False,
                 session_file: Optional[str] = None,
                 use_session: bool = False,
                 smart_headers_mode: Optional[str] = None):

        self.timeout = timeout
        self.max_retries = max_retries
        self.use_proxy = use_proxy
        self.verbose = verbose
        self.max_concurrency = max_concurrency
        self.semaphore = asyncio.Semaphore(max_concurrency)

        # Enhanced proxy manager
        self.proxy_manager = EnhancedProxyManager(verbose=verbose)
        self.cookie_jar = SafeCookieJar()
        self.header_builder = HeaderBuilder(non_standard_obfuscation=non_standard_header_obfuscation,
                                            smart_headers_mode=smart_headers_mode)
        try:
            self.header_builder._parent = self
        except Exception:
            pass

        self.auto_rotate_proxy = auto_rotate_proxy
        self.http2_priority_hint = http2_priority_hint
        self.rotate_ja3 = rotate_ja3
        self.bypass_fragmentation = bypass_fragmentation
        self._ja3_profile = None

        self.use_session_global = use_session
        self._aiohttp_session: Optional[aiohttp.ClientSession] = None
        self._httpx_clients: Dict[Optional[str], Any] = {}
        self._client_lock = asyncio.Lock()

        self._session_file = session_file or "./sessions_v13.json"
        self._auto_session_task: Optional[asyncio.Task] = None
        self._auto_session_interval = 30

        # Enhanced security features
        self.security_manager = AdvancedSecurityManager()
        self.anti_detection = AntiDetectionManager()
        self.circuit = CircuitBreaker()

        self._verbose = verbose
        self._proxy_cleanup_task: Optional[asyncio.Task] = None

        if HAVE_HTTPX and verbose:
            print("[UltraBoostedV13] httpx available with enhanced security")
        elif verbose:
            print("[UltraBoostedV13] httpx not available; using aiohttp + raw TLS fallback")

        if session_file:
            try:
                self.load_sessions_from_file(session_file)
            except Exception as e:
                logger.warning("[UltraBoostedV13] failed loading session file: %s", e)

    def _make_ja3_profile(self) -> str:
        parts = [771, 4865, 49195, 49199]
        extras = [159, 158]
        parts += extras
        parts_str = ",".join(map(str, parts))
        ja3 = f"771,{parts_str},0,0"
        self._ja3_profile = ja3
        return ja3

    async def _ensure_aiohttp(self):
        if self._aiohttp_session is None or self._aiohttp_session.closed:
            self._aiohttp_session = aiohttp.ClientSession(trust_env=True)
            if self._verbose:
                print("[UltraBoostedV13] aiohttp session created")

    async def _ensure_httpx_for_proxy(self, proxy: Optional[str]):
        if not HAVE_HTTPX:
            return None
        async with self._client_lock:
            if proxy in self._httpx_clients:
                return self._httpx_clients[proxy]
            try:
                if proxy:
                    proxies = {"http://": proxy, "https://": proxy}
                    c = httpx.AsyncClient(http2=True, timeout=self.timeout, proxies=proxies)
                else:
                    c = httpx.AsyncClient(http2=True, timeout=self.timeout)
            except Exception:
                c = httpx.AsyncClient(http2=True)
            self._httpx_clients[proxy] = c
            if self._verbose:
                print("[UltraBoostedV13] httpx client ready for proxy=%s", proxy)
            return c

    def start_session(self):
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = None

        if loop and loop.is_running():
            try:
                asyncio.create_task(self._ensure_aiohttp())
                if HAVE_HTTPX:
                    asyncio.create_task(self._ensure_httpx_for_proxy(None))
            except Exception:
                pass
            self.use_session_global = True
            if self._verbose:
                print("[UltraBoostedV13] sessions start scheduled (event loop running)")
            return

        loop = asyncio.new_event_loop()
        try:
            asyncio.set_event_loop(loop)
            loop.run_until_complete(self._ensure_aiohttp())
            if HAVE_HTTPX:
                loop.run_until_complete(self._ensure_httpx_for_proxy(None))
            self.use_session_global = True
            if self._verbose:
                print("[UltraBoostedV13] sessions started")
        finally:
            try:
                loop.close()
            except Exception:
                pass

    async def close_session(self):
        try:
            self.stop_auto_session_saver()
        except Exception:
            pass
        if self._aiohttp_session:
            try:
                await self._aiohttp_session.close()
            except Exception:
                pass
            self._aiohttp_session = None
        if HAVE_HTTPX:
            async with self._client_lock:
                for k, c in list(self._httpx_clients.items()):
                    try:
                        await c.aclose()
                    except Exception:
                        pass
                self._httpx_clients.clear()
        self.use_session_global = False
        if self._verbose:
            print("[UltraBoostedV13] sessions closed")

    async def close(self):
        await self.close_session()

    async def _save_sessions_to_file_async(self, path: Optional[str] = None, profile: str = "default"):
        p = path or self._session_file
        if not p:
            raise ValueError("Session file not configured")
        container = {}
        if os.path.exists(p):
            try:
                with open(p, "r", encoding="utf-8") as f:
                    container = json.load(f) or {}
            except Exception:
                container = {}
        cookies = await self.cookie_jar.to_dict()
        proxy_info = {}
        try:
            proxy_info = dict(self.proxy_manager._scores) if hasattr(self.proxy_manager, "_scores") else {}
        except Exception:
            proxy_info = {}
        payload = {
            "saved_at": int(_now()),
            "cookies": cookies,
            "proxy_scores": proxy_info,
            "ja3": self._ja3_profile,
            "header_builder": {"non_standard_obfuscation": self.header_builder.non_standard_obfuscation,
                                "smart_headers_mode": self.header_builder.smart_headers_mode}
        }
        container[profile] = payload
        with open(p, "w", encoding="utf-8") as f:
            json.dump(container, f, ensure_ascii=False, indent=2)
        if self._verbose:
            print("[UltraBoostedV13] sessions saved to %s (profile=%s)", p, profile)

    def save_sessions_to_file(self, path: Optional[str] = None, profile: str = "default"):
        p = path or self._session_file
        if not p:
            raise ValueError("Session file not configured")
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None
        if loop and loop.is_running():
            asyncio.create_task(self._save_sessions_to_file_async(path=p, profile=profile))
            return
        loop = asyncio.new_event_loop()
        try:
            asyncio.set_event_loop(loop)
            loop.run_until_complete(self._save_sessions_to_file_async(path=p, profile=profile))
        finally:
            try:
                loop.close()
            except Exception:
                pass

    async def _load_sessions_from_file_async(self, path: Optional[str] = None, profile: str = "default", merge: bool = True):
        p = path or self._session_file
        if not p or not os.path.exists(p):
            if self._verbose:
                print("[UltraBoostedV13] session file not found %s", p)
            return
        with open(p, "r", encoding="utf-8") as f:
            container = json.load(f) or {}
        payload = container.get(profile)
        if not payload:
            if self._verbose:
                print("[UltraBoostedV13] profile %s not found in %s", profile, p)
            return
        cookies = payload.get("cookies") or {}
        await self.cookie_jar.merge_from_dict(cookies)
        proxy_scores = payload.get("proxy_scores") or {}
        try:
            async with self.proxy_manager._lock:
                for k, v in proxy_scores.items():
                    self.proxy_manager._scores[k] = v
        except Exception:
            pass
        hb = payload.get("header_builder") or {}
        try:
            self.header_builder.non_standard_obfuscation = hb.get("non_standard_obfuscation", self.header_builder.non_standard_obfuscation)
            self.header_builder.smart_headers_mode = hb.get("smart_headers_mode", self.header_builder.smart_headers_mode)
        except Exception:
            pass
        if self._verbose:
            print("[UltraBoostedV13] sessions loaded from %s profile=%s", p, profile)

    def load_sessions_from_file(self, path: Optional[str] = None, profile: str = "default", merge: bool = True):
        p = path or self._session_file
        if not p or not os.path.exists(p):
            if self._verbose:
                print("[UltraBoostedV13] session file not found %s", p)
            return
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None
        if loop and loop.is_running():
            asyncio.create_task(self._load_sessions_from_file_async(path=p, profile=profile, merge=merge))
            return
        loop = asyncio.new_event_loop()
        try:
            asyncio.set_event_loop(loop)
            loop.run_until_complete(self._load_sessions_from_file_async(path=p, profile=profile, merge=merge))
        finally:
            try:
                loop.close()
            except Exception:
                pass

    def start_auto_session_saver(self, path: Optional[str] = None, interval: int = 30, profile: str = "default"):
        if self._auto_session_task and not self._auto_session_task.done():
            return
        self._session_file = path or self._session_file
        if not self._session_file:
            raise ValueError("No session file path configured")
        self._auto_session_interval = interval
        self._auto_session_profile = profile
        self._auto_session_task = asyncio.create_task(self._auto_session_loop())
        if self._verbose:
            print("[UltraBoostedV13] auto session saver started -> %s (every %ss)", self._session_file, interval)

    async def _auto_session_loop(self):
        try:
            while True:
                try:
                    await self._save_sessions_to_file_async(self._session_file, getattr(self, '_auto_session_profile', 'default'))
                except Exception as e:
                    if self._verbose:
                        logger.warning("[UltraBoostedV13] auto session save failed: %s", e)
                await asyncio.sleep(self._auto_session_interval)
        except asyncio.CancelledError:
            if self._verbose:
                print("[UltraBoostedV13] auto session saver stopped")

    def stop_auto_session_saver(self):
        if self._auto_session_task:
            self._auto_session_task.cancel()
            self._auto_session_task = None

    def _fragment(self, data: bytes, min_size: int = 2, max_size: int = 64, bypass_like: bool = False) -> List[bytes]:
        chunks = []
        i = 0
        L = len(data)
        while i < L:
            size = random.randint(min_size, min(max_size, max(min_size, L - i)))
            chunks.append(data[i:i+size])
            i += size
        return chunks

    async def _raw_tls_request(self, method: str, url: str, headers: Dict[str, str], data: Optional[bytes], proxy: Optional[str]) -> Tuple[int, bytes, Dict[str, str]]:
        parsed = urlparse(url)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query

        ctx = ssl.create_default_context()
        ctx.set_alpn_protocols(["h2", "http/1.1"])

        reader = None
        writer = None
        try:
            if proxy:
                p = proxy
                if p.startswith("http://"):
                    p = p[len("http://"):]
                if p.startswith("https://"):
                    p = p[len("https://"):]
                if "@" in p:
                    creds, hostport = p.split("@", 1)
                    p_host, p_port = hostport.split(":", 1)
                    p_port = int(p_port)
                    auth = base64.b64encode(creds.encode()).decode()
                    auth_hdr = f"Proxy-Authorization: Basic {auth}"
                else:
                    p_host, p_port = p.split(":", 1)
                    p_port = int(p_port)
                    auth_hdr = ""
                reader, writer = await asyncio.open_connection(p_host, p_port)
                connect = f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: keep-alive\r\n{auth_hdr}\r\n\r\n"
                writer.write(connect.encode())
                await writer.drain()
                status_line = await reader.readline()
                if not status_line:
                    raise RuntimeError("Empty proxy response for CONNECT")
                sl = status_line.decode(errors="ignore").strip()
                if "200" not in sl:
                    rest = await reader.read(1024)
                    raise RuntimeError(f"Proxy CONNECT failed: {sl} {rest[:200]!r}")
                while True:
                    l = await reader.readline()
                    if not l or l in (b"\r\n", b""):
                        break
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass
                reader, writer = await asyncio.open_connection(host, port, ssl=ctx, server_hostname=host)
            else:
                reader, writer = await asyncio.open_connection(host, port, ssl=ctx, server_hostname=host)

            hdrs = dict(headers)
            hdrs.setdefault("Host", host)
            hdrs.setdefault("Connection", "close")
            if data:
                hdrs.setdefault("Content-Length", str(len(data)))
            lines = [f"{method} {path} HTTP/1.1\r\n"]
            for k, v in hdrs.items():
                lines.append(f"{k}: {v}\r\n")
            lines.append("\r\n")
            req = "".join(lines).encode()
            if data:
                req += data
            writer.write(req)
            await writer.drain()

            status_line = await reader.readline()
            if not status_line:
                raise RuntimeError("no response")
            sl = status_line.decode(errors="ignore").strip()
            try:
                status = int(sl.split()[1])
            except Exception:
                status = 0
            resp_headers: Dict[str, str] = {}
            while True:
                l = await reader.readline()
                if not l or l in (b"\r\n", b""):
                    break
                d = l.decode(errors="ignore")
                if ":" in d:
                    k, v = d.split(":", 1)
                    resp_headers[k.strip().lower()] = v.strip()
            body = b""
            if "content-length" in resp_headers:
                try:
                    remaining = int(resp_headers["content-length"])
                except Exception:
                    remaining = 0
                while remaining > 0:
                    chunk = await reader.read(min(65536, remaining))
                    if not chunk:
                        break
                    body += chunk
                    remaining -= len(chunk)
            else:
                b = await reader.read()
                while b:
                    body += b
                    b = await reader.read()
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            return status, body, resp_headers
        except Exception:
            try:
                if writer:
                    writer.close()
                    await writer.wait_closed()
            except Exception:
                pass
            raise

    async def _do_request(self, method: str, url: str, headers: Optional[Dict[str, str]] = None,
                          data: Optional[bytes] = None, auto_cookie: bool = True, use_session: Optional[bool] = None) -> Dict[str, Any]:
        """Enhanced request method dengan anti-detection features"""
        
        # Apply smart delay
        delay = self.anti_detection.calculate_smart_delay()
        await asyncio.sleep(delay)
        
        # Check if fingerprint rotation needed
        if self.anti_detection.should_rotate_fingerprint():
            if self.verbose:
                print("[UltraBoostedV13] Rotating fingerprint...")
            self._ja3_profile = self._make_ja3_profile()
            self.anti_detection.last_rotation = time.time()
        
        # Continue dengan existing logic...
        async with self.semaphore:
            if not await self.circuit.can_request():
                return {"status": None, "body": b"CIRCUIT_BLOCKED", "headers": {}, "_proxy_used": None}

            merged_common = {}
            if headers:
                merged_common.update(headers)

            last_exc = None
            chosen_proxy = None

            use_session_effective = self.use_session_global if use_session is None else use_session

            for attempt in range(1, self.max_retries + 1):
                ja3 = self._ja3_profile or self._make_ja3_profile() if self.rotate_ja3 else "default"
                proxy = await self.proxy_manager.pick(auto_rotate=self.auto_rotate_proxy) if self.use_proxy else None
                chosen_proxy = proxy
                domain = urlparse(url).hostname or ""

                if auto_cookie:
                    ch = await self.cookie_jar.get_cookie_header(domain)
                    if ch:
                        merged_common["Cookie"] = ch

                extra_for_build = {}
                if self.header_builder and getattr(self.header_builder, "smart_headers_mode", None) == 'A':
                    parsed = urlparse(url)
                    origin = f"{parsed.scheme}://{parsed.netloc}"
                    extra_for_build.setdefault('Origin', origin)
                    extra_for_build.setdefault('Referer', url)

                session_headers = self.header_builder.build(extra=extra_for_build, common=merged_common)

                if self.http2_priority_hint and random.random() < 0.05:
                    session_headers.setdefault('X-HTTP2-Priority-Hint', 'u=254,i=0')

                body_bytes = None
                if data is not None:
                    if isinstance(data, bytes):
                        body_bytes = data
                    else:
                        body_bytes = bytes(data)

                if self.header_builder and self.header_builder.non_standard_obfuscation and random.random() < 0.1:
                    await asyncio.sleep(random.uniform(0.01, 0.1))

                # Enhanced: Add security fingerprint to headers
                fingerprint = self.security_manager.generate_request_fingerprint()
                session_headers["X-Request-Fingerprint"] = fingerprint['session_id']
                session_headers["X-Timestamp-Millis"] = str(fingerprint['timestamp'])

                if HAVE_HTTPX:
                    client = None
                    try:
                        if use_session_effective:
                            client = await self._ensure_httpx_for_proxy(proxy)
                        else:
                            try:
                                client = httpx.AsyncClient(http2=True, timeout=self.timeout, proxies=({"http://": proxy, "https://": proxy} if proxy else None))
                            except Exception:
                                client = None

                        if client is None:
                            raise RuntimeError("no httpx client available")

                        req_kwargs = {"headers": session_headers}
                        if body_bytes:
                            req_kwargs["content"] = body_bytes
                        fn = getattr(client, method.lower())
                        resp = await fn(url, **req_kwargs)
                        status = getattr(resp, "status_code", resp.status_code)
                        content = resp.content

                        try:
                            sc_all = resp.headers.get("set-cookie")
                            if sc_all:
                                scs = [s.strip() for s in re.split(r', (?=[^;]+=)', sc_all)] if ',' in sc_all else [sc_all]
                                for sc in scs:
                                    try:
                                        await self.cookie_jar.update_from_set_cookie_header(domain, sc)
                                    except Exception:
                                        pass
                        except Exception:
                            pass

                        if not use_session_effective and client is not None:
                            try:
                                await client.aclose()
                            except Exception:
                                pass

                        if status and status < 500:
                            if proxy:
                                await self.proxy_manager.score_success(proxy)
                            await self.circuit.record_success()
                            return {"status": status, "body": content, "headers": dict(resp.headers), "_proxy_used": proxy, "ja3": ja3}
                        else:
                            last_exc = RuntimeError(f"httpx status {status}")
                            if proxy:
                                await self.proxy_manager.mark_bad(proxy)
                            if self._verbose:
                                logger.warning("[UltraBoostedV13] httpx attempt %s status %s proxy=%s", attempt, status, proxy)
                    except Exception as e:
                        last_exc = e
                        if self._verbose:
                            logger.warning("[UltraBoostedV13] httpx attempt %s exception=%s proxy=%s", attempt, e, proxy)

                session = None
                close_session_local = False
                try:
                    if use_session_effective:
                        await self._ensure_aiohttp()
                        session = self._aiohttp_session
                    else:
                        session = aiohttp.ClientSession(trust_env=True)
                        close_session_local = True

                    req_kwargs = {"headers": session_headers, "timeout": aiohttp.ClientTimeout(total=self.timeout)}
                    if proxy:
                        req_kwargs["proxy"] = proxy

                    if method.upper() == "GET":
                        async with session.get(url, **req_kwargs) as r:
                            content = await r.read()
                            status = r.status
                            try:
                                cookies = {k: v.value for k, v in r.cookies.items()}
                                if cookies:
                                    for k, v in cookies.items():
                                        await self.cookie_jar.set_cookie(domain, k, v)
                            except Exception:
                                pass
                            try:
                                sc_headers = []
                                try:
                                    sc_headers = r.headers.getall('Set-Cookie', [])
                                except Exception:
                                    try:
                                        sc_headers = [h.decode() for (h, v) in r.raw_headers if h.decode().lower() == 'set-cookie']
                                    except Exception:
                                        sc_headers = []
                                for sc in sc_headers:
                                    try:
                                        await self.cookie_jar.update_from_set_cookie_header(domain, sc)
                                    except Exception:
                                        pass
                            except Exception:
                                pass

                            if status < 500:
                                if proxy:
                                    await self.proxy_manager.score_success(proxy)
                                await self.circuit.record_success()
                                return {"status": status, "body": content, "headers": dict(r.headers), "_proxy_used": proxy, "ja3": ja3}
                            else:
                                last_exc = RuntimeError(f"aiohttp status {status}")
                                if proxy:
                                    await self.proxy_manager.mark_bad(proxy)
                                if self._verbose:
                                    logger.warning("[UltraBoostedV13] aiohttp attempt %s status %s proxy=%s", attempt, status, proxy)
                    else:
                        async with session.request(method, url, data=body_bytes, **req_kwargs) as r:
                            content = await r.read()
                            status = r.status
                            try:
                                cookies = {k: v.value for k, v in r.cookies.items()}
                                if cookies:
                                    for k, v in cookies.items():
                                        await self.cookie_jar.set_cookie(domain, k, v)
                            except Exception:
                                pass
                            try:
                                sc_headers = []
                                try:
                                    sc_headers = r.headers.getall('Set-Cookie', [])
                                except Exception:
                                    try:
                                        sc_headers = [h.decode() for (h, v) in r.raw_headers if h.decode().lower() == 'set-cookie']
                                    except Exception:
                                        sc_headers = []
                                for sc in sc_headers:
                                    try:
                                        await self.cookie_jar.update_from_set_cookie_header(domain, sc)
                                    except Exception:
                                        pass
                            except Exception:
                                pass

                            if status < 500:
                                if proxy:
                                    await self.proxy_manager.score_success(proxy)
                                await self.circuit.record_success()
                                return {"status": status, "body": content, "headers": dict(r.headers), "_proxy_used": proxy, "ja3": ja3}
                            else:
                                last_exc = RuntimeError(f"aiohttp status {status}")
                                if proxy:
                                    await self.proxy_manager.mark_bad(proxy)
                                if self._verbose:
                                    logger.warning("[UltraBoostedV13] aiohttp attempt %s status %s proxy=%s", attempt, status, proxy)
                except Exception as e:
                    last_exc = e
                    if self._verbose:
                        logger.warning("[UltraBoostedV13] aiohttp attempt %s exception=%s proxy=%s", attempt, e, proxy)
                finally:
                    if close_session_local and session is not None:
                        try:
                            if not session.closed:
                                await session.close()
                        except Exception:
                            pass

                try:
                    status, content, resp_headers = await self._raw_tls_request(method, url, session_headers, body_bytes, proxy)
                    try:
                        sc_candidates = []
                        for k, v in resp_headers.items():
                            if k.lower() == "set-cookie":
                                if isinstance(v, (list, tuple)):
                                    sc_candidates.extend(v)
                                else:
                                    sc_candidates.append(v)
                        for sc in sc_candidates:
                            try:
                                await self.cookie_jar.update_from_set_cookie_header(domain, sc)
                            except Exception:
                                pass
                    except Exception:
                        pass

                    if status < 500:
                        if proxy:
                            await self.proxy_manager.score_success(proxy)
                        await self.circuit.record_success()
                        return {"status": status, "body": content, "headers": resp_headers, "_proxy_used": proxy, "ja3": ja3}
                    else:
                        last_exc = RuntimeError(f"raw-tls status {status}")
                        if proxy:
                            await self.proxy_manager.mark_bad(proxy)
                except Exception as e:
                    last_exc = e
                    if self._verbose:
                        logger.warning("[UltraBoostedV13] raw-tls attempt %s exception=%s proxy=%s", attempt, e, proxy)

                base = min(0.5 * (2 ** (attempt - 1)), 8.0)
                jitter = random.uniform(0, 0.4)
                await asyncio.sleep(base + jitter)

            if self._verbose:
                logger.error("[UltraBoostedV13] all retries failed for %s last_exc=%s", url, last_exc)
            await self.circuit.record_failure()
            return {"status": None, "body": b"", "headers": {}, "_proxy_used": chosen_proxy, "error": str(last_exc)}

    async def get(self, url: str, headers: Optional[Dict[str, str]] = None, use_session: Optional[bool] = None) -> Dict[str, Any]:
        return await self._do_request("GET", url, headers=headers, data=None, use_session=use_session)

    async def post(self, url: str, data: Optional[Any] = None, headers: Optional[Dict[str, str]] = None, use_session: Optional[bool] = None) -> Dict[str, Any]:
        bdata = None
        if data is not None:
            if isinstance(data, (bytes, bytearray)):
                bdata = bytes(data)
            elif isinstance(data, str):
                bdata = data.encode()
            else:
                bdata = json.dumps(data).encode()
        return await self._do_request("POST", url, headers=headers, data=bdata, use_session=use_session)

    async def get_json(self, url: str, headers: Optional[Dict[str, str]] = None, use_session: Optional[bool] = None) -> Optional[Dict[str, Any]]:
        r = await self.get(url, headers=headers, use_session=use_session)
        if not r or r.get("status") != 200 or not r.get("body"):
            return None
        try:
            j = json.loads(r["body"].decode())
            j["_status"] = r["status"]
            j["_proxy_used"] = r["_proxy_used"]
            return j
        except Exception:
            try:
                return {"_status": r.get("status"), "_proxy_used": r.get("_proxy_used"), "text": r.get("body").decode(errors="ignore")}
            except Exception:
                return None

    async def post_json(self, url: str, data: Any = None, headers: Optional[Dict[str, str]] = None, use_session: Optional[bool] = None) -> Optional[Dict[str, Any]]:
        r = await self.post(url, data=data, headers=headers, use_session=use_session)
        if not r or r.get("status") != 200 or not r.get("body"):
            return None
        try:
            j = json.loads(r["body"].decode())
            j["_status"] = r["status"]
            j["_proxy_used"] = r["_proxy_used"]
            return j
        except Exception:
            try:
                return {"_status": r.get("status"), "_proxy_used": r.get("_proxy_used"), "text": r.get("body").decode(errors="ignore")}
            except Exception:
                return None

    async def add_proxy(self, proxy: str):
        await self.proxy_manager.add(proxy)

    async def remove_proxy(self, proxy: str):
        await self.proxy_manager.remove(proxy)

    def set_mandatory_headers(self, headers: Dict[str, Any]):
        self.header_builder.smart_headers_mode = headers.get("smart_headers_mode", self.header_builder.smart_headers_mode)

# ============================================================================
# MAIL SERVICES (FIXED)
# ============================================================================

class MailTm:
    """Mail.tm service - ✅ FIXED: subject typo"""
    
    API = "https://api.mail.tm"

    def __init__(self):
        self.email = None
        self.password = None
        self.token = None

    @staticmethod
    def random_string(n=10):
        return ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(n))

    def register(self):
        try:
            domains = requests.get(f"{self.API}/domains", timeout=10).json()
            domain = random.choice(domains["hydra:member"])["domain"]
            
            self.email = f"{self.random_string()}@{domain}"
            self.password = self.random_string(12)

            r = requests.post(f"{self.API}/accounts", json={
                "address": self.email,
                "password": self.password
            }, timeout=10)

            if r.status_code != 201:
                logger.warning("[MailTm] Registration failed: %s", r.status_code)
                return None

            r = requests.post(f"{self.API}/token", json={
                "address": self.email,
                "password": self.password
            }, timeout=10)

            if r.status_code != 200:
                logger.warning("[MailTm] Token failed: %s", r.status_code)
                return None

            self.token = r.json().get("token")
            return self.email
        except Exception as e:
            logger.error("[MailTm] Register error: %s", e)
            return None

    def wait_for_email(self, max_attempts=20):
        """✅ FIXED: ssessionject → subject"""
        if not self.token:
            return None

        headers = {"Authorization": f"Bearer {self.token}"}

        for attempt in range(1, max_attempts + 1):
            try:
                inbox = requests.get(f"{self.API}/messages", headers=headers, timeout=10).json()
                items = inbox.get("hydra:member", [])

                if items:
                    for msg in items:
                        subject = msg.get("subject", "")
                        msg_id = msg["id"]

                        match_subject = re.search(r"(\d{6})\s+is your Instagram code", subject)
                        if match_subject:
                            return match_subject.group(1)

                        detail = requests.get(f"{self.API}/messages/{msg_id}", headers=headers, timeout=10).json()
                        text = detail.get("text", "")

                        match_body = re.search(r"\b(\d{6})\b", text)
                        if match_body:
                            return match_body.group(1)

                time.sleep(1)
            except Exception as e:
                logger.debug("[MailTm] wait_for_email error: %s", e)
                time.sleep(2)
        
        return None


HEADERS = {
    "Host": "10minutemail.net",
    "accept": "application/json, text/javascript, */*; q=0.01",
    "x-requested-with": "XMLHttpRequest",
    "sec-ch-ua-mobile": "?1",
    "user-agent": "Mozilla/5.0 (Linux; Android 13; SM-A135F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Mobile Safari/537.36",
    "referer": "https://10minutemail.net/m/?lang=id",
    "accept-encoding": "identity",
    "accept-language": "id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7",
}


class Sepuluh:
    ses = requests.Session()
    ses.trust_env = False
    ses.headers.update(HEADERS)

    # -----------------------------
    #  INIT SESSION (stable)
    # -----------------------------
    @staticmethod
    def _init_session():
        for attempt in range(1, 4):
            try:
                r = Sepuluh.ses.get(
                    "https://10minutemail.net",
                    timeout=15,
                    verify=False
                )
                if r.status_code == 200:
                    return True
            except:
                pass
            # print(f"[INIT RETRY {attempt}/3] gagal init session…")
            time.sleep(1)
        # print("[FATAL] Gagal init session")
        return False

    # -----------------------------
    #  GET EMAIL
    # -----------------------------
    @staticmethod
    def get_mail(name, retry=5):
        if not Sepuluh._init_session():
            return None

        for attempt in range(1, retry + 1):
            waktu = int(time.time() * 1000)
            url = f"https://10minutemail.net/address.api.php?new=1&_={waktu}"

            try:
                resp = Sepuluh.ses.get(url, timeout=15, verify=False)
                resp.raise_for_status()

                # JSON parse
                data = resp.json()
                email = data.get("mail_get_mail")

                if email:
                    # print("[OK] Email:", email)
                    return email

            except Exception as e:
                # print(f"[RETRY {attempt}/{retry}] get_email error:", str(e))
                time.sleep(2)

        # print("[ERROR] Email gagal diambil setelah semua retry")
        return None

    # -----------------------------
    #  GET CODE (Instagram)
    # -----------------------------
    @staticmethod
    def get_code(timeout=20):
        if not Sepuluh._init_session():
            return None

        start = time.time()

        while time.time() - start < timeout:
            waktu = int(time.time() * 1000)
            url = f"https://10minutemail.net/address.api.php?_={waktu}"

            try:
                resp = Sepuluh.ses.get(url, timeout=5, verify=False)
                data = resp.json()
            except:
                time.sleep(2)
                continue

            if "Instagram" in str(data):
                code = re.findall('\'subject\': \'(.*?) is your Instagram code\',', str(data))[0]
                return code

            time.sleep(2)

        # print("[TIMEOUT] Tidak ada kode masuk dalam waktu", timeout, "detik")
        return None


class GmailAlias:
    """Generate Gmail alias dinamis dengan validasi"""
    
    def __init__(self, base_email):
        if "@gmail.com" not in base_email:
            raise ValueError("Hanya mendukung email @gmail.com")
        self.base_email = base_email
        self.local, self.domain = base_email.split("@")
        self.used_dot_positions = set()  # Track positions yang sudah dipakai

    def _clean_local_part(self, local_part):
        """Bersihkan local part dari dots berlebihan"""
        # Remove consecutive dots
        while '..' in local_part:
            local_part = local_part.replace('..', '.')
        # Remove dots at start/end
        local_part = local_part.strip('.')
        return local_part

    def unique_alias(self, dots=2, plus_length=6):
        """Generate unique alias dengan dots yang terdistribusi"""
        chars = list(self.local.replace('.', ''))  # Remove existing dots first
        
        # Generate unique dot positions (no duplicates, no adjacent)
        available_positions = list(range(1, len(chars)))  # Positions between chars
        if not available_positions:
            available_positions = [1]  # Fallback untuk very short emails
            
        # Pilih positions yang belum digunakan dan tidak adjacent
        selected_positions = []
        attempts = 0
        max_attempts = 10
        
        while len(selected_positions) < min(dots, len(available_positions)) and attempts < max_attempts:
            pos = random.choice(available_positions)
            
            # Check jika position valid (tidak adjacent dengan yang sudah dipilih)
            valid_position = True
            for selected in selected_positions:
                if abs(pos - selected) <= 1:  # Tidak boleh adjacent
                    valid_position = False
                    break
            
            if valid_position and pos not in selected_positions:
                selected_positions.append(pos)
                self.used_dot_positions.add(pos)
            
            attempts += 1
        
        # Sort positions descending untuk insert dari belakang
        for pos in sorted(selected_positions, reverse=True):
            if pos < len(chars):
                chars.insert(pos, ".")
        
        alias_local = "".join(chars)
        alias_local = self._clean_local_part(alias_local)
        
        # Generate unique suffix
        timestamp = str(int(time.time() * 1000))[-6:]  # Last 6 digits
        rand_plus = "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(plus_length))
        hash_str = hashlib.sha1(f"{self.base_email}{timestamp}{rand_plus}".encode()).hexdigest()[:4]
        
        return f"{alias_local}+{timestamp}{rand_plus}{hash_str}@{self.domain}"

    def custom_alias(self, custom_text=""):
        """Generate alias dengan custom text"""
        # Clean custom text
        clean_text = "".join(c for c in custom_text if c.isalnum()).lower()
        if not clean_text:
            clean_text = "ig"
        
        # Combine base local dengan custom text (tanpa dots berlebihan)
        base_local = self.local.replace('.', '')
        combined = base_local + clean_text
        
        # Add max 1 dot secara random
        if len(combined) > 1:
            available_positions = list(range(1, len(combined)))
            if available_positions:
                dot_pos = random.choice(available_positions)
                # Pastikan tidak double dots
                if dot_pos > 0 and dot_pos < len(combined):
                    if combined[dot_pos-1] != '.' and (dot_pos >= len(combined) or combined[dot_pos] != '.'):
                        combined = combined[:dot_pos] + "." + combined[dot_pos:]
        
        alias_local = self._clean_local_part(combined)
        
        return f"{alias_local}+{int(time.time())}@{self.domain}"

    def simple_alias(self):
        """Alias sederhana tanpa dots tambahan"""
        timestamp = str(int(time.time() * 1000))[-4:]
        return f"{self.local}+ig{timestamp}@{self.domain}"

    def batch_aliases(self, count=5):
        """Generate batch of unique aliases"""
        aliases = set()
        strategies = [self.unique_alias, self.custom_alias, self.simple_alias]
        
        while len(aliases) < count:
            strategy = random.choice(strategies)
            try:
                if strategy == self.unique_alias:
                    alias = strategy(dots=random.randint(1, 2))
                elif strategy == self.custom_alias:
                    alias = strategy(custom_text=random.choice(["ig", "app", "social", "acc", "new"]))
                else:
                    alias = strategy()
                
                if alias not in aliases:
                    aliases.add(alias)
                    
            except Exception as e:
                print(f"   ⚠️ Alias generation error: {e}")
                continue
        
        return list(aliases)

class BehaviorAnalyzer:
    """Analyze & simulate realistic user behavior"""
    
    def __init__(self):
        self.request_patterns: List[Dict[str, Any]] = []
        self.action_timings: Dict[str, List[float]] = {}
        self.mouse_movements: List[Tuple[int, int]] = []
        self.key_presses: List[str] = []
        self.scroll_positions: List[int] = []
        self.page_view_times: Dict[str, float] = {}
        self.referrer_chain: List[str] = []

    def record_action(self, action: str, timestamp: float, data: Optional[Dict] = None):
        """Record user action dengan timing"""
        if action not in self.action_timings:
            self.action_timings[action] = []
        self.action_timings[action].append(timestamp)
        
        self.request_patterns.append({
            "action": action,
            "timestamp": timestamp,
            "data": data or {}
        })

    def get_action_interval(self, action: str) -> Optional[float]:
        """Get average time between actions"""
        times = self.action_timings.get(action, [])
        if len(times) < 2:
            return None
        
        intervals = [times[i+1] - times[i] for i in range(len(times)-1)]
        return sum(intervals) / len(intervals)

    def is_suspicious(self) -> bool:
        """Check if behavior is suspicious"""
        
        # Check for too many requests too fast
        if len(self.request_patterns) > 0:
            time_span = self.request_patterns[-1]["timestamp"] - self.request_patterns[0]["timestamp"]
            if time_span > 0:
                req_per_sec = len(self.request_patterns) / time_span
                if req_per_sec > 5:  # More than 5 requests/sec = suspicious
                    return True
        
        # Check for no variation in action intervals
        for action, times in self.action_timings.items():
            if len(times) >= 3:
                intervals = [times[i+1] - times[i] for i in range(len(times)-1)]
                variance = sum((x - sum(intervals)/len(intervals))**2 for x in intervals) / len(intervals)
                if variance < 0.01:  # No variance = bot-like
                    return True
        
        return False


class FingerprintRotator:
    """Advanced fingerprint rotation untuk avoid detection"""
    
    def __init__(self):
        self.used_fingerprints: Set[str] = set()
        self.fingerprint_history: List[Dict[str, Any]] = []
        self.os_list = ["mac", "windows", "linux"]
        self.browser_versions = list(range(115, 131))
        
    def generate_unique_fingerprint(self) -> Dict[str, Any]:
        """Generate truly unique fingerprint"""
        
        # Ensure uniqueness
        attempts = 0
        while attempts < 10:
            os_name = random.choice(self.os_list)
            fp = ChromeFingerprintSuperRealistic(os_name=os_name, stable=False)
            
            # Create fingerprint hash
            fp_hash = hashlib.sha256(
                f"{fp.user_agent()}{fp.chrome_version()}".encode()
            ).hexdigest()
            
            if fp_hash not in self.used_fingerprints:
                self.used_fingerprints.add(fp_hash)
                
                fingerprint_data = {
                    "hash": fp_hash,
                    "os": os_name,
                    "ua": fp.user_agent(),
                    "chrome_version": fp.chrome_version(),
                    "timestamp": _now(),
                    "platform": fp.platform_label(),
                }
                
                self.fingerprint_history.append(fingerprint_data)
                return fingerprint_data
            
            attempts += 1
        
        # Fallback
        return {"hash": str(uuid.uuid4()), "ua": COMMON_UAS[0]}

    def get_rotation_strategy(self) -> str:
        """Determine fingerprint rotation strategy"""
        
        history_len = len(self.fingerprint_history)
        
        if history_len == 0:
            return "stable"  # First request - stable
        elif history_len < 5:
            return "gradual"  # Gradual changes
        elif history_len < 20:
            return "moderate"  # Moderate rotation
        else:
            return "aggressive"  # Full rotation


class ProxyHealthMonitor:
    """Monitor proxy health & reliability"""
    
    def __init__(self):
        self.proxy_stats: Dict[str, Dict[str, Any]] = {}
        self.proxy_blacklist: Set[str] = set()
        self.proxy_whitelist: Set[str] = set()

    async def test_proxy(self, proxy: str, timeout: int = 10) -> bool:
        """Test proxy connectivity & speed"""
        
        try:
            test_urls = [
                "https://www.instagram.com",
                "https://www.google.com",
                "https://httpbin.org/ip"
            ]
            
            start_time = _now()
            
            async with aiohttp.ClientSession() as session:
                for url in test_urls:
                    try:
                        async with session.get(
                            url, 
                            proxy=proxy, 
                            timeout=aiohttp.ClientTimeout(total=timeout),
                            ssl=False
                        ) as resp:
                            if resp.status == 200:
                                latency = _now() - start_time
                                
                                if proxy not in self.proxy_stats:
                                    self.proxy_stats[proxy] = {
                                        "tests": 0,
                                        "successes": 0,
                                        "failures": 0,
                                        "avg_latency": 0,
                                        "last_test": _now()
                                    }
                                
                                stats = self.proxy_stats[proxy]
                                stats["tests"] += 1
                                stats["successes"] += 1
                                stats["avg_latency"] = (
                                    (stats["avg_latency"] * (stats["successes"]-1) + latency) / 
                                    stats["successes"]
                                )
                                stats["last_test"] = _now()
                                
                                if latency > 30:  # Very slow
                                    return False
                                
                                return True
                    except Exception:
                        continue
            
            # Failed all tests
            if proxy in self.proxy_stats:
                self.proxy_stats[proxy]["failures"] += 1
                self.proxy_stats[proxy]["last_test"] = _now()
            
            return False
        
        except Exception as e:
            logger.warning("[ProxyHealthMonitor] Test error: %s", e)
            return False

    def is_proxy_healthy(self, proxy: str) -> bool:
        """Check if proxy is healthy"""
        
        if proxy in self.proxy_blacklist:
            return False
        
        if proxy in self.proxy_whitelist:
            return True
        
        if proxy not in self.proxy_stats:
            return True  # Unknown - assume healthy
        
        stats = self.proxy_stats[proxy]
        
        # Success rate > 80%
        if stats["tests"] > 0:
            success_rate = stats["successes"] / stats["tests"]
            if success_rate < 0.8:
                return False
        
        # Latency < 20s
        if stats["avg_latency"] > 20:
            return False
        
        # Last tested < 1 hour ago
        if _now() - stats["last_test"] > 3600:
            return False
        
        return True

    def blacklist_proxy(self, proxy: str):
        """Blacklist proxy"""
        self.proxy_blacklist.add(proxy)
        self.proxy_whitelist.discard(proxy)

    def whitelist_proxy(self, proxy: str):
        """Whitelist proxy"""
        self.proxy_whitelist.add(proxy)
        self.proxy_blacklist.discard(proxy)


class AnomalyDetector:
    """Detect & bypass Instagram anomaly detection"""
    
    def __init__(self):
        self.request_history: List[Dict[str, Any]] = []
        self.error_patterns: Dict[str, int] = {}
        self.challenge_count = 0
        self.rate_limit_count = 0

    def record_request(self, url: str, method: str, status: int, response_time: float):
        """Record request untuk analysis"""
        
        self.request_history.append({
            "url": url,
            "method": method,
            "status": status,
            "response_time": response_time,
            "timestamp": _now()
        })
        
        # Keep only last 1000 requests
        if len(self.request_history) > 1000:
            self.request_history = self.request_history[-1000:]

    def detect_challenges(self, response: Dict[str, Any]) -> bool:
        """Detect challenge/verification requirements"""
        
        try:
            body = response.get("body", b"").decode(errors="ignore")
            status = response.get("status")
            
            # Check for challenge keywords
            challenge_keywords = [
                "challenge", "verify", "security_code", "code_required",
                "action_required", "suspicious", "suspicious_activity",
                "please_verify", "confirm_identity", "confirm_login"
            ]
            
            for keyword in challenge_keywords:
                if keyword in body.lower():
                    self.challenge_count += 1
                    return True
            
            # Check for 403 Forbidden
            if status == 403:
                self.challenge_count += 1
                return True
            
            # Check for rate limit
            if status == 429 or "rate limit" in body.lower():
                self.rate_limit_count += 1
                return True
            
            return False
        
        except Exception:
            return False

    def get_anomaly_score(self) -> float:
        """Get overall anomaly detection score (0-1)"""
        
        if not self.request_history:
            return 0.0
        
        score = 0.0
        
        # Factor 1: Request frequency
        recent_requests = [
            r for r in self.request_history 
            if _now() - r["timestamp"] < 300  # Last 5 min
        ]
        if len(recent_requests) > 30:
            score += 0.3
        
        # Factor 2: Response times
        avg_response_time = sum(r["response_time"] for r in self.request_history) / len(self.request_history)
        if avg_response_time < 0.5:  # Too fast = bot-like
            score += 0.2
        
        # Factor 3: Error patterns
        error_rate = sum(1 for r in self.request_history if r["status"] >= 400) / len(self.request_history)
        if error_rate > 0.2:
            score += 0.3
        
        # Factor 4: Challenge count
        if self.challenge_count > 2:
            score += 0.2
        
        return min(score, 1.0)

    async def apply_evasion_strategy(self, score: float) -> float:
        """Apply evasion strategy based on anomaly score"""
        
        if score < 0.3:
            # Low suspicion - normal behavior
            delay = random.uniform(1.0, 2.0)
        elif score < 0.6:
            # Medium suspicion - increase delays
            delay = random.uniform(3.0, 5.0)
            await asyncio.sleep(2)  # Extra pause
        else:
            # High suspicion - aggressive evasion
            delay = random.uniform(10.0, 30.0)
            await asyncio.sleep(random.uniform(5.0, 10.0))  # Multiple pauses
        
        return delay


class DeviceIDRotator:
    """Rotate device IDs untuk avoid tracking"""
    
    def __init__(self):
        self.device_ids: Set[str] = set()
        self.device_id_history: List[str] = []
        self.current_device_id: Optional[str] = None

    def generate_device_id(self) -> str:
        """Generate new unique device ID"""
        
        for attempt in range(10):
            try:
                gen = UUDI_V6()
                device_id = gen.generate()
                
                if device_id not in self.device_ids:
                    self.device_ids.add(device_id)
                    self.device_id_history.append(device_id)
                    self.current_device_id = device_id
                    return device_id
            except Exception:
                pass
        
        # Fallback
        device_id = f"uuid_{int(time.time())}_{random.randint(100000, 999999)}"
        self.device_ids.add(device_id)
        self.device_id_history.append(device_id)
        self.current_device_id = device_id
        return device_id

    def get_device_id(self) -> str:
        """Get current device ID"""
        if not self.current_device_id:
            return self.generate_device_id()
        return self.current_device_id

    def rotate_device_id(self, force: bool = False) -> str:
        """Rotate to new device ID"""
        if force or random.random() < 0.1:  # 10% chance to rotate
            return self.generate_device_id()
        return self.get_device_id()


class SessionValidator:
    """Validate session health & consistency"""
    
    def __init__(self):
        self.session_cookies: Dict[str, str] = {}
        self.session_created_at: Optional[float] = None
        self.last_activity: Optional[float] = None
        self.activity_count = 0

    def start_session(self):
        """Mark session start"""
        self.session_created_at = _now()
        self.last_activity = _now()
        self.activity_count = 0

    def record_activity(self):
        """Record session activity"""
        self.last_activity = _now()
        self.activity_count += 1

    def is_session_valid(self, max_age: int = 3600) -> bool:
        """Check if session is still valid"""
        
        if not self.session_created_at:
            return False
        
        age = _now() - self.session_created_at
        if age > max_age:
            return False  # Session too old
        
        if not self.last_activity:
            return False
        
        inactivity = _now() - self.last_activity
        if inactivity > 600:  # 10 min inactivity
            return False  # Too much inactivity
        
        return True

    def get_session_health(self) -> float:
        """Get session health score (0-1)"""
        
        if not self.session_created_at:
            return 0.0
        
        age = _now() - self.session_created_at
        inactivity = _now() - (self.last_activity or _now())
        
        # Health based on age & activity
        age_score = max(0.0, 1.0 - (age / 3600))  # Decrease over 1 hour
        activity_score = max(0.0, 1.0 - (inactivity / 600))  # Decrease over 10 min
        
        return (age_score + activity_score) / 2

class ChallengeDetector:
    """Advanced challenge detection untuk Instagram"""
    
    def __init__(self):
        self.challenge_keywords = [
            "challenge", "verify", "security_code", "code_required",
            "action_required", "suspicious", "suspicious_activity",
            "please_verify", "confirm_identity", "confirm_login",
            "checkpoint", "security_challenge", "verify_email",
            "verify_phone", "two_factor", "unusual_activity"
        ]
        
        self.challenge_status_codes = [403, 401, 429, 400]
        self.challenge_history: List[Dict[str, Any]] = []

    def detect_challenge(self, response: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """Detect challenge dalam response"""
        
        try:
            status = response.get("status")
            body = response.get("body", b"").decode(errors="ignore").lower()
            headers = response.get("headers", {})
            
            # Check 1: Status code
            if status in self.challenge_status_codes:
                logger.warning("[ChallengeDetector] Challenge status code: %d", status)
                return True, f"status_code_{status}"
            
            # Check 2: Keywords dalam body
            for keyword in self.challenge_keywords:
                if keyword in body:
                    logger.warning("[ChallengeDetector] Challenge keyword detected: %s", keyword)
                    return True, f"keyword_{keyword}"
            
            # Check 3: Specific Instagram challenge responses
            if "action_required" in body or "action required" in body:
                return True, "action_required"
            
            if "challenge" in body and "instagram" in body:
                return True, "instagram_challenge"
            
            if "verification" in body and "required" in body:
                return True, "verification_required"
            
            # Check 4: Empty response dengan suspicious status
            if status in [400, 403] and len(body) < 100:
                return True, f"suspicious_empty_response_{status}"
            
            return False, None
        
        except Exception as e:
            logger.debug("[ChallengeDetector] Error: %s", e)
            return False, None

    def record_challenge(self, challenge_type: str, url: str, response_snippet: str):
        """Record challenge untuk analysis"""
        self.challenge_history.append({
            "type": challenge_type,
            "url": url,
            "timestamp": _now(),
            "response": response_snippet
        })

    def get_challenge_summary(self) -> str:
        """Get summary dari challenges"""
        if not self.challenge_history:
            return "No challenges detected"
        
        summary = f"Total challenges: {len(self.challenge_history)}\n"
        for ch in self.challenge_history[-5:]:  # Last 5
            summary += f"- {ch['type']} at {ch['url']}\n"
        
        return summary


class ChallengeBypassStrategy:
    """Strategy untuk bypass challenges"""
    
    def __init__(self):
        self.strategies = [
            "wait_and_retry",          # Wait & retry dengan delay
            "rotate_proxy",             # Ganti proxy
            "rotate_fingerprint",       # Ganti fingerprint
            "clear_cookies",            # Clear cookies
            "full_reset",              # Full reset session
            "switch_to_chromium",      # Switch ke chromium
            "use_different_email",     # Gunakan email baru
        ]

    async def apply_bypass(self, account: 'Account', challenge_type: str, 
                          strategy_index: int = 0) -> bool:
        """Apply bypass strategy"""
        
        if strategy_index >= len(self.strategies):
            logger.error("[ChallengeBypassStrategy] All strategies exhausted")
            return False
        
        strategy = self.strategies[strategy_index]
        
        logger.warning("[ChallengeBypassStrategy] Applying strategy %d/%d: %s",
                      strategy_index + 1, len(self.strategies), strategy)
        
        try:
            if strategy == "wait_and_retry":
                wait_time = 15 * (strategy_index + 1)
                print("[ChallengeBypassStrategy] Waiting %d seconds...", wait_time)
                await asyncio.sleep(wait_time)
                return True
            
            elif strategy == "rotate_proxy":
                print("[ChallengeBypassStrategy] Rotating proxy...")
                try:
                    if account.session.proxy_manager:
                        new_proxy = await account.session.proxy_manager.pick(auto_rotate=True)
                        if new_proxy and new_proxy != account.bound_proxy:
                            account.bound_proxy = new_proxy
                            print("[ChallengeBypassStrategy] Proxy rotated: %s", 
                                      new_proxy[:50])
                            return True
                except Exception as e:
                    logger.warning("[ChallengeBypassStrategy] Proxy rotation failed: %s", e)
                    return False
            
            elif strategy == "rotate_fingerprint":
                print("[ChallengeBypassStrategy] Rotating fingerprint...")
                try:
                    account.fp = ChromeFingerprintSuperRealistic(os_name="mac", stable=False)
                    account.ig_meta = InstagramHeaderAutoSync(account.fp)
                    meta = account.ig_meta.generate()
                    account.asbd_id = meta.get("asbd_id")
                    account.app_id = meta.get("app_id")
                    account.ajax = meta.get("ajax")
                    account.ua = meta.get("ua")
                    
                    account.hb = HeaderBuilderV5(device="macbook", stable_session=False)
                    account.base_headers = account.hb.build_with_ig_meta()
                    
                    print("[ChallengeBypassStrategy] Fingerprint rotated")
                    return True
                except Exception as e:
                    logger.warning("[ChallengeBypassStrategy] Fingerprint rotation failed: %s", e)
                    return False
            
            elif strategy == "clear_cookies":
                print("[ChallengeBypassStrategy] Clearing cookies...")
                try:
                    account.session.cookie_jar = SafeCookieJar()
                    print("[ChallengeBypassStrategy] Cookies cleared")
                    return True
                except Exception as e:
                    logger.warning("[ChallengeBypassStrategy] Cookie clear failed: %s", e)
                    return False
            
            elif strategy == "full_reset":
                print("[ChallengeBypassStrategy] Full reset...")
                try:
                    # Stop chromium
                    if account.chromium_started:
                        await account.stop_chromium()
                        await asyncio.sleep(2)
                    
                    # Clear session
                    await account.session.close_session()
                    await asyncio.sleep(1)
                    await account.session._ensure_aiohttp()
                    
                    # Clear cookies
                    account.session.cookie_jar = SafeCookieJar()
                    
                    # Rotate everything
                    account.fingerprint_rotator.generate_unique_fingerprint()
                    account.device_id_rotator.generate_device_id()
                    
                    # Restart chromium
                    if account.use_chromium:
                        await account.start_chromium()
                    
                    print("[ChallengeBypassStrategy] Full reset completed")
                    return True
                except Exception as e:
                    logger.warning("[ChallengeBypassStrategy] Full reset failed: %s", e)
                    return False
            
            elif strategy == "switch_to_chromium":
                print("[ChallengeBypassStrategy] Switching to Chromium...")
                try:
                    if not account.chromium_started:
                        await account.start_chromium()
                        await account._sync_jar_cookies_to_chromium()
                        account.use_chromium_for_signup = True
                        print("[ChallengeBypassStrategy] Switched to Chromium")
                        return True
                    else:
                        logger.warning("[ChallengeBypassStrategy] Already using Chromium")
                        return False
                except Exception as e:
                    logger.warning("[ChallengeBypassStrategy] Switch to Chromium failed: %s", e)
                    return False
            
            elif strategy == "use_different_email":
                print("[ChallengeBypassStrategy] Cannot change email mid-creation")
                return False
        
        except Exception as e:
            logger.error("[ChallengeBypassStrategy] Strategy failed: %s", e)
            return False

    async def apply_next_strategy(self, account: 'Account', challenge_type: str,
                                 current_index: int) -> bool:
        """Apply next strategy dalam sequence"""
        return await self.apply_bypass(account, challenge_type, current_index + 1)


# ============================================================================
# UPDATE CLASS Account dengan challenge handling
# ============================================================================

# TAMBAHKAN di Account.__init__():

        # ========== CHALLENGE DETECTION & BYPASS ==========
        self.challenge_detector = ChallengeDetector()
        self.challenge_bypass = ChallengeBypassStrategy()
        self.challenge_count = 0
        self.current_bypass_strategy_index = 0

# REPLACE METHOD _make_request_with_anomaly_tracking():

    async def _make_request_with_anomaly_tracking(self, method: str, url: str,
                                                   data: Optional[bytes] = None,
                                                   headers: Optional[Dict[str, str]] = None,
                                                   allow_challenge_bypass: bool = True) -> Dict[str, Any]:
        """Make request dengan anomaly tracking & challenge detection"""
        
        start_time = _now()
        
        # Apply smart delays
        await self._apply_smart_delays("api")
        
        # Smart fingerprint rotation
        fp_headers = await self._smart_fingerprint_rotation()
        if headers:
            headers = {**headers, **fp_headers}
        else:
            headers = fp_headers
        
        # Build fresh headers
        fresh_headers = await self._build_fresh_headers(headers)
        
        # ✅ CHOOSE REQUEST METHOD
        try:
            # Try Chromium POST jika available
            if method.upper() == "POST" and self.use_chromium_for_signup and self.chromium_started:
                try:
                    if self.verbose:
                        logger.debug("[_make_request_with_anomaly_tracking] Trying Chromium POST")
                    
                    resp = await self._chromium_post_request(url, headers=fresh_headers, data=data)
                    
                    if resp.get("status"):
                        await self._sync_chromium_cookies_to_jar()
                        response_time = _now() - start_time
                        self.anomaly_detector.record_request(url, method, resp.get("status", 0), response_time)
                        
                        # ✅ CHECK FOR CHALLENGE
                        is_challenge, challenge_type = self.challenge_detector.detect_challenge(resp)
                        if is_challenge and allow_challenge_bypass:
                            logger.error("[_make_request_with_anomaly_tracking] 🔴 CHALLENGE DETECTED: %s", 
                                       challenge_type)
                            self.challenge_count += 1
                            self.challenge_detector.record_challenge(challenge_type, url, 
                                                                    str(resp.get("body", b""))[:200])
                            self.increase_suspicion(0.25, f"Challenge detected: {challenge_type}")
                            
                            # Try bypass
                            bypass_ok = await self.challenge_bypass.apply_bypass(
                                self, challenge_type, self.current_bypass_strategy_index
                            )
                            
                            if bypass_ok:
                                self.current_bypass_strategy_index += 1
                                print("[_make_request_with_anomaly_tracking] Bypass applied, retrying...")
                                
                                # Retry request
                                await asyncio.sleep(3)
                                return await self._make_request_with_anomaly_tracking(
                                    method, url, data=data, headers=headers,
                                    allow_challenge_bypass=(self.current_bypass_strategy_index < 5)
                                )
                            else:
                                logger.error("[_make_request_with_anomaly_tracking] Bypass failed")
                                return resp
                        
                        if self.verbose:
                            logger.debug("[_make_request_with_anomaly_tracking] ✅ Chromium POST success")
                        
                        return resp
                except Exception as e:
                    logger.debug("[_make_request_with_anomaly_tracking] Chromium POST failed: %s", e)
            
            # Fallback to HTTP
            resp = await self._make_request(method, url, data=data, headers=fresh_headers, use_chromium=False)
        
        except Exception as e:
            logger.error("[_make_request_with_anomaly_tracking] Error: %s", e)
            resp = {"status": None, "body": b"", "headers": {}}
        
        # Track response
        response_time = _now() - start_time
        status = resp.get("status")
        
        self.anomaly_detector.record_request(url, method, status or 0, response_time)
        
        # ✅ CHECK FOR CHALLENGE (HTTP response juga)
        is_challenge, challenge_type = self.challenge_detector.detect_challenge(resp)
        if is_challenge and allow_challenge_bypass:
            logger.error("[_make_request_with_anomaly_tracking] 🔴 CHALLENGE DETECTED (HTTP): %s", 
                       challenge_type)
            self.challenge_count += 1
            self.challenge_detector.record_challenge(challenge_type, url, 
                                                    str(resp.get("body", b""))[:200])
            self.increase_suspicion(0.25, f"Challenge detected: {challenge_type}")
            
            # Try bypass
            bypass_ok = await self.challenge_bypass.apply_bypass(
                self, challenge_type, self.current_bypass_strategy_index
            )
            
            if bypass_ok:
                self.current_bypass_strategy_index += 1
                print("[_make_request_with_anomaly_tracking] Bypass applied, retrying...")
                
                # Retry request
                await asyncio.sleep(3)
                return await self._make_request_with_anomaly_tracking(
                    method, url, data=data, headers=headers,
                    allow_challenge_bypass=(self.current_bypass_strategy_index < 5)
                )
        
        # Check for other anomalies
        if self.anomaly_detector.detect_challenges(resp):
            self.increase_suspicion(0.2, "Challenge detected in response")
        
        if status == 429:
            self.increase_suspicion(0.15, "Rate limit hit")
        
        if status == 403 and "suspicious" in resp.get("body", b"").decode(errors="ignore").lower():
            self.increase_suspicion(0.25, "Suspicious activity detected")
        
        if status == 200:
            self.decrease_suspicion(0.05)
        
        return resp

# TAMBAHKAN method untuk monitor challenge:

    def get_challenge_report(self) -> str:
        """Get challenge report"""
        return f"""
╔════════════════════════════════════════════════════════════╗
║              CHALLENGE DETECTION REPORT                     ║
╚════════════════════════════════════════════════════════════╝

Total Challenges: {self.challenge_count}
Bypass Strategies Used: {self.current_bypass_strategy_index}
Suspicion Level: {self.get_suspicion_status()} ({self.suspicion_level:.2f})

Challenge History:
{self.challenge_detector.get_challenge_summary()}

Current Status:
- Browser: {'Chromium' if self.chromium_started else 'HTTP'}
- Proxy: {self.bound_proxy[:50] if self.bound_proxy else 'None'}
- Session Health: {self.session_validator.get_session_health():.2f}
- Anomaly Score: {self.anomaly_detector.get_anomaly_score():.2f}

Recommendations:
{'✅ Low risk - Continue' if self.suspicion_level < 0.4 else '⚠️ Medium risk - Monitor' if self.suspicion_level < 0.7 else '🔴 High risk - Consider restart'}
"""

    def print_challenge_report(self):
        """Print challenge report"""
        print(self.get_challenge_report())

class Account:
    def __init__(self, tmp: int = 1, gmail_base: str = None, use_proxy: bool = False, platform: str = "safari",
                 use_chromium: bool = True, suppress_no_code_log: bool = False,
                 verbose: bool = True, anti_checkpoint_level: int = 3):
        """Initialize Account dengan enhanced security features"""
        
        # ========== BASIC PROPERTIES ==========
        self.username: Optional[str] = None
        self.password: Optional[str] = None
        self.email_new: Optional[str] = None
        self.tmp = int(tmp)
        self.gmail_base = gmail_base
        self.status = 0
        self.verbose = verbose
        self.suppress_no_code_log = bool(suppress_no_code_log)
        self.platform = platform

        # ========== SESSION IDENTIFIERS ==========
        self.web_session_id = self._generate_web_session_id()
        self.use_chromium = bool(use_chromium)
        self.page = None
        self.browser_context = None
        self._chromium_resources = None
        self._keep_browser_alive: bool = False
        self.chromium_started: bool = False
        self._otp_session_data: Optional[Dict[str, Any]] = None

        # ========== PROXY MANAGEMENT ==========
        self.bound_proxy: Optional[str] = None
        self.proxy_url = None
        if use_proxy:
            self.proxy_url = "https://komaroapa:EawXD0htYxHOuI3CW3cg_country-AU_mode-speed_session-MFFH7XKXF_lifetime-2@premium-residential.evomi-proxy.com:1001"

        # ========== INITIALIZE UltraBoostedV13 SESSION ==========
        try:
            self.session: UltraBoostedV13 = UltraBoostedV13(
                timeout=60,
                max_retries=5,
                use_proxy=use_proxy,
                max_concurrency=12,
                verbose=verbose,
                rotate_ja3=True,
                non_standard_header_obfuscation=True,
                bypass_fragmentation=True,
                auto_rotate_proxy=True,
                http2_priority_hint=True,
                anti_detect=True,
                session_file="./sessions_account.json",
                use_session=True,
                smart_headers_mode='A'
            )

            self.session.proxy_manager = UnifiedProxyManager(verbose=verbose)

            try:
                self.session.header_builder._parent = self.session
            except Exception:
                pass
        except Exception as e:
            logger.error("[Account] Failed to initialize UltraBoostedV13: %s", e)
            raise

        # ========== ENHANCED SECURITY FEATURES ==========
        self.security_manager = AdvancedSecurityManager()
        self.anti_detection = AntiDetectionManager()
        self.creation_attempts = 0
        self.success_count = 0

        # ========== EXISTING FINGERPRINT & HEADERS ==========
        try:
            self.fp = ChromeFingerprintSuperRealistic(os_name="mac", stable=True)
            self.ig_meta = InstagramHeaderAutoSync(self.fp)
            meta = self.ig_meta.generate()
            
            self.asbd_id = meta.get("asbd_id", "166")
            self.app_id = meta.get("app_id", "936619743392459")
            self.ajax = meta.get("ajax", "1")
            self.ua = meta.get("ua")
            self.sec_ua = meta.get("sec_ua")
        except Exception as e:
            logger.warning("[Account] Fingerprint init failed: %s", e)
            self.fp = None
            self.ig_meta = None
            self.asbd_id = "166"
            self.app_id = "936619743392459"
            self.ajax = "1"
            self.ua = None
            self.sec_ua = None

        try:
            self.hb = HeaderBuilderV5(device="macbook", stable_session=True)
            self.base_headers = self.hb.build_with_ig_meta(
                referer="https://www.instagram.com/accounts/emailsignup/"
            )
        except Exception as e:
            logger.warning("[Account] HeaderBuilderV5 init failed: %s", e)
            self.hb = None
            self.base_headers = {}

        # ========== EXISTING TRAFFIC SHAPER & MANAGERS ==========
        try:
            self.traffic_shaper = TrafficShaper()
        except Exception:
            self.traffic_shaper = None

        try:
            self.fingerprint_manager = AdvancedFingerprintManager()
        except Exception:
            self.fingerprint_manager = None

        # ========== EXISTING ANTI-CHECKPOINT PROPERTIES ==========
        self.anti_checkpoint_level = anti_checkpoint_level
        self.checkpoint_attempts = 0
        self.max_checkpoint_attempts = 3
        self.checkpoint_recovery_enabled = True

        # ========== EXISTING PROFILE & LOGIN STATE ==========
        self.bio: Optional[str] = None
        self.profile_pic: Optional[str] = None
        self.full_name: Optional[str] = None
        self.is_logged_in: bool = False
        self.logged_in_at: Optional[float] = None
        self.session_lifetime = 3600

        # ========== EXISTING BEHAVIORAL TRACKING ==========
        self.request_count = 0
        self.request_timestamps: List[float] = []
        self.action_history: Dict[str, int] = {}
        self.last_action_time: float = _now()

        # ========== EXISTING FINGERPRINT & DEVICE ROTATION ==========
        self.device_id_rotated: bool = False
        self.ua_rotation_enabled: bool = True
        self.timezone_rotation_enabled: bool = True
        self.geolocation_proxy_enabled: bool = use_proxy

        # ========== EXISTING RATE LIMITING EVASION ==========
        self.request_delay_multiplier: float = 1.0
        self.random_delay_enabled: bool = True
        self.burst_delay_enabled: bool = True
        self.min_request_delay: float = 0.5
        self.max_request_delay: float = 3.5

        # ========== EXISTING CHROMIUM SPECIFIC ==========
        self.chromium_manager: Optional[ChromiumManager] = None
        self.use_chromium_for_signup: bool = use_chromium
        self.chromium_profile_dir: str = "./chromium_profiles/account"

        # ========== EXISTING ANTI-BOT COMPONENTS ==========
        self.behavior_analyzer = BehaviorAnalyzer()
        self.fingerprint_rotator = FingerprintRotator()
        self.proxy_health_monitor = ProxyHealthMonitor()
        self.anomaly_detector = AnomalyDetector()
        self.device_id_rotator = DeviceIDRotator()
        self.session_validator = SessionValidator()

        # ========== EXISTING SUSPICION TRACKING ==========
        self.suspicion_level: float = 0.0
        self.suspicion_history: List[Tuple[float, str]] = []
        self.auto_recovery_attempts = 0
        self.max_auto_recovery_attempts = 5

        # ========== EXISTING CHALLENGE DETECTION & BYPASS ==========
        self.challenge_detector = ChallengeDetector()
        self.challenge_bypass = ChallengeBypassStrategy()
        self.challenge_count = 0
        self.current_bypass_strategy_index = 0

        # ========== ADVANCED IP STEALTH SYSTEM 2025 ==========
        self.ip_stealth_system = IP_STEALTH_SYSTEM
        self.webrtc_webgl_spoofer = WEBRTC_WEBGL_SPOOFER
        self.current_ip_config: Optional[Dict[str, Any]] = None
        self.ip_rotation_count: int = 0
        self.last_ip_rotation: float = 0
        self.ip_rotation_interval: int = 300  # 5 minutes

        if verbose:
            print("[Account] ✅ Initialized COMPLETE with ENHANCED SECURITY")
            print("[Account] - UltraBoostedV13: ON")
            print("[Account] - Chromium: %s", "ON" if use_chromium else "OFF")
            print("[Account] - Enhanced Security: ON")
            print("[Account] - Anti-Checkpoint Level: %d", anti_checkpoint_level)
            print("[Account] - IP Stealth System 2025: ON")
            print("[Account] - WebRTC/WebGL Spoofing: ON")

    # ============================================================================
    # IP STEALTH & FINGERPRINT MANAGEMENT
    # ============================================================================

    def get_fresh_identity(self) -> Dict[str, Any]:
        """Get fresh IP and fingerprint identity for rate limit evasion"""
        # Rotate IP
        ip_config = self.ip_stealth_system.get_fresh_ip_config()
        self.current_ip_config = ip_config
        self.ip_rotation_count += 1
        self.last_ip_rotation = time.time()
        
        # Get device info
        device_fp = ip_config.get("device_fingerprint", {})
        brand = device_fp.get("brand", "Samsung").lower()
        connection_type = ip_config.get("connection_type", "mobile")
        
        # Get WebRTC/WebGL fingerprint
        webrtc_webgl_fp = self.webrtc_webgl_spoofer.get_complete_fingerprint("android", brand, connection_type)
        
        identity = {
            "ip_config": ip_config,
            "webrtc_webgl_fingerprint": webrtc_webgl_fp,
            "stealth_script": self.webrtc_webgl_spoofer.get_stealth_injection_script(webrtc_webgl_fp),
            "headers": ip_config.get("headers", {}),
            "user_agent": device_fp.get("user_agent", ""),
            "ja3": ip_config.get("fingerprints", {}).get("ja3", ""),
            "rotation_count": self.ip_rotation_count,
            "timestamp": int(time.time())
        }
        
        if self.verbose:
            print(f"🔄 [Account] Fresh identity generated:")
            print(f"   📍 IP: {ip_config.get('ip')} ({ip_config.get('isp')})")
            print(f"   📱 Device: {device_fp.get('market_name', 'Unknown')}")
            print(f"   🔗 Connection: {connection_type}")
            print(f"   🔢 Rotation: #{self.ip_rotation_count}")
        
        return identity

    def should_rotate_identity(self) -> bool:
        """Check if identity should be rotated for rate limit evasion"""
        if self.current_ip_config is None:
            return True
        return time.time() - self.last_ip_rotation > self.ip_rotation_interval

    async def apply_identity_to_context(self, context, identity: Dict[str, Any] = None) -> bool:
        """Apply identity (IP/fingerprint) to browser context"""
        try:
            if identity is None:
                identity = self.get_fresh_identity()
            
            # Add stealth script
            stealth_script = identity.get("stealth_script", "")
            if stealth_script:
                await context.add_init_script(stealth_script)
            
            # Set headers
            headers = identity.get("headers", {})
            if headers:
                await context.set_extra_http_headers(headers)
            
            return True
        except Exception as e:
            logger.error(f"[Account] Failed to apply identity: {e}")
            return False

    # ============================================================================
    # UTILITY METHODS
    # ============================================================================

    def _rand_block(self, length: int = 6) -> str:
        """Generate random block"""
        return ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(length))

    def _generate_web_session_id(self) -> str:
        """Generate web session ID"""
        return f"{self._rand_block()}:{self._rand_block()}:{self._rand_block()}"

    def generate_valid_birthdate(self, min_age: int = 15, max_age: int = 25) -> Tuple[str, str, str]:
        """Generate valid birthdate"""
        today = time.localtime()
        year_now = today.tm_year
        min_year = year_now - max_age
        max_year = year_now - min_age
        year = random.randint(min_year, max_year)
        month = random.randint(1, 12)
        
        if month in (1, 3, 5, 7, 8, 10, 12):
            max_day = 31
        elif month in (4, 6, 9, 11):
            max_day = 30
        else:
            max_day = 29 if (year % 4 == 0 and year % 100 != 0) or (year % 400 == 0) else 28
        
        day = random.randint(1, max_day)
        return str(month), str(day), str(year)

    def decode_instagram_html(self, response) -> str:
        """Decode Instagram HTML response"""
        raw = b""
        headers = {}
        
        if isinstance(response, dict):
            raw = response.get("body") or b""
            headers = response.get("headers") or {}
            enc = headers.get("Content-Encoding", "") or headers.get("content-encoding", "")
        else:
            raw = getattr(response, "content", b"")
            enc = getattr(response, "headers", {}).get("Content-Encoding", "").lower()
        
        try:
            if isinstance(enc, str) and "gzip" in enc:
                raw = gzip.decompress(raw)
            elif isinstance(enc, str) and ("br" in enc or "brotli" in enc):
                raw = brotli.decompress(raw)
        except Exception:
            pass
        
        try:
            text = raw.decode("utf-8", errors="replace")
        except Exception:
            text = getattr(response, "text", "") or ""
        
        text = html.unescape(text)
        return text

    # ============================================================================
    # SUSPICION MANAGEMENT
    # ============================================================================

    def increase_suspicion(self, amount: float, reason: str):
        self.suspicion_level = min(1.0, self.suspicion_level + amount)
        self.suspicion_history.append((self.suspicion_level, reason))
        
        if self.verbose:
            logger.warning("[Account] ⚠️ Suspicion increased to %.2f: %s", 
                         self.suspicion_level, reason)

    def decrease_suspicion(self, amount: float):
        """Decrease suspicion level"""
        self.suspicion_level = max(0.0, self.suspicion_level - amount)

    def get_suspicion_status(self) -> str:
        """Get suspicion status"""
        if self.suspicion_level < 0.3:
            return "🟢 Safe"
        elif self.suspicion_level < 0.6:
            return "🟡 Caution"
        elif self.suspicion_level < 0.85:
            return "🔴 High Risk"
        else:
            return "🔴🔴 Critical"

    # ============================================================================
    # CORE REQUEST METHODS (dengan semua integration)
    # ============================================================================

    async def _make_request_with_challenge_detection(self, method: str, url: str,
                                                     data: Optional[bytes] = None,
                                                     headers: Optional[Dict[str, str]] = None,
                                                     allow_challenge_bypass: bool = True,
                                                     retry_count: int = 0) -> Dict[str, Any]:
        """
        ✅ FIXED: Enhanced request method dengan better error handling
        """
        if retry_count > 3:
            logger.error("[_make_request_with_challenge_detection] Max retries exceeded")
            return {"status": None, "body": b"", "headers": {}, "_browser": "max_retries_exceeded"}
        
        try:
            # Apply smart delays
            await self._apply_smart_delays("api")
            
            # Smart fingerprint rotation
            fp_headers = await self._smart_fingerprint_rotation()
            if headers:
                headers = {**headers, **fp_headers}
            else:
                headers = fp_headers
            
            # Build fresh headers
            fresh_headers = await self._build_fresh_headers(headers)
            
            # ✅ FIXED: Better Chromium fallback logic
            if self.use_chromium_for_signup and self.chromium_started:
                try:
                    if self.verbose:
                        logger.debug("[_make_request_with_challenge_detection] Using Chromium")
                    
                    resp = await self._chromium_request(url, method=method, headers=fresh_headers, data=data)
                    
                    if resp and resp.get("status"):
                        await self._sync_chromium_cookies_to_jar()
                        self.anomaly_detector.record_request(url, method, resp.get("status", 0), _now())
                        
                        # Challenge detection
                        is_challenge, challenge_type = self.challenge_detector.detect_challenge(resp)
                        if is_challenge and allow_challenge_bypass:
                            return await self._handle_challenge_response(method, url, data, headers, 
                                                                       challenge_type, retry_count)
                        
                        return resp
                
                except Exception as e:
                    logger.error("[_make_request_with_challenge_detection] Chromium error: %s", e)
            
            # ✅ FIXED: Better HTTP fallback
            return await self._http_fallback_request(method, url, fresh_headers, data)
            
        except Exception as e:
            logger.error("[_make_request_with_challenge_detection] Unexpected error: %s", e)
            return {"status": None, "body": b"", "headers": {}, "_browser": "error"}

    async def _http_fallback_request(self, method: str, url: str, headers: Dict[str, str], 
                                   data: Optional[bytes]) -> Dict[str, Any]:
        """✅ FIXED: HTTP fallback request dengan better error handling"""
        try:
            if method.upper() == "GET":
                resp = await self.session.get(url, headers=headers, use_session=True)
            else:
                resp = await self.session.post(url, data=data, headers=headers, use_session=True)
            
            await self._sync_cookies_from_response(resp)
            resp["_browser"] = "http_fallback"
            return resp
        
        except Exception as e:
            logger.error("[_http_fallback_request] HTTP fallback failed: %s", e)
            return {"status": None, "body": b"", "headers": {}, "_browser": "http_fallback_error"}

    async def _handle_challenge_response(self, method: str, url: str, data: Optional[bytes],
                                       headers: Optional[Dict[str, str]], challenge_type: str,
                                       retry_count: int) -> Dict[str, Any]:
        """✅ FIXED: Centralized challenge handling"""
        logger.error("[_handle_challenge_response] 🔴 CHALLENGE: %s", challenge_type)
        
        self.challenge_count += 1
        self.increase_suspicion(0.25, f"Challenge: {challenge_type}")
        
        if self.current_bypass_strategy_index < len(self.challenge_bypass.strategies):
            bypass_ok = await self.challenge_bypass.apply_bypass(
                self, challenge_type, self.current_bypass_strategy_index
            )
            
            if bypass_ok:
                self.current_bypass_strategy_index += 1
                await asyncio.sleep(3)
                
                # Retry with incremented retry_count
                return await self._make_request_with_challenge_detection(
                    method, url, data=data, headers=headers,
                    allow_challenge_bypass=True,
                    retry_count=retry_count + 1
                )
        
        return {"status": None, "body": b"", "headers": {}, "_browser": "challenge_failed"}

    # ============================================================================
    # REMAINING METHODS (COPY DARI SEBELUMNYA)
    # ============================================================================

    async def _apply_smart_delays(self, request_type: str = "api"):
        """Apply smart delays"""
        anomaly_score = self.anomaly_detector.get_anomaly_score()
        
        request_delays = {
            "navigation": (0.5, 1.5),
            "api": (1.0, 2.5),
            "critical": (3.0, 6.0),
            "signup": (2.0, 4.0),
            "profile": (1.5, 3.0),
            "login": (1.0, 2.0),
            "logout": (0.5, 1.0)
        }
        
        min_delay, max_delay = request_delays.get(request_type, (1.0, 2.5))
        
        suspicion_multiplier = 1.0 + (self.suspicion_level * 2.0)
        anomaly_multiplier = 1.0 + anomaly_score
        
        min_delay *= suspicion_multiplier * anomaly_multiplier
        max_delay *= suspicion_multiplier * anomaly_multiplier
        
        evasion_delay = await self.anomaly_detector.apply_evasion_strategy(anomaly_score)
        
        base_delay = random.uniform(min_delay, max_delay)
        jitter = base_delay * random.uniform(0.05, 0.3)
        total_delay = base_delay + jitter + evasion_delay
        
        await asyncio.sleep(total_delay)
        self.behavior_analyzer.record_action(request_type, _now())

    async def _smart_fingerprint_rotation(self) -> Dict[str, str]:
        """Smart fingerprint rotation"""
        rotation_strategy = self.fingerprint_rotator.get_rotation_strategy()
        
        if rotation_strategy == "stable":
            return {}
        elif rotation_strategy == "gradual":
            fresh_fp = ChromeFingerprintSuperRealistic(os_name="mac", stable=False)
            fresh_meta = InstagramHeaderAutoSync(fresh_fp)
            meta = fresh_meta.generate()
            return {"User-Agent": meta.get("ua")}
        elif rotation_strategy == "moderate":
            os_choice = random.choice(["windows", "mac", "linux"])
            fresh_fp = ChromeFingerprintSuperRealistic(os_name=os_choice, stable=False)
            fresh_meta = InstagramHeaderAutoSync(fresh_fp)
            meta = fresh_meta.generate()
            return {
                "User-Agent": meta.get("ua"),
                "X-Ig-App-Id": meta.get("app_id"),
                "X-Asbd-Id": meta.get("asbd_id"),
            }
        else:  # aggressive
            unique_fp = self.fingerprint_rotator.generate_unique_fingerprint()
            return {
                "User-Agent": unique_fp.get("ua"),
                "X-Ig-App-Id": str(random.choice(["936619743392459", "878587922602823", "192313041724948"])),
            }

    async def _smart_device_id_rotation(self) -> str:
        """Smart device ID rotation"""
        if self.suspicion_level > 0.7:
            return self.device_id_rotator.rotate_device_id(force=True)
        elif self.suspicion_level > 0.4:
            return self.device_id_rotator.rotate_device_id(force=False)
        else:
            return self.device_id_rotator.get_device_id()

    async def _validate_and_update_proxy(self):
        """Enhanced proxy validation dengan UnifiedProxyManager"""
        if not self.bound_proxy or not self.use_proxy:
            return
        
        try:
            proxy_manager = self.session.proxy_manager
            
            # Check proxy health
            is_healthy = await proxy_manager._health_check_proxy(self.bound_proxy)
            
            if not is_healthy:
                print("[_validate_and_update_proxy] ⚠️ Proxy unhealthy, rotating...")
                
                await proxy_manager.mark_bad(self.bound_proxy)
                
                # Dapatkan proxy optimal baru
                new_proxy = await proxy_manager.get_optimal_proxy(country="US", min_score=60)
                
                if new_proxy and new_proxy != self.bound_proxy:
                    old_proxy = self.bound_proxy
                    self.bound_proxy = new_proxy
                    
                    print("[_validate_and_update_proxy] ✅ Proxy rotated: %s -> %s", 
                          old_proxy[:50] if old_proxy else "None", 
                          new_proxy[:50])
                    
                    # Update Chromium jika sedang digunakan
                    if self.chromium_started:
                        try:
                            await self.stop_chromium()
                            await asyncio.sleep(2)
                            await self.start_chromium()
                            print("[_validate_and_update_proxy] ✅ Chromium restarted with new proxy")
                        except Exception as e:
                            logger.error("[_validate_and_update_proxy] Chromium restart failed: %s", e)
            else:
                # Proxy sehat, tingkatkan score
                await proxy_manager.score_success(self.bound_proxy, bonus=2.0)
                
        except Exception as e:
            logger.error("[_validate_and_update_proxy] Error: %s", e)

    async def rotate_proxy_automatically(self):
        """Automatic proxy rotation berdasarkan kondisi"""
        if not self.use_proxy:
            return
        
        try:
            proxy_manager = self.session.proxy_manager
            
            # Rotate berdasarkan suspicion level
            if self.suspicion_level > 0.7:
                new_proxy = await proxy_manager.get_optimal_proxy(country="US", min_score=80)
            elif self.suspicion_level > 0.4:
                if random.random() < 0.3:
                    new_proxy = await proxy_manager.get_optimal_proxy(country="US", min_score=70)
                else:
                    new_proxy = None
            else:
                if random.random() < 0.1:
                    new_proxy = await proxy_manager.get_optimal_proxy(country="US", min_score=60)
                else:
                    new_proxy = None
            
            if new_proxy and new_proxy != self.bound_proxy:
                old_proxy = self.bound_proxy
                self.bound_proxy = new_proxy
                
                print("[rotate_proxy_automatically] 🔄 Auto-rotated proxy: %s -> %s", 
                      old_proxy[:50] if old_proxy else "None", 
                      new_proxy[:50])
                
                if old_proxy:
                    await proxy_manager.cleanup_proxy(old_proxy)
        
        except Exception as e:
            logger.error("[rotate_proxy_automatically] Error: %s", e)

    async def _build_fresh_headers(self, extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        headers = dict(self.base_headers or {})

        if extra:
            headers.update(extra)

        cookie_jar = self.session.cookie_jar

        # Ambil nilai cookie tertentu
        csrf = await cookie_jar.get_cookie_value("https://www.instagram.com", "csrftoken")
        mid = await cookie_jar.get_cookie_value("https://www.instagram.com", "mid")
        ig_did = await cookie_jar.get_cookie_value("https://www.instagram.com", "ig_did")

        cookie_parts = []

        # Tambahkan cookie penting dulu
        if mid:
            cookie_parts.append(f"mid={mid}")
        if ig_did:
            cookie_parts.append(f"ig_did={ig_did}")
        if csrf:
            cookie_parts.append(f"csrftoken={csrf}")

        # Ambil semua cookie yang tersimpan
        # _cookies: dict[domain][path][cookie_name]
        try:
            for domain, paths in cookie_jar._cookies.items():
                for path, cookie_dict in paths.items():
                    for name, cookie in cookie_dict.items():
                        if name in ("mid", "csrftoken", "ig_did"):
                            continue
                        cookie_parts.append(f"{name}={cookie.value}")
        except Exception:
            pass

        # Build Cookie header
        if cookie_parts:
            headers["Cookie"] = "; ".join(cookie_parts)

        # CSRF header
        if csrf:
            headers["X-Csrftoken"] = csrf

        # Header default IG
        headers.setdefault("X-Ig-App-Id", self.app_id or "936619743392459")
        headers.setdefault("X-Instagram-Ajax", self.ajax or "1")
        headers.setdefault("X-Asbd-Id", self.asbd_id or "166")
        headers.setdefault("X-Web-Session-Id", self.web_session_id)

        return headers

    async def _sync_cookies_from_response(self, resp: Optional[Dict[str, Any]]):
        """Sync cookies dari response"""
        if not resp:
            return
        try:
            hdrs = resp.get("headers") or {}
            sc = hdrs.get("set-cookie") or hdrs.get("Set-Cookie")
            if not sc:
                return
            
            if isinstance(sc, (list, tuple)):
                for s in sc:
                    try:
                        await self.session.cookie_jar.update_from_set_cookie_header("www.instagram.com", s)
                    except Exception:
                        pass
            else:
                try:
                    await self.session.cookie_jar.update_from_set_cookie_header("www.instagram.com", sc)
                except Exception:
                    pass
        except Exception:
            pass

    async def _sync_chromium_cookies_to_jar(self) -> int:
        """Sync Chromium cookies ke jar - return count"""
        
        if not self.browser_context:
            return 0
        
        try:
            cookies = await self.browser_context.cookies()
            count = 0
            
            for c in cookies:
                domain = c.get("domain") or "www.instagram.com"
                try:
                    await self.session.cookie_jar.set_cookie(
                        domain,
                        c.get("name"),
                        c.get("value"),
                        path=c.get("path", "/"),
                        secure=c.get("secure", False),
                        httponly=c.get("httpOnly", False)
                    )
                    count += 1
                except Exception:
                    pass
            
            if count > 0 and self.verbose:
                logger.debug("[_sync_chromium_cookies_to_jar] Synced %d cookies", count)
            
            return count
        
        except Exception as e:
            logger.debug("[_sync_chromium_cookies_to_jar] Error: %s", e)
            return 0

    async def _sync_jar_cookies_to_chromium(self) -> int:
        """Sync jar cookies ke Chromium - return count"""
        
        if not self.browser_context:
            return 0
        
        try:
            cookies_dict = await self.session.cookie_jar.to_dict()
            cookies_list = []
            count = 0
            
            for domain, cookie_dict in cookies_dict.items():
                for name, cookie_data in cookie_dict.items():
                    cookies_list.append({
                        "name": name,
                        "value": cookie_data.get("value", ""),
                        "domain": cookie_data.get("domain", domain),
                        "path": cookie_data.get("path", "/"),
                        "secure": cookie_data.get("secure", False),
                        "httpOnly": cookie_data.get("httponly", False),
                    })
                    count += 1
            
            if cookies_list:
                await self.browser_context.add_cookies(cookies_list)
            
            if count > 0 and self.verbose:
                logger.debug("[_sync_jar_cookies_to_chromium] Synced %d cookies", count)
            
            return count
        
        except Exception as e:
            logger.debug("[_sync_jar_cookies_to_chromium] Error: %s", e)
            return 0

    async def _make_request(self, method: str, url: str, data: Optional[bytes] = None,
                       headers: Optional[Dict[str, str]] = None, use_chromium: Optional[bool] = None) -> Dict[str, Any]:
        """Make HTTP request dengan better proxy handling"""
        try:
            # Check if session is properly initialized
            if not hasattr(self, 'session') or self.session is None:
                logger.error("[_make_request] Session not initialized")
                return {"status": None, "body": b"", "headers": {}}
            
            # Jika proxy menyebabkan masalah, coba tanpa proxy untuk request internal
            if "username" in url or "suggest" in url:
                logger.info("[_make_request] Using direct connection for username suggestions")
                use_chromium = False
            
            # Make the request
            if method.upper() == "GET":
                resp = await self.session.get(url, headers=headers, use_session=True)
            else:
                resp = await self.session.post(url, data=data, headers=headers, use_session=True)
            
            await self._sync_cookies_from_response(resp)
            resp["_browser"] = "http"
            return resp
            
        except Exception as e:
            logger.error("[_make_request] Error: %s", e)
            # Fallback ke direct request untuk internal calls
            try:
                import aiohttp
                async with aiohttp.ClientSession() as session:
                    if method.upper() == "GET":
                        async with session.get(url, headers=headers) as response:
                            body = await response.read()
                            return {
                                "status": response.status,
                                "body": body,
                                "headers": dict(response.headers),
                                "_browser": "direct_fallback"
                            }
                    else:
                        async with session.post(url, data=data, headers=headers) as response:
                            body = await response.read()
                            return {
                                "status": response.status,
                                "body": body,
                                "headers": dict(response.headers),
                                "_browser": "direct_fallback"
                            }
            except Exception as fallback_error:
                logger.error("[_make_request] Fallback also failed: %s", fallback_error)
                return {"status": None, "body": b"", "headers": {}}

    async def _chromium_post_request(self, url: str, headers: Optional[Dict[str, str]] = None,
                                     data: Optional[bytes] = None) -> Dict[str, Any]:
        """POST via Chromium"""
        if not self.browser_context or not self.chromium_started:
            return {"status": None, "body": b"", "headers": {}}
        
        try:
            response = await self.browser_context.request.post(url, headers=headers or {}, data=data)
            return {
                "status": response.status,
                "body": await response.body(),
                "headers": dict(response.headers) if response.headers else {},
                "_proxy_used": self.bound_proxy,
                "_browser": "chromium"
            }
        except Exception as e:
            logger.error("[_chromium_post_request] Error: %s", e)
            return {"status": None, "body": b"", "headers": {}}

    async def _cleanup_chromium_profiles(self):
        """Cleanup chromium profile directories"""
        try:
            print("🧹 Cleaning up chromium profiles...")
            
            import glob
            import shutil
            
            patterns = [
                "chromium_profile*",
                "chromium_temp_*", 
                "account_temp_*",
                "pw-*",
                "tmp*",
                "temp*"
            ]
            
            cleaned_count = 0
            current_dir = os.getcwd()
            
            for pattern in patterns:
                try:
                    search_pattern = os.path.join(current_dir, pattern)
                    matches = glob.glob(search_pattern)
                    
                    for match in matches:
                        if os.path.exists(match):
                            if os.path.isdir(match):
                                shutil.rmtree(match, ignore_errors=True)
                                print(f"   ✅ Deleted folder: {os.path.basename(match)}")
                            else:
                                os.remove(match)
                                print(f"   ✅ Deleted file: {os.path.basename(match)}")
                            cleaned_count += 1
                except Exception as e:
                    print(f"   ⚠️ Cleanup failed for {pattern}: {e}")
            
            print(f"🧹 Cleanup completed: {cleaned_count} items removed")
            
        except Exception as e:
            print(f"⚠️ Chromium profiles cleanup error: {e}")

    async def _cleanup_directory(self, dir_path: str):
        """Bersihkan directory tertentu"""
        try:
            if os.path.exists(dir_path):
                shutil.rmtree(dir_path, ignore_errors=True)
                print(f"✅ Cleaned directory: {dir_path}")
        except Exception as e:
            print(f"⚠️ Directory cleanup error: {e}")

    async def init_session(self, profile_dir: Optional[str] = None):
        """Initialize session - sekarang start_chromium() sudah ada"""
        
        print("[init_session] 🔧 Initializing session via Account.start_chromium()")
        
        # ========== CLEANUP PREVIOUS SESSION ==========
        if self.chromium_started:
            print("[init_session] 🗑️ Cleaning previous session...")
            await self.stop_chromium()
            await asyncio.sleep(1)

        # ========== HTTP SESSION ==========
        try:
            await self.session._ensure_aiohttp()
            self.session.use_session_global = True
            print("[init_session] ✅ HTTP session ready")
        except Exception as e:
            logger.warning("[init_session] HTTP init failed: %s", e)

        # ========== PROXY SETUP ==========
        if self.proxy_url:
            print("[init_session] 🔗 Setting up proxy...")
            try:
                await self.session.add_proxy(self.proxy_url)
                self.bound_proxy = self.proxy_url
                print("[init_session] ✅ Proxy configured")
            except Exception as e:
                logger.warning("[init_session] Proxy setup error: %s", e)

        # ========== CHROMIUM INITIALIZATION ==========
        print("[init_session] 🌐 Starting Chromium...")
        
        if self.use_chromium:
            try:
                # ✅ SEKARANG start_chromium() SUDAH ADA
                chromium_ok = await self.start_chromium(profile_dir)
                
                if chromium_ok:
                    print("[init_session] ✅ Chromium started successfully")
                    self.use_chromium_for_signup = True
                else:
                    logger.error("[init_session] ❌ start_chromium() failed")
                    self.use_chromium_for_signup = False
            
            except Exception as e:
                logger.error("[init_session] ❌ Chromium initialization error: %s", e)
                self.use_chromium_for_signup = False
        else:
            logger.warning("[init_session] ⚠️ Chromium disabled")

        print("[init_session] ✅ Session initialization complete")

    async def _ensure_fresh_account_state(self):
        """Ensure fresh state untuk one account one session"""
        try:
            if not self.browser_context:
                return
                
            print("   🧹 Ensuring fresh account state...")
            
            # Clear cookies untuk fresh start
            await self.browser_context.clear_cookies()
            print("   ✅ Cookies cleared")
            
            # Clear storage via temporary page
            page = await self.browser_context.new_page()
            await page.goto("about:blank", wait_until="domcontentloaded")
            
            await page.evaluate("""() => {
                try {
                    localStorage.clear();
                    sessionStorage.clear();
                    console.log('✅ Storage cleared for fresh account');
                } catch(e) {
                    console.log('Storage clear error:', e);
                }
            }""")
            
            await page.close()
            print("   ✅ Storage cleared")
            
        except Exception as e:
            print(f"   ⚠️ Fresh state setup skipped: {e}")

    async def _apply_browser_settings_manually(self):
        """Apply settings manually setelah browser started"""
        try:
            if not self.browser_context:
                return
                
            print("   🛠️ Applying browser settings manually...")
            
            # 1. Apply user agent
            if self.ua or (self.fp and self.fp.user_agent()):
                user_agent = self.ua or self.fp.user_agent()
                await self.browser_context.set_extra_http_headers({
                    'User-Agent': user_agent
                })
                print(f"   ✅ User-Agent set: {user_agent[:50]}...")
            
            # 2. Apply viewport via pages
            if self.hb and self.hb.device_profile.get("viewport"):
                vp = self.hb.device_profile.get("viewport")
                # Viewport akan di-set per page, bukan per context
            
            # 3. Clear cookies untuk fresh session
            await self.browser_context.clear_cookies()
            print("   ✅ Cookies cleared")
            
            # 4. Add stealth scripts
            stealth_script = """
            Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
            Object.defineProperty(navigator, 'plugins', {get: () => [1, 2, 3, 4, 5]});
            Object.defineProperty(navigator, 'languages', {get: () => ['en-US', 'en']});
            window.chrome = {runtime: {}};
            """
            await self.browser_context.add_init_script(stealth_script)
            print("   ✅ Stealth scripts added")
            
            print("   ✅ Browser settings applied manually")
            
        except Exception as e:
            print(f"   ⚠️ Manual settings skipped: {e}")

    async def _init_chromium_manager(self):
        """Initialize ChromiumManager dengan proxy support"""
        try:
            if not self.chromium_manager:
                self.chromium_manager = ChromiumManager(
                    verbose=self.verbose,
                    headless=True,
                    use_proxy=bool(self.bound_proxy),
                    proxy_url=self.bound_proxy
                )
                print("[_init_chromium_manager] ✅ ChromiumManager created")
            return True
        except Exception as e:
            logger.error("[_init_chromium_manager] Error: %s", e)
            return False

    async def _chromium_request(self, url: str, method: str = "GET",
                               headers: Optional[Dict[str, str]] = None,
                               data: Optional[bytes] = None,
                               wait_until: str = "domcontentloaded") -> Dict[str, Any]:
        """
        ✅ FIXED: Chromium request dengan comprehensive error handling
        """
        if not self.browser_context or not self.chromium_started:
            logger.error("[_chromium_request] Chromium not available")
            return {"status": None, "body": b"", "headers": {}, "_browser": "chromium_not_started"}
        
        page = None
        
        try:
            # ✅ CREATE NEW PAGE dengan timeout
            page = await self.browser_context.new_page()
            
            # ✅ SET DEFAULT TIMEOUT
            await page.set_default_timeout(30000)
            
            # ✅ INJECT HEADERS
            if headers:
                await self._inject_headers_to_chromium(page, headers)
            
            # ✅ ADD STEALTH
            await page.add_init_script(self._get_stealth_script())
            
            # ✅ SET VIEWPORT
            if self.hb:
                viewport = self.hb.device_profile.get("viewport")
                if viewport:
                    await page.set_viewport_size({"width": viewport[0], "height": viewport[1]})
            
            if self.verbose:
                logger.debug("[_chromium_request] %s %s", method.upper(), url)
            
            # ========== GET REQUEST ==========
            if method.upper() == "GET":
                try:
                    response = await page.goto(url, wait_until=wait_until, timeout=45000)
                    
                    if response:
                        status = response.status
                        body = await response.body()
                        
                        # ✅ GET HEADERS
                        headers_dict = {}
                        try:
                            headers_dict = await response.all_headers()
                        except Exception:
                            pass
                        
                        return {
                            "status": status,
                            "body": body,
                            "headers": headers_dict,
                            "_proxy_used": self.bound_proxy,
                            "_browser": "chromium"
                        }
                    else:
                        logger.warning("[_chromium_request] No response from goto")
                        return {"status": None, "body": b"", "headers": {}, "_browser": "chromium_no_response"}
                
                except Exception as e:
                    logger.error("[_chromium_request] GET error: %s", e)
                    return {"status": None, "body": b"", "headers": {}, "_browser": "chromium_get_error"}
            
            # ========== POST REQUEST ==========
            else:
                try:
                    # ✅ USE PAGE EVALUATE UNTUK POST JIKA REQUEST API GAGAL
                    if data:
                        # Convert bytes to dict jika JSON
                        try:
                            data_dict = json.loads(data.decode()) if data else {}
                        except:
                            data_dict = {"data": data.decode() if data else ""}
                        
                        result = await page.evaluate("""async (url, headers, data) => {
                            const response = await fetch(url, {
                                method: 'POST',
                                headers: headers,
                                body: JSON.stringify(data)
                            });
                            return {
                                status: response.status,
                                body: await response.text(),
                                headers: Object.fromEntries(response.headers.entries())
                            };
                        }""", url, headers or {}, data_dict)
                        
                        return {
                            "status": result.get("status"),
                            "body": result.get("body", "").encode(),
                            "headers": result.get("headers", {}),
                            "_proxy_used": self.bound_proxy,
                            "_browser": "chromium_js"
                        }
                    else:
                        # Fallback ke context request
                        request_context = page.context
                        response = await request_context.request.post(
                            url,
                            headers=headers or {},
                            data=data,
                        )
                        
                        return {
                            "status": response.status,
                            "body": await response.body(),
                            "headers": dict(response.headers) if response.headers else {},
                            "_proxy_used": self.bound_proxy,
                            "_browser": "chromium"
                        }
                
                except Exception as e:
                    logger.error("[_chromium_request] POST error: %s", e)
                    return {"status": None, "body": b"", "headers": {}, "_browser": "chromium_post_error"}
        
        except Exception as e:
            logger.error("[_chromium_request] Critical error: %s", e)
            return {"status": None, "body": b"", "headers": {}, "_browser": "chromium_critical_error"}
        
        finally:
            if page:
                try:
                    await page.close()
                except Exception:
                    pass

    async def start_chromium(self, profile_dir: Optional[str] = None) -> bool:
        """Start Chromium browser menggunakan ChromiumManager"""
        
        if self.chromium_started:
            logger.warning("[start_chromium] Chromium already started")
            return True
        
        try:
            # Initialize ChromiumManager
            if not await self._init_chromium_manager():
                return False
            
            # Use temporary profile untuk one account one session
            temp_profile_dir = tempfile.mkdtemp(prefix="account_temp_")
            profile_dir = temp_profile_dir  # Override dengan temporary directory
            print(f"[start_chromium] 📁 Using temporary profile: {temp_profile_dir}")
            
            # Prepare parameters
            user_agent = self.ua or (self.fp.user_agent() if self.fp else None)
            
            viewport = None
            if self.hb and self.hb.device_profile.get("viewport"):
                vp = self.hb.device_profile.get("viewport")
                viewport = {"width": vp[0], "height": vp[1]}
            
            if self.verbose:
                print("[start_chromium] Starting Chromium with:")
                print(f"  - User Agent: {user_agent[:50] if user_agent else 'Default'}")
                print(f"  - Viewport: {viewport}")
                print(f"  - Proxy: {self.bound_proxy[:50] if self.bound_proxy else 'None'}")
            
            # Create persistent context menggunakan ChromiumManager
            self.browser_context = await self.chromium_manager.new_browser_context(
                user_agent=None,
                viewport=None,
                proxy=self.bound_proxy,
                locale="en-US",
                timezone="America/New_York"
            )
            
            if not self.browser_context:
                logger.error("[start_chromium] Failed to create browser context")
                await self._cleanup_directory(temp_profile_dir)
                return False
            
            # Add additional stealth scripts
            await self.browser_context.add_init_script("""
            Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
            Object.defineProperty(navigator, 'plugins', {get: () => [1, 2, 3, 4, 5]});
            Object.defineProperty(navigator, 'languages', {get: () => ['en-US', 'en']});
            window.chrome = {runtime: {}};
            """)
            
            self.chromium_started = True
            
            print("[start_chromium] ✅ Chromium started successfully")
            return True
            
        except Exception as e:
            logger.error("[start_chromium] Error: %s", e)
            self.chromium_started = False
            return False

    async def stop_chromium(self) -> bool:
        """Stop Chromium browser"""
        try:
            if hasattr(self, 'browser_context') and self.browser_context:
                try:
                    await self.browser_context.close()
                except Exception:
                    pass
                self.browser_context = None
            
            if hasattr(self, 'chromium_manager') and self.chromium_manager:
                try:
                    await self.chromium_manager.close_all()
                except Exception:
                    pass
            
            self.chromium_started = False
            
            # Cleanup temporary files
            await self._cleanup_chromium_profiles()
            
            print("✅ Chromium stopped completely")
            return True
            
        except Exception as e:
            logger.warning("⚠️ Chromium stop warning: %s", e)
            self.chromium_started = False
            return False

    def _get_stealth_script(self) -> str:
        """Stealth script"""
        return """
        Object.defineProperty(navigator, 'webdriver', {get: () => false});
        Object.defineProperty(navigator, 'plugins', {get: () => [{name: 'Chrome PDF Plugin'}]});
        Object.defineProperty(navigator, 'languages', {get: () => ['en-US', 'en']});
        Object.defineProperty(navigator, 'hardwareConcurrency', {get: () => 4});
        Object.defineProperty(navigator, 'deviceMemory', {get: () => 8});
        """

    async def save_session(self, profile: str = "default"):
        """Save session"""
        try:
            await self.session._save_sessions_to_file_async(profile=profile)
        except Exception:
            pass

    def get_action_stats(self) -> Dict[str, Any]:
        """Get stats"""
        return {
            "username": self.username,
            "email": self.email_new,
            "status": self.status,
            "suspicion_level": self.suspicion_level,
            "suspicion_status": self.get_suspicion_status(),
            "request_count": self.request_count,
            "checkpoint_attempts": self.checkpoint_attempts,
            "challenge_count": self.challenge_count,
            "auto_recovery_attempts": self.auto_recovery_attempts,
        }

    def print_action_stats(self):
        """Print stats"""
        stats = self.get_action_stats()
        
        print(f"\n{bg_hijau}{hitam}═══════════════════════════════════════════════════{reset}")
        print(f"{bg_hijau}{hitam}  ACCOUNT CREATED - {stats['username']}{reset}")
        print(f"{bg_hijau}{hitam}═══════════════════════════════════════════════════{reset}\n")
        
        print(f"{hijau}[✓] Status{reset}: {cyan}✅ Created{reset}")
        print(f"{hijau}[✓] Email{reset}: {cyan}{stats['email']}{reset}")
        print(f"{hijau}[✓] Suspicion Level{reset}: {stats['suspicion_status']} ({stats['suspicion_level']:.2f})")
        print(f"{hijau}[✓] Total Requests{reset}: {cyan}{stats['request_count']}{reset}")
        print(f"{hijau}[✓] Challenges Detected{reset}: {cyan}{stats['challenge_count']}{reset}")
        print(f"{hijau}[✓] Checkpoint Attempts{reset}: {cyan}{stats['checkpoint_attempts']}{reset}")
        
        print(f"\n{bg_hijau}{hitam}═══════════════════════════════════════════════════{reset}\n")

    async def fetch_username_suggestions(self, email: str, full_name: str) -> List[str]:
        """Fetch usernames dari API"""
        url = "https://www.instagram.com/accounts/username_suggestions/"
        
        for attempt in range(1, 6):
            try:
                csrftoken = await self.fetch_csrf()
                if not csrftoken:
                    csrftoken = await self.session.cookie_jar.get_cookie_value("https://www.instagram.com", "csrftoken")
                
                headers = dict(self.base_headers or {})
                if csrftoken:
                    headers.update({"X-CSRFToken": csrftoken, "X-Csrftoken": csrftoken})
                
                headers.update({
                    "Referer": "https://www.instagram.com/accounts/emailsignup/",
                    "Origin": "https://www.instagram.com",
                    "X-Ig-App-Id": self.app_id,
                    "X-Instagram-Ajax": self.ajax,
                    "X-Web-Session-Id": self.web_session_id,
                    "X-Asbd-Id": self.asbd_id,
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                })
                
                try:
                    cj = await self.session.cookie_jar.get_cookie_header("www.instagram.com")
                    if cj:
                        headers["Cookie"] = cj
                except Exception:
                    pass
                
                payload = urlencode({"email": email, "name": full_name}).encode("utf-8")
                
                if self.traffic_shaper:
                    await self.traffic_shaper.shape_traffic("api")
                
                resp = await self._make_request("POST", url, data=payload, headers=headers)
                
                if resp.get("status") == 200:
                    try:
                        parsed = json.loads(resp.get("body", b"").decode(errors="ignore")) if resp.get("body") else {}
                        if parsed.get("status") == "ok":
                            suggestions = parsed.get("suggestions") or []
                            results = [s for s in suggestions if isinstance(s, str)] + \
                                     [s.get("username") for s in suggestions if isinstance(s, dict) and s.get("username")]
                            
                            seen = set()
                            final = [u for u in results if u and u not in seen and not seen.add(u)]
                            
                            if final:
                                print("[fetch_username_suggestions] ✅ Got %d: %s", len(final), final[:3])
                                return final
                    except Exception:
                        pass
                
                await asyncio.sleep(min(30, 2 ** attempt))
            
            except Exception as e:
                logger.warning("[fetch_username_suggestions] Attempt %d: %s", attempt, e)
                await asyncio.sleep(5)
        
        return []

    async def fetch_csrf(self) -> Optional[str]:
        """Get CSRF token"""
        try:
            headers = await self._build_fresh_headers()
            await self.session.get("https://www.instagram.com/accounts/emailsignup/", headers=headers)
            
            csrf = await self.session.cookie_jar.get_cookie_value("https://www.instagram.com", "csrftoken")
            if csrf:
                return csrf
        except Exception:
            pass
        return None

    async def setup_bio(self, bio: Optional[str] = None) -> bool:
        """Setup bio"""
        if not bio:
            bio_templates = [
                "📱 Digital Creator | Content Creator 🎯",
                "🌟 Entrepreneur | Influencer",
                "💼 Business Owner | Marketing 🚀",
                "🎨 Designer | Creative Specialist",
                "📸 Photography | Travel | Lifestyle 🌍",
            ]
            bio = random.choice(bio_templates)
        
        self.bio = bio
        
        try:
            headers = await self._build_fresh_headers()
            resp = await self._make_request_with_challenge_detection("POST", "https://www.instagram.com/api/v1/accounts/set_biography/",
                                                                     data=urlencode({"biography": bio}).encode("utf-8"), headers=headers)
            
            if resp.get("status") == 200:
                print("[setup_bio] ✅ Set: %s", bio[:40])
                self.action_history["setup_bio"] = self.action_history.get("setup_bio", 0) + 1
                return True
        except Exception as e:
            logger.error("[setup_bio] Error: %s", e)
        
        return False

    async def verify_profile_setup(self) -> bool:
        """Verify profile"""
        try:
            headers = await self._build_fresh_headers()
            resp = await self._make_request_with_challenge_detection("GET", f"https://www.instagram.com/api/v1/users/web_profile_info/?username={self.username}", headers=headers)
            
            if resp.get("status") == 200:
                try:
                    data = json.loads(resp.get("body", b"").decode(errors="ignore"))
                    if data.get("status") == "ok":
                        print("[verify_profile_setup] ✅ Verified")
                        return True
                except Exception:
                    pass
        except Exception:
            pass
        return False

    async def login(self) -> bool:
        """Login"""
        if not self.username or not self.password:
            return False
        
        try:
            payload = urlencode({"username": self.username, "password": self.password, "login_attempt_count": "0"}).encode("utf-8")
            headers = await self._build_fresh_headers()
            resp = await self._make_request_with_challenge_detection("POST", "https://www.instagram.com/api/v1/web/accounts/login/ajax/", data=payload, headers=headers)
            
            if resp.get("status") == 200:
                try:
                    body_json = json.loads((resp.get("body") or b"").decode(errors="ignore"))
                    if body_json.get("status") == "ok":
                        self.is_logged_in = True
                        self.logged_in_at = _now()
                        print("[login] ✅ Success")
                        self.action_history["login"] = self.action_history.get("login", 0) + 1
                        return True
                except Exception:
                    pass
        except Exception:
            pass
        return False

    async def logout(self) -> bool:
        """Logout"""
        if not self.is_logged_in:
            return False
        
        try:
            await self.save_session()
            headers = await self._build_fresh_headers()
            resp = await self._make_request_with_challenge_detection("POST", "https://www.instagram.com/api/v1/web/accounts/logout/ajax/",
                                                                     data=urlencode({"csrfmiddlewaretoken": "dummy"}).encode("utf-8"), headers=headers)
            
            if resp.get("status") == 200:
                try:
                    body_json = json.loads((resp.get("body") or b"").decode(errors="ignore"))
                    if body_json.get("status") == "ok":
                        self.is_logged_in = False
                        print("[logout] ✅ Success")
                        self.action_history["logout"] = self.action_history.get("logout", 0) + 1
                        return True
                except Exception:
                    pass
        except Exception:
            pass
        return False

    async def simulate_user_behavior(self, duration: int = 60) -> bool:
        """Simulate behavior"""
        if not self.is_logged_in:
            return False
        
        print("[simulate_user_behavior] Starting for %d seconds", duration)
        start_time = _now()
        
        while _now() - start_time < duration:
            try:
                action = random.choice([
                    self._action_browse_feed,
                    self._action_view_profile,
                    self._action_search_user,
                ])
                
                await action()
                await asyncio.sleep(random.uniform(5.0, 30.0))
            except Exception:
                await asyncio.sleep(5)
        
        print("[simulate_user_behavior] ✅ Completed")
        return True

    async def _action_browse_feed(self):
        """Browse feed action"""
        try:
            headers = await self._build_fresh_headers()
            headers["Referer"] = "https://www.instagram.com/"
            await self._make_request_with_challenge_detection("GET", "https://www.instagram.com/api/v1/feed/timeline/", headers=headers)
            self.action_history["browse_feed"] = self.action_history.get("browse_feed", 0) + 1
        except Exception:
            pass

    async def _action_view_profile(self):
        """View profile action"""
        try:
            user = random.choice(["instagram", "facebook", "google"])
            headers = await self._build_fresh_headers()
            headers["Referer"] = f"https://www.instagram.com/{user}/"
            await self._make_request_with_challenge_detection("GET", f"https://www.instagram.com/api/v1/users/web_profile_info/?username={user}", headers=headers)
            self.action_history["view_profile"] = self.action_history.get("view_profile", 0) + 1
        except Exception:
            pass

    async def _action_search_user(self):
        """Search action"""
        try:
            query = random.choice(["photography", "travel", "fitness"])
            headers = await self._build_fresh_headers()
            await self._make_request_with_challenge_detection("GET", f"https://www.instagram.com/api/v1/users/search/?query={query}", headers=headers)
            self.action_history["search"] = self.action_history.get("search", 0) + 1
        except Exception:
            pass

    async def get_jazoest(self, url="https://www.instagram.com/accounts/emailsignup/"):
        """Enhanced jazoest fetching dengan traffic shaping"""
        try:
            headers = await self._build_fresh_headers()
            
            r = await self.session.request(url, headers=headers, use_chromium=False)
            html_clean = self.decode_instagram_html(r)
            match = re.search(r'jazoest=(\d+)', html_clean)
            if match:
                return match.group(1)
        except Exception:
            pass
        return "22345"

    async def _inject_headers_to_chromium(self, page, headers: Optional[Dict[str, str]] = None):
        """Inject headers ke Chromium page"""
        
        try:
            if not headers:
                headers = await self._build_fresh_headers()
            
            # Remove headers yang tidak boleh di-set
            forbidden_headers = {"Host", "Content-Length", "User-Agent"}
            safe_headers = {k: v for k, v in headers.items() if k not in forbidden_headers}
            
            await page.set_extra_http_headers(safe_headers)
            
            if self.verbose:
                logger.debug("[_inject_headers_to_chromium] %d headers injected", len(safe_headers))
        
        except Exception as e:
            logger.error("[_inject_headers_to_chromium] Error: %s", e)

    def _get_stealth_script(self) -> str:
        """Enhanced stealth script"""
        return """
        // Prevent detection
        Object.defineProperty(navigator, 'webdriver', {get: () => false});
        Object.defineProperty(navigator, 'plugins', {get: () => [1, 2, 3, 4, 5]});
        Object.defineProperty(navigator, 'languages', {get: () => ['en-US', 'en']});
        
        // Mock permissions
        const originalQuery = window.navigator.permissions.query;
        window.navigator.permissions.query = (parameters) => (
            parameters.name === 'notifications' ?
                Promise.resolve({ state: Notification.permission }) :
                originalQuery(parameters)
        );
        
        // Mock chrome runtime
        window.chrome = { runtime: {} };
        
        // Remove automation traces
        delete window.cdc_adoQpoasnfa76pfcZLmcfl_Array;
        delete window.cdc_adoQpoasnfa76pfcZLmcfl_Promise;
        delete window.cdc_adoQpoasnfa76pfcZLmcfl_Symbol;
        """

    async def _ensure_logged_out(self, page):
        """Quick method untuk memastikan clean state - simplified"""
        try:
            print("   🧹 Ensuring clean session state...")
            
            # Quick cleanup - focus on what matters
            await page.context.clear_cookies()
            
            await page.evaluate("""() => {
                try {
                    localStorage.clear();
                    sessionStorage.clear();
                } catch(e) {}
            }""")
            
            # Quick navigation to signup page (bypass any logged-in state)
            try:
                await page.goto("https://www.instagram.com/accounts/emailsignup/", 
                            wait_until="domcontentloaded", 
                            timeout=10000)
                await asyncio.sleep(2)
            except:
                pass
                
            print("   ✅ Session cleaned - Ready for new account")
            
        except Exception as e:
            print(f"   ⚠️ Quick cleanup skipped: {e}")

    async def _get_random_viewport(self):
        """Random viewport untuk setiap session"""
        viewports = [
            {"width": 1920, "height": 1080},
            {"width": 1366, "height": 768}, 
            {"width": 1536, "height": 864},
            {"width": 1440, "height": 900}
        ]
        return random.choice(viewports)
    
    async def _inject_enhanced_stealth(self, page):
        """Enhanced stealth injection untuk page"""
        stealth_script = """
        // Enhanced stealth - remove all automation traces
        delete window.cdc_adoQpoasnfa76pfcZLmcfl_Array;
        delete window.cdc_adoQpoasnfa76pfcZLmcfl_Promise;
        delete window.cdc_adoQpoasnfa76pfcZLmcfl_Symbol;
        
        // Override webdriver
        Object.defineProperty(navigator, 'webdriver', {
            get: () => undefined,
        });
        
        // Override chrome runtime
        Object.defineProperty(window, 'chrome', {
            get: () => ({
                runtime: {},
                loadTimes: () => {},
                csi: () => {},
                app: {},
            }),
        });
        
        // Mock permissions
        const originalQuery = window.navigator.permissions.query;
        window.navigator.permissions.query = (parameters) => (
            parameters.name === 'notifications' ?
                Promise.resolve({ state: Notification.permission }) :
                originalQuery(parameters)
        );
        
        console.log('Enhanced stealth activated');
        """
        await page.add_init_script(stealth_script)
    
    async def _verify_clean_session(self, page):
        """Verify bahwa session benar-benar clean"""
        try:
            # Test automation detection
            tests = await page.evaluate("""
                () => {
                    return {
                        webdriver: navigator.webdriver,
                        chrome: !!window.chrome,
                        automation: !!window.cdc_adoQpoasnfa76pfcZLmcfl_Array,
                        plugins: navigator.plugins.length,
                        languages: navigator.languages
                    };
                }
            """)
            
            # Check untuk automation traces
            if tests.get('webdriver') or tests.get('automation'):
                print(f"   🚨 Automation detected: {tests}")
                return False
            
            print(f"   ✅ Session clean: webdriver={tests.get('webdriver')}, automation={tests.get('automation')}")
            return True
            
        except Exception as e:
            print(f"   ⚠️ Clean session check failed: {e}")
            return True  # Continue anyway

    def _generate_fallback_username(self) -> str:
        """Generate fallback username yang panjang dan unique"""
        try:
            # Kombinasi timestamp + random string untuk uniqueness maksimal
            timestamp = int(time.time() * 1000)  # millisecond precision
            random_str = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=12))
            
            # Format: base + timestamp + random_string
            base_name = self.full_name.lower() if self.full_name else "user"
            base_name = re.sub(r'[^a-zA-Z0-9]', '', base_name)
            
            if len(base_name) < 2:
                base_name = "social"
            
            username = f"{base_name}_{timestamp}_{random_str}"
            
            # Potong jika terlalu panjang (max 50 chars untuk safety)
            if len(username) > 50:
                username = username[:50]
                
            logger.debug("Generated fallback username: %s", username)
            return username
            
        except Exception as e:
            logger.warning("Fallback username generation failed: %s", e)
            # Ultimate fallback dengan nanosecond precision
            return f"user_{int(time.time_ns())}_{random.randint(100000, 999999)}"

    async def create(self, pwd: str):
        """FINAL FIXED INSTAGRAM ACCOUNT CREATION WITH VERSION AUTO-DETECTION"""
        
        print("┌─────────────────────────────────────────────┐")
        print("│      VERSION AUTO-DETECTION CREATION       │")
        print("└─────────────────────────────────────────────┘")
        
        mail = None
        page = None
        
        try:
            # ========== PASSWORD VALIDATION ==========
            print("🔐 STEP 0: Password validation...")

            # Enhanced password cleaning and validation
            original_pwd = pwd
            pwd = re.sub(r'\s+', '', str(pwd))
            pwd = pwd.strip()

            if not pwd or len(pwd) < 6:
                logger.error("❌ Password is empty or too short (min 6 characters)")
                self.status = 4
                self.password = ''
                return self._return_data()

            # Store the CLEAN password IMMEDIATELY
            self.password = pwd
            print("   ✅ Password stored: %s", "*" * len(pwd))
            print("   📏 Password length: %d characters", len(pwd))

            # ========== BROWSER INITIALIZATION ==========
            print("🚀 STEP 1: Browser initialization...")

            delay = self.anti_detection.calculate_smart_delay()
            await asyncio.sleep(delay)
            
            self.use_chromium = True
            self.use_chromium_for_signup = True
            
            if self.chromium_started:
                print("🔄 Restarting Chromium session...")
                await self.stop_chromium()
                await asyncio.sleep(3)
            
            await self.init_session()
            
            if not self.chromium_started:
                logger.error("❌ Chromium initialization failed")
                self.status = 4
                return self._return_data()

            page = await self.browser_context.new_page()

            await page.context.clear_cookies()

            await self._inject_enhanced_stealth(page)
            
            # Verify session cleanliness
            if not await self._verify_clean_session(page):
                print("   🚨 Session not clean, skipping...")
                return False

            await page.set_extra_http_headers({
                'Accept-Language': 'en-US,en;q=0.9',
            })

            print("   🧹 Cleaning page state...")
            await self._ensure_logged_out(page)
            
            print("✅ Browser setup completed")

            # ========== ACCOUNT DATA GENERATION ==========
            print("")
            print("📝 STEP 2: Account data generation...")
            
            print("   📧 Generating email...")
            email_new = None
            max_retries = 3
            name_first = fake.user_name()
            
            for attempt in range(max_retries):
                try:
                    if self.tmp == 1:
                        mail = MailTm()
                        email_new = mail.register()
                        if email_new:
                            print("   ✅ MailTm email: %s", email_new)
                            break
                    elif self.tmp == 2:
                        email_new = Sepuluh.get_mail(name_first)
                        if email_new:
                            print("   ✅ Sepuluh email: %s", email_new)
                            break
                    elif self.tmp == 3:
                        gmail = GmailAlias(self.gmail_base)
                        email_new = gmail.unique_alias()
                        if email_new:
                            print("   ✅ Cmail email: %s", email_new)
                            break
                except Exception as e:
                    logger.warning("   ⚠️ Email attempt %d failed: %s", attempt + 1, e)
                    if attempt < max_retries - 1:
                        await asyncio.sleep(2)
            
            if not email_new:
                logger.error("   ❌ All email generation attempts failed")
                self.status = 4
                return self._return_data()
            
            self.email_new = email_new
            self.full_name = fake.name()
            full_name = self.full_name
            print("   👨‍💼 Full Name: %s", full_name)
            
            print("   👤 Generating username...")
            try:
                usernames = await self.fetch_username_suggestions(email_new, name_first)
                if usernames and len(usernames) > 0:
                    usernam = usernames[0]
                    usernam = re.sub(r'[^a-zA-Z0-9._]', '', usernam)
                    if len(usernam) < 3:
                        usernam = self._generate_fallback_username()
                else:
                    usernam = self._generate_fallback_username()
            except Exception as e:
                logger.warning("   ⚠️ Username suggestions failed: %s, using fallback", e)
                usernam = self._generate_fallback_username()

            self.username = usernam
            print("   ✅ Username: %s", usernam)
            
            current_year = datetime.now().year
            birth_year = random.randint(current_year-25, current_year-18)
            birth_month = random.randint(1, 12)
            birth_day = random.randint(1, 28)
            print("   🎂 Birthday: %d-%02d-%02d", birth_year, birth_month, birth_day)
            
            print("✅ Account data completed!")

            # ========== NAVIGATION ==========
            print("")
            print("🌐 STEP 3: Navigation...")
            
            try:
                urls_to_try = [
                    "https://www.instagram.com/accounts/emailsignup/",
                    "https://instagram.com/accounts/emailsignup/",
                ]
                
                success = False
                for i, url in enumerate(urls_to_try):
                    print("   🔗 Attempt %d: %s", i+1, url)
                    try:
                        await page.goto(url, wait_until="networkidle", timeout=45000)
                        await asyncio.sleep(4)
                        
                        page_title = (await page.title()).lower()
                        page_url = page.url.lower()
                        
                        print("   📄 Page title: %s", page_title)
                        print("   🔗 Current URL: %s", page_url)
                        
                        if any(keyword in page_url or keyword in page_title for keyword in ['signup', 'join', 'create']):
                            print("   ✅ Successfully reached signup page!")
                            success = True
                            break
                        else:
                            logger.warning("   ⚠️ Not on signup page, trying next...")
                            
                    except Exception as e:
                        logger.warning("   ❌ URL attempt failed: %s", e)
                        continue
                
                if not success:
                    logger.error("   ❌ All navigation attempts failed")
                    try:
                        await page.screenshot(path="./debug_initial_page.png", timeout=5000)
                        print("   📸 Screenshot saved")
                    except Exception as e:
                        print("   ⚠️ Screenshot skipped: %s", e)
                    self.status = 4
                    return self._return_data()
                
                try:
                    await page.screenshot(path="./debug_initial_page.png", timeout=5000)
                    print("   📸 Screenshot saved")
                except Exception as e:
                    print("   ⚠️ Screenshot skipped: %s", e)
                print("   📸 Screenshot saved")
                    
            except Exception as e:
                logger.error("   ❌ Navigation failed: %s", e)
                self.status = 4
                return self._return_data()
            
            # ========== FULLY DYNAMIC FORM PROCESSING ==========
            print("")
            print("🔍 STEP 4: Fully Dynamic Form Processing...")
            print("   🔄 Using adaptive form detection that works with any form structure")
            
            await asyncio.sleep(3)
            
            # Use the new fully dynamic form processor
            success = await self._process_form_dynamically(
                page, email_new, pwd, full_name, usernam, 
                birth_year, birth_month, birth_day
            )
            
            # Fallback to version-specific processing if dynamic fails
            if not success:
                print("")
                print("   ⚠️ Dynamic processing failed, trying version-specific fallback...")
                
                # Detect form version for fallback
                form_version = await self._detect_form_version(page)
                print(f"   🎯 DETECTED FORM VERSION: {form_version}")
                
                if form_version == "version_1":
                    success = await self._process_version_1(page, email_new, pwd, full_name, usernam, birth_year, birth_month, birth_day, form_version)
                elif form_version == "version_2":
                    success = await self._process_version_2(page, email_new, pwd, full_name, usernam, birth_year, birth_month, birth_day)
                elif form_version == "version_3":
                    success = await self._process_version_1(page, email_new, pwd, full_name, usernam, birth_year, birth_month, birth_day, form_version)
                else:
                    logger.error("   ❌ Could not detect form version")
                    self.status = 4
                    return self._return_data()
            
            if not success:
                self.status = 4
                return self._return_data()
            
            # ========== OTP PROCESSING WITH RETRY ==========
            if self.status == 2:
                print("")
                print("📧 STEP 5: OTP Verification with Retry...")
                
                max_otp_retries = 2  # Maximum 2 retries dengan email berbeda
                otp_success = False
                current_email = self.email_new
                
                for otp_attempt in range(max_otp_retries + 1):
                    print(f"   🔄 OTP Attempt {otp_attempt + 1}/{max_otp_retries + 1}")
                    print(f"   📧 Using email: {current_email}")
                    
                    # Try OTP verification
                    otp_success = await self._handle_otp_verification(page, current_email)
                    
                    if otp_success:
                        self.status = 1
                        print("   🎉 ACCOUNT FULLY VERIFIED AND READY!")
                        break
                    else:
                        print(f"   ❌ OTP attempt {otp_attempt + 1} failed")
                        
                        # Check if we need to close session (OTP not received)
                        if self.status == STATUS_OTP_NOT_RECEIVED:
                            print("   🚫 OTP code not received - IMMEDIATELY closing session")
                            print("   ⏹️ Session closed. Please start a new session with fresh fingerprint/IP")
                            # Immediately close session and return - no retry with same session
                            try:
                                if page:
                                    await page.close()
                                await self.stop_chromium()
                                await self._cleanup_chromium_profiles()
                            except Exception:
                                pass
                            return self._return_data()
                        
                        # Check if phone verification required - close session
                        if self.status == STATUS_PHONE_REQUIRED:
                            print("   📱 Phone verification required - IMMEDIATELY closing session")
                            print("   ⏹️ Session closed. Please start a new session with different identity")
                            # Immediately close session and return - need different approach
                            try:
                                if page:
                                    await page.close()
                                await self.stop_chromium()
                                await self._cleanup_chromium_profiles()
                            except Exception:
                                pass
                            return self._return_data()
                        
                        if otp_attempt < max_otp_retries:
                            print("   🔄 Preparing for OTP retry with new email...")
                            
                            # 1. Kembali ke halaman signup awal
                            print("   ↩️ Navigating back to signup page...")
                            back_success = await self._navigate_back_to_signup(page)
                            if not back_success:
                                print("   ❌ Failed to navigate back to signup page")
                                break
                            
                            # 2. Generate new email
                            print("   📧 Generating new email...")
                            new_email = await self._generate_new_email(otp_attempt)
                            if not new_email:
                                print("   ❌ Failed to generate new email")
                                break
                            
                            current_email = new_email
                            self.email_new = new_email
                            print(f"   ✅ New email: {new_email}")
                            
                            # 3. Isi form lagi dengan email baru
                            print("   📝 Filling form with new email...")
                            # Use dynamic form processor for retry (handles any form layout)
                            form_success = await self._process_form_dynamically(
                                page, new_email, pwd, full_name, usernam,
                                birth_year, birth_month, birth_day
                            )
                            
                            if not form_success:
                                print("   ❌ Failed to fill form with new email")
                                break
                                
                            print("   🔄 Waiting before next OTP attempt...")
                            await asyncio.sleep(5)
                
                if not otp_success:
                    self.status = 3
                    print("   ⚠️ ALL OTP ATTEMPTS FAILED - NEED MANUAL INTERVENTION")

            return self._return_data()
            
        except Exception as e:
            logger.error("❌ CREATION FAILED: %s", e)
            import traceback
            logger.error(traceback.format_exc())
            self.status = 4
            return self._return_data()
        
        finally:
            # ========== CLEANUP ==========
            print("🧹 FINAL CLEANUP...")
            try:
                if page:
                    await page.close()
            except:
                pass
                
            try:
                await self.stop_chromium()  # ✅ Ini akan panggil ChromiumManager.stop_chromium()
            except:
                pass
            
            # CLEANUP FILES SETELAH SELESAI
            await self._cleanup_chromium_profiles()

    async def _navigate_back_to_signup(self, page) -> bool:
        """Navigate back to signup page dengan timeout lebih pendek"""
        try:
            print("   🔙 Attempting to go back to signup page...")
            
            # Method 1: Coba reload page dulu
            try:
                await page.reload(wait_until="domcontentloaded", timeout=15000)
                await asyncio.sleep(3)
            except:
                pass
            
            # Method 2: Go to signup URL langsung dengan timeout lebih pendek
            print("   🔗 Going to signup URL directly...")
            try:
                await page.goto("https://www.instagram.com/accounts/emailsignup/", 
                            wait_until="domcontentloaded", timeout=20000)  # Reduced timeout
                await asyncio.sleep(3)
                
                # Verify we're on signup page
                current_url = page.url.lower()
                if any(keyword in current_url for keyword in ['signup', 'emailsignup', 'accounts/emailsignup']):
                    print("   ✅ Successfully returned to signup page")
                    return True
            except Exception as e:
                logger.warning("   ⚠️ Direct navigation failed: %s", e)
            
            # Method 3: Use simple JavaScript navigation
            print("   🚀 Trying JavaScript navigation...")
            try:
                await page.evaluate("""() => {
                    window.location.href = 'https://www.instagram.com/accounts/emailsignup/';
                }""")
                await asyncio.sleep(5)  # Wait longer for JS navigation
                return True
            except Exception as e:
                logger.warning("   ⚠️ JS navigation failed: %s", e)
            
            print("   ❌ All back methods failed")
            return False
            
        except Exception as e:
            logger.error("   ❌ Navigate back failed: %s", e)
            return False

    async def _generate_new_email(self, attempt: int) -> str:
        """Generate new email for OTP retry"""
        name_first = fake.user_name()
        
        try:
            if self.tmp == 1:
                mail = MailTm()
                return mail.register()
            elif self.tmp == 2:
                return Sepuluh.get_mail(name_first)
            elif self.tmp == 3:
                set_name, set_email = Cmail.get_random(3)
                return f"{set_name}@{name_first}"
        except Exception as e:
            logger.error("   ❌ Failed to generate new email: %s", e)
        
        return None

    async def _detect_form_version(self, page) -> str:
        """Debug version detection with FULL analysis for Version 1, 2, and 3"""
        print("   🔍 Debug version detection...")
        
        try:
            await page.screenshot(path="./debug_initial_page.png", timeout=5000)
            print("   📸 Screenshot saved")
        except Exception as e:
            print("   ⚠️ Screenshot skipped: %s", e)
        
        # Check Facebook buttons
        facebook_selectors = [
            'button:has-text("Log in with Facebook")',
            'button:has-text("Continue with Facebook")', 
            'button:has-text("Facebook")',
            '[aria-label*="Facebook" i]',
            '[data-testid*="facebook"]'
        ]
        
        facebook_found = False
        for selector in facebook_selectors:
            elements = await page.query_selector_all(selector)
            for element in elements:
                if await element.is_visible():
                    button_text = await element.text_content() or ""
                    print(f"   📱 Facebook button FOUND: '{button_text.strip()}' with {selector}")
                    facebook_found = True
                    break
            if facebook_found:
                break
        
        if not facebook_found:
            print("   📱 No Facebook button found")
        
        # Check birthday fields - PERBAIKI SELECTOR INI
        birthday_selectors = [
            'select[name="birthday_year"]',
            'select[title="Year:"]',
            'select[aria-label="Year:"]',
            'select[name="birthday_month"]', 
            'select[name="birthday_day"]',
            'select:has(option[value="1990"])'  # Common birth year
        ]
        
        birthday_found = False
        birthday_fields_count = 0
        for selector in birthday_selectors:
            elements = await page.query_selector_all(selector)
            for element in elements:
                if await element.is_visible():
                    field_name = await element.get_attribute('name') or await element.get_attribute('title') or await element.get_attribute('aria-label') or selector
                    print(f"   🎯 Birthday field FOUND: '{field_name}' with {selector}")
                    birthday_found = True
                    birthday_fields_count += 1
                    break
        
        print(f"   🎯 Total birthday fields found: {birthday_fields_count}")
        
        if not birthday_found:
            print("   🎯 No birthday fields found")
        
        # Check "Log in with existing account" button (SPECIFIC untuk Version 3)
        existing_account_selectors = [
            'button:has-text("Log in with existing account")',
            'button:has-text("Log in to existing account")',
            'a:has-text("Log in with existing account")',
            'a:has-text("Log in to existing account")'
        ]
        
        existing_account_found = False
        for selector in existing_account_selectors:
            elements = await page.query_selector_all(selector)
            for element in elements:
                if await element.is_visible():
                    button_text = await element.text_content() or ""
                    print(f"   🔄 Existing account button FOUND: '{button_text.strip()}' with {selector}")
                    existing_account_found = True
                    break
            if existing_account_found:
                break
        
        if not existing_account_found:
            print("   🔄 No existing account button found")
        
        # Check semua field yang ada untuk konfirmasi
        field_selectors = {
            'email': ['input[name="email"]', 'input[name="emailOrPhone"]'],
            'full_name': ['input[name="fullName"]'],
            'username': ['input[name="username"]'], 
            'password': ['input[name="password"]']
        }
        
        print("   📋 Field analysis:")
        for field_name, selectors in field_selectors.items():
            found = False
            for selector in selectors:
                element = await page.query_selector(selector)
                if element and await element.is_visible():
                    print(f"   ✅ {field_name} field: FOUND")
                    found = True
                    break
            if not found:
                print(f"   ❌ {field_name} field: NOT FOUND")
        
        # ========== FINAL VERSION DETECTION ==========
        print("   🎯 FINAL VERSION ANALYSIS:")
        print(f"   - Facebook button: {'YES' if facebook_found else 'NO'}")
        print(f"   - Birthday fields: {'YES' if birthday_found else 'NO'} ({birthday_fields_count} fields)")
        print(f"   - Existing account button: {'YES' if existing_account_found else 'NO'}")
        
        # VERSION 3: Birthday + Facebook + Existing account buttons
        if birthday_found and facebook_found and existing_account_found:
            print("   ✅ VERSION 3 DETECTED: Birthday + Facebook + Existing account buttons")
            return "version_3"
        
        # VERSION 2: Facebook button + NO birthday
        elif facebook_found and not birthday_found:
            print("   ✅ VERSION 2 DETECTED: Facebook button + NO birthday")
            return "version_2"
        
        # VERSION 1: Birthday + NO Facebook button  
        elif birthday_found and not facebook_found:
            print("   ✅ VERSION 1 DETECTED: Birthday + NO Facebook button")
            return "version_1"
        
        # FALLBACK: Berdasarkan field yang ada
        elif birthday_found:
            print("   ⚠️ FALLBACK: Version 1 (birthday found)")
            return "version_1"
        elif facebook_found:
            print("   ⚠️ FALLBACK: Version 2 (Facebook found)") 
            return "version_2"
        else:
            print("   ⚠️ UNKNOWN: Default to Version 1")
            return "version_1"

    async def _process_version_1(self, page, email: str, password: str, full_name: str, username: str, 
                            birth_year: int, birth_month: int, birth_day: int, form_version: str) -> bool:
        """Process Version 1: All fields in one form with enhanced dynamic detection"""
        print("   📝 Processing Version 1 form...")
        
        # ========== ENHANCED DYNAMIC FORM DETECTION ==========
        print("   🔍 Starting enhanced dynamic form field detection...")
        
        await asyncio.sleep(3)
        
        field_mapping = {}
        
        # ========== STEP 1: Use new dynamic detection ==========
        print("   🔄 Step 1: Enhanced dynamic detection using FIELD_PATTERNS...")
        
        detected_fields = await self._detect_form_fields_dynamically(page)
        
        # Map detected fields to our internal naming
        field_name_mapping = {
            'email': 'email_field',
            'password': 'password_field',
            'fullname': 'name_field',
            'username': 'username_field'
        }
        
        for detected_type, internal_name in field_name_mapping.items():
            if detected_type in detected_fields:
                field_mapping[internal_name] = detected_fields[detected_type]
                print(f"   ✅ {internal_name} detected via dynamic detection")
        
        print(f"   📊 Dynamic detection found {len(field_mapping)} fields (confidence: {detected_fields.get('confidence', 0):.1%})")
        
        # ========== STEP 2: Fallback to direct attribute matching ==========
        print("   🎯 Step 2: Direct attribute matching for missing fields...")
        
        field_selectors = {
            'email_field': [
                'input[name="emailOrPhone"]',
                'input[aria-label*="email" i]',
                'input[placeholder*="email" i]',
                'input[type="email"]',
            ],
            'password_field': [
                'input[type="password"]',
                'input[name*="password" i]',
                'input[aria-label*="password" i]',
            ],
            'name_field': [
                'input[name="fullName"]',
                'input[aria-label*="full name" i]',
                'input[placeholder*="full name" i]',
            ],
            'username_field': [
                'input[name="username"]',
                'input[aria-label*="username" i]',
                'input[placeholder*="username" i]'
            ]
        }
        
        for field_type, selectors in field_selectors.items():
            if field_type not in field_mapping:  # Only search for missing fields
                for selector in selectors:
                    try:
                        element = await page.query_selector(selector)
                        if element and await element.is_visible():
                            field_mapping[field_type] = element
                            print(f"   ✅ {field_type} found with: {selector}")
                            break
                    except Exception:
                        continue
        
        # ========== STEP 3: Position-based detection for remaining fields ==========
        print("   📍 Step 3: Position-based detection for remaining fields...")
        
        all_inputs = await page.query_selector_all('input:not([type="hidden"])')
        visible_inputs = []
        
        for inp in all_inputs:
            try:
                if await inp.is_visible():
                    bbox = await inp.bounding_box()
                    if bbox and bbox['width'] > 0 and bbox['height'] > 0:
                        visible_inputs.append({
                            'element': inp,
                            'y': bbox['y'],
                            'type': await inp.get_attribute('type') or 'text',
                        })
            except Exception:
                continue
        
        visible_inputs.sort(key=lambda x: x['y'])
        
        print(f"   📊 Found {len(visible_inputs)} visible inputs")
        
        position_mapping = {
            0: 'email_field',
            1: 'password_field', 
            2: 'name_field',
            3: 'username_field'
        }
        
        for i, inp_data in enumerate(visible_inputs[:4]):
            field_type = position_mapping.get(i)
            if field_type and field_type not in field_mapping:
                field_mapping[field_type] = inp_data['element']
                print(f"   ✅ {field_type} mapped by position {i}")
        
        # ========== BIRTHDAY FIELD DETECTION ==========
        birthday_success = await self._fill_birthday_fields_v3(page, birth_year, birth_month, birth_day, form_version)
        
        if not birthday_success:
            print("   ⚠️ Birthday filling failed, but continuing...")
            # Take screenshot untuk debug
            try:
                await page.screenshot(path="./debug_birthday_failed.png")
            except:
                pass
        else:
            print("   ✅ Birthday filled successfully")
        
        required_fields = ['email_field', 'password_field']
        missing_fields = [f for f in required_fields if f not in field_mapping]
        
        if missing_fields:
            logger.error("   ❌ Missing required fields: %s", missing_fields)
            try:
                await page.screenshot(path="./debug_initial_page.png", timeout=5000)
                print("   📸 Screenshot saved")
            except Exception as e:
                print("   ⚠️ Screenshot skipped: %s", e)
            return False
        
        print("✅ Form detection completed!")

        # ========== FORM FILLING ==========
        print("")
        print("📝 Form filling...")

        try:
            # Fill basic fields
            print("   📧 Filling basic fields...")
            
            # Email
            email_field = field_mapping['email_field']
            await email_field.click()
            await asyncio.sleep(0.5)
            await email_field.fill("")
            await asyncio.sleep(0.3)
            await email_field.type(email, delay=80)
            await asyncio.sleep(1)

            # Password
            password_field = field_mapping['password_field']
            await password_field.click()
            await asyncio.sleep(0.5)
            await password_field.fill("")
            await asyncio.sleep(0.3)
            await password_field.type(password, delay=70)
            await asyncio.sleep(1)

            # Name
            if 'name_field' in field_mapping:
                name_field = field_mapping['name_field']
                await name_field.click()
                await asyncio.sleep(0.3)
                await name_field.fill("")
                await asyncio.sleep(0.3)
                await name_field.type(full_name, delay=90)
                await asyncio.sleep(1)

            # Username
            if 'username_field' in field_mapping:
                username_field = field_mapping['username_field']
                await username_field.click()
                await asyncio.sleep(0.3)
                await username_field.fill("")
                await asyncio.sleep(0.3)
                await username_field.type(username, delay=80)
                await asyncio.sleep(1)

            # ========== BIRTHDAY FILLING ==========
            print("   🎂 Birthday filling...")

            birthday_filled = False

            if all(f in field_mapping for f in ['month_input', 'day_input', 'year_input']):
                try:
                    print("   📝 Filling birthday via custom combobox...")
                    
                    month_str = f"{birth_month}"
                    day_str = f"{birth_day}"
                    year_str = f"{birth_year}"
                    
                    # MONTH
                    print("   📅 Selecting month...")
                    await field_mapping['month_input'].click()
                    await asyncio.sleep(1)
                    
                    month_option = await page.query_selector(f'[role="option"]:has-text("{month_str}")')
                    if not month_option:
                        month_option = await page.query_selector(f'[role="option"]:nth-child({birth_month})')
                    
                    if month_option:
                        await month_option.click()
                        await asyncio.sleep(0.5)
                        print("   ✅ Month selected")
                    
                    # DAY
                    print("   📅 Selecting day...")
                    await field_mapping['day_input'].click()
                    await asyncio.sleep(1)
                    
                    day_option = await page.query_selector(f'[role="option"]:has-text("{day_str}")')
                    if not day_option:
                        day_option = await page.query_selector(f'[role="option"]:nth-child({birth_day})')
                        
                    if day_option:
                        await day_option.click()
                        await asyncio.sleep(0.5)
                        print("   ✅ Day selected")
                    
                    # YEAR
                    print("   📅 Selecting year...")
                    await field_mapping['year_input'].click()
                    await asyncio.sleep(1)
                    
                    year_option = await page.query_selector(f'[role="option"]:has-text("{year_str}")')
                    if not year_option:
                        year_selectors = [
                            f'[role="option"]:has-text("{year_str}")',
                            f'[data-value="{year_str}"]',
                            f'[value="{year_str}"]'
                        ]
                        for selector in year_selectors:
                            year_option = await page.query_selector(selector)
                            if year_option:
                                break
                    
                    if year_option:
                        await year_option.scroll_into_view_if_needed()
                        await asyncio.sleep(0.5)
                        await year_option.click()
                        await asyncio.sleep(0.5)
                        print("   ✅ Year selected")
                    
                    birthday_filled = True
                    print("   ✅ Birthday filled via custom combobox")
                    
                    await asyncio.sleep(1)
                    try:
                        await page.screenshot(path="./debug_birthday_filled.png", timeout=5000)
                        print("   📸 Birthday verification screenshot saved")
                    except Exception as e:
                        print("   ⚠️ Screenshot skipped: %s", e)
                    
                except Exception as e:
                    logger.error(f"   ❌ Custom combobox filling failed: {e}")

            if not birthday_filled:
                logger.error("   ❌ UNABLE TO FILL BIRTHDAY COMBOBOXES")
                return False
            
        except Exception as e:
            logger.error("   ❌ Form filling failed: %s", e)
            try:
                await page.screenshot(path="./debug_birthday_filled.png", timeout=5000)
            except Exception as e:
                print("   ⚠️ Screenshot skipped: %s", e)
            return False

        # ========== ENHANCED BUTTON DETECTION & SUBMISSION ==========
        print("")
        print("   🔎 Enhanced button detection with scroll support...")

        # First, scroll to ensure all elements are visible
        print("   📜 Scrolling to reveal all buttons...")
        await self._scroll_page_to_bottom(page)
        await asyncio.sleep(1)
        
        try:
            await page.screenshot(path="./debug_birthday_filled.png", timeout=5000)
        except Exception as e:
            print("   ⚠️ Screenshot skipped: %s", e)

        # Use enhanced button detection for signup step
        submit_success = await self._detect_and_click_submit_button(page, "signup")
        
        if not submit_success:
            print("   🔄 Fallback: Legacy button detection strategies...")
            
            submit_button = None

            # Strategy 1: Instagram's specific button patterns
            instagram_button_selectors = [
                'button[type="submit"]',
                'button._acan._acap._acas',
                'button._aact',
                'button:has-text("Sign up")',
                'button:has-text("Sign Up")',
                'button:has-text("Submit")',
                'button:has-text("Daftar")',  # Indonesian
                'button:has-text("Next")',
                'button:has-text("Lanjut")',  # Indonesian
            ]

            for selector in instagram_button_selectors:
                try:
                    buttons = await page.query_selector_all(selector)
                    for button in buttons:
                        try:
                            # SCROLL EACH BUTTON INTO VIEW before checking visibility
                            await button.scroll_into_view_if_needed()
                            await asyncio.sleep(0.5)
                            
                            if await button.is_visible() and await button.is_enabled():
                                button_text = (await button.text_content() or "").strip()
                                print(f"   🔘 Found candidate: '{button_text}' with {selector}")
                                
                                # Validate it's actually a submit button
                                if button_text and any(word in button_text.lower() for word in ['sign up', 'submit', 'next', 'continue', 'daftar', 'lanjut']):
                                    submit_button = button
                                    print(f"   ✅ SELECTED submit button: '{button_text}'")
                                    break
                        except Exception:
                            continue
                    if submit_button:
                        break
                except Exception:
                    continue

            # Strategy 2: If not found, try scrolling and searching again
            if not submit_button:
                print("   🔄 Strategy 2: Additional scrolling and search...")
                
                # Scroll to very bottom and search again
                await page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
                await asyncio.sleep(2)
                
                all_buttons = await page.query_selector_all('button, [role="button"]')
                for button in all_buttons:
                    try:
                        await button.scroll_into_view_if_needed()
                        await asyncio.sleep(0.3)
                        
                        if await button.is_visible() and await button.is_enabled():
                            button_text = (await button.text_content() or "").strip().lower()
                            print(f"   🔘 Button after scroll: '{button_text}'")
                            
                            if any(word in button_text for word in ['sign up', 'submit', 'next', 'continue', 'daftar', 'lanjut']):
                                submit_button = button
                                print(f"   ✅ SELECTED button after scroll: '{button_text}'")
                                break
                    except Exception:
                        continue

            # Strategy 3: Look for buttons inside form (with scroll)
            if not submit_button:
                print("   🔍 Strategy 3: Looking for buttons inside forms...")
                forms = await page.query_selector_all('form')
                for form in forms:
                    form_buttons = await form.query_selector_all('button:not([disabled])')
                    for button in form_buttons:
                        try:
                            await button.scroll_into_view_if_needed()
                            await asyncio.sleep(0.3)
                            
                            if await button.is_visible():
                                button_text = (await button.text_content() or "").strip()
                                print(f"   🔘 Form button: '{button_text}'")
                                if not submit_button and button_text:
                                    submit_button = button
                        except Exception:
                            continue

            # Click the found button
            if submit_button:
                try:
                    await submit_button.scroll_into_view_if_needed()
                    await asyncio.sleep(0.3)
                    await submit_button.click()
                    submit_success = True
                    print("   ✅ Clicked legacy submit button")
                except Exception as e:
                    print(f"   ⚠️ Click failed: {e}")
                    try:
                        await submit_button.evaluate("el => el.click()")
                        submit_success = True
                        print("   ✅ Clicked via JS")
                    except Exception:
                        pass
        
        if not submit_success:
            # Final fallback: Press Enter
            print("   🔄 Final fallback: Pressing Enter key...")
            await page.keyboard.press('Enter')
            submit_success = True
            print("   ✅ Pressed Enter key")
        
        if not submit_success:
            print("   ❌ All button detection strategies failed")
            
            # DEBUG: Log all buttons for analysis
            print("   🐛 DEBUG: Listing ALL buttons...")
            all_buttons = await page.query_selector_all('button, [role="button"]')
            print(f"   📊 Total buttons found: {len(all_buttons)}")
            
            for i, btn in enumerate(all_buttons[:MAX_DEBUG_BUTTONS]):  # Limit to first 10
                try:
                    await btn.scroll_into_view_if_needed()
                    await asyncio.sleep(0.1)
                    
                    is_visible = await btn.is_visible()
                    is_enabled = await btn.is_enabled()
                    btn_text = (await btn.text_content() or "").strip()[:50]
                    
                    print(f"   🔘 Button {i}: visible={is_visible}, enabled={is_enabled}, text='{btn_text}'")
                        
                except Exception as e:
                    print(f"   🔘 Button {i}: error - {e}")
            
            try:
                await page.screenshot(path="./debug_no_button_found.png")
            except Exception as e:
                print("   ⚠️ Screenshot skipped: %s", e)
            
            return False

        # ========== SUCCESS DETECTION ==========
        print("   ⏳ Waiting for result...")

        final_status_determined = False
        original_url = page.url.lower()

        for wait_time in [5, 8, 12]:
            await asyncio.sleep(wait_time)
            
            current_url = page.url.lower()
            page_title = (await page.title()).lower()
            
            print(f"   🔗 After {wait_time}s: {current_url}")
            print(f"   📄 Page title: {page_title}")
            
            # Check for OTP requirement
            self.status = 2
            final_status_determined = True

        if not final_status_determined:
            print("   📱 Assuming OTP verification required")
            self.status = 2

        try:
            await page.screenshot(path="./debug_final_result.png", timeout=5000)
            print("   📸 Final result screenshot saved")
        except Exception as e:
            print("   ⚠️ Screenshot skipped: %s", e)
        
        print("   ✅ Version 1 form submitted successfully, OTP verification required")
        
        return True

    async def _process_version_2(self, page, email: str, password: str, full_name: str, username: str,
                           birth_year: int, birth_month: int, birth_day: int) -> bool:
        """Process Version 2: Basic fields first, then birthday in next step with enhanced dynamic detection"""
        print("   📝 Processing Version 2 form...")
        
        try:
            # Step 1: Fill basic fields only with enhanced detection
            print("   🔄 Step 1: Filling basic fields with enhanced detection...")
            
            field_mapping = {}
            
            # ========== ENHANCED: Use dynamic detection first ==========
            print("   🔍 Using enhanced dynamic form field detection...")
            
            detected_fields = await self._detect_form_fields_dynamically(page)
            
            # Map detected fields to our internal naming
            field_name_mapping = {
                'email': 'email_field',
                'password': 'password_field',
                'fullname': 'name_field',
                'username': 'username_field'
            }
            
            for detected_type, internal_name in field_name_mapping.items():
                if detected_type in detected_fields:
                    field_mapping[internal_name] = detected_fields[detected_type]
                    print(f"   ✅ {internal_name} detected via dynamic detection")
            
            print(f"   📊 Dynamic detection found {len(field_mapping)} fields (confidence: {detected_fields.get('confidence', 0):.1%})")
            
            # ========== Fallback to selector-based detection ==========
            field_selectors = {
                'email_field': [
                    'input[name="emailOrPhone"]',
                    'input[type="email"]',
                    'input[aria-label*="email" i]'
                ],
                'password_field': [
                    'input[type="password"]',
                    'input[name*="password" i]',
                    'input[aria-label*="password" i]'
                ],
                'name_field': [
                    'input[name="fullName"]',
                    'input[aria-label*="full name" i]'
                ],
                'username_field': [
                    'input[name="username"]',
                    'input[aria-label*="username" i]'
                ]
            }
            
            # Find and fill basic fields (only for missing ones)
            for field_type, selectors in field_selectors.items():
                if field_type not in field_mapping:  # Only search for missing fields
                    for selector in selectors:
                        element = await page.query_selector(selector)
                        if element and await element.is_visible():
                            field_mapping[field_type] = element
                            print(f"   ✅ {field_type} found: {selector}")
                            break
            
            # Fill fields
            if 'email_field' in field_mapping:
                await field_mapping['email_field'].click()
                await asyncio.sleep(0.3)
                await field_mapping['email_field'].fill("")
                await asyncio.sleep(0.2)
                await field_mapping['email_field'].type(email, delay=50)
                await asyncio.sleep(1)
                print("   📧 Email filled")
            
            if 'password_field' in field_mapping:
                await field_mapping['password_field'].click()
                await asyncio.sleep(0.3)
                await field_mapping['password_field'].fill("")
                await asyncio.sleep(0.2)
                await field_mapping['password_field'].type(password, delay=50)
                await asyncio.sleep(1)
                print("   🔐 Password filled")
            
            if 'name_field' in field_mapping:
                await field_mapping['name_field'].click()
                await asyncio.sleep(0.3)
                await field_mapping['name_field'].fill("")
                await asyncio.sleep(0.2)
                await field_mapping['name_field'].type(full_name, delay=50)
                await asyncio.sleep(1)
                print("   👨‍💼 Full name filled")
            
            if 'username_field' in field_mapping:
                await field_mapping['username_field'].click()
                await asyncio.sleep(0.3)
                await field_mapping['username_field'].fill("")
                await asyncio.sleep(0.2)
                await field_mapping['username_field'].type(username, delay=50)
                await asyncio.sleep(1)
                print("   👤 Username filled")
            
            try:
                await page.screenshot(path="./debug_final_result.png", timeout=5000)
            except Exception as e:
                print("   ⚠️ Screenshot skipped: %s", e)
            
            # ========== ENHANCED: Scroll and click Sign up button ==========
            print("   🔄 Looking for Sign up button (with scroll support)...")
            
            # First scroll to make sure button is visible
            await self._scroll_page_to_bottom(page)
            await asyncio.sleep(0.5)
            
            # Use enhanced button detection
            signup_success = await self._detect_and_click_submit_button(page, "signup")
            
            if not signup_success:
                # Fallback to legacy method
                print("   🔄 Fallback: Legacy button detection...")
                signup_success = await self._click_button_by_text(page, ["sign up", "daftar", "next", "lanjut"])
            
            if not signup_success:
                logger.error("   ❌ Could not find/click Sign up button")
                try:
                    await page.screenshot(path="./debug_signup_button_not_found.png")
                except Exception:
                    pass
                return False
            
            print("   ✅ Sign up button clicked, waiting for birthday step...")
            print("   ⏳ Waiting for birthday page to fully load...")
            await asyncio.sleep(5)

            # Step 2: Fill birthday in second step with enhanced detection
            print("   🔄 Step 2: Filling birthday with enhanced detection...")
            try:
                await page.screenshot(path="./debug_birthday_step.png")
            except Exception as e:
                print("   ⚠️ Screenshot skipped: %s", e)
            
            # Fill birthday using enhanced v3 method
            birthday_filled = await self._fill_birthday_fields_v3(page, birth_year, birth_month, birth_day, "version_2")
            
            if not birthday_filled:
                # Fallback to original method
                print("   🔄 Trying legacy birthday fill method...")
                birthday_filled = await self._fill_birthday_fields(page, birth_year, birth_month, birth_day)
            
            if not birthday_filled:
                logger.error("   ❌ Could not fill birthday in step 2")
                return False
            
            # ========== ENHANCED BUTTON DETECTION with scroll support ==========
            print("   🔄 Looking for Continue/Next button after birthday (with scroll)...")
            
            # Scroll to ensure button is visible
            await self._scroll_page_to_bottom(page)
            await asyncio.sleep(0.5)
            
            # Take screenshot before looking for button
            try:
                await page.screenshot(path="./debug_before_continue_button.png")
            except Exception as e:
                print("   ⚠️ Screenshot skipped: %s", e)
            
            # Use enhanced button detection for birthday step
            continue_success = await self._detect_and_click_submit_button(page, "birthday")
            
            # Fallback Strategy: If enhanced detection fails, try legacy methods
            if not continue_success:
                print("   🔄 Fallback: Legacy button detection with scroll...")
                
                # Scroll page to bottom first
                await self._scroll_page_to_bottom(page)
                await asyncio.sleep(0.5)
                
                # Try clicking any visible action button
                continue_success = await self._click_button_by_text_with_scroll(page, [
                    "next", "continue", "lanjut", "lanjutkan", "berikutnya", 
                    "sign up", "daftar", "submit", "done", "selesai"
                ])
            
            # Final fallback: Press Enter key
            if not continue_success:
                print("   🔄 Final fallback: Pressing Enter key...")
                await page.keyboard.press('Enter')
                print("   ✅ Pressed Enter key")
                continue_success = True
            
            if not continue_success:
                logger.error("   ❌ Could not find/click Continue/Next button after birthday")
                try:
                    await page.screenshot(path="./debug_no_continue_button.png")
                except Exception as e:
                    print("   ⚠️ Screenshot skipped: %s", e)
                
                # Debug: List all available buttons with details
                print("   🐛 DEBUG: All buttons on birthday page:")
                all_buttons = await page.query_selector_all('button, [role="button"]')
                for i, btn in enumerate(all_buttons[:MAX_DEBUG_BUTTONS]):  # Limit to first 10 buttons
                    try:
                        is_visible = await btn.is_visible()
                        is_enabled = await btn.is_enabled()
                        btn_text = (await btn.text_content() or "").strip()[:50]  # Truncate long text
                        btn_type = await btn.get_attribute('type') or ""
                        
                        print(f"   🔘 {i}: visible={is_visible}, enabled={is_enabled}, type='{btn_type}', text='{btn_text}'")
                                
                    except Exception as e:
                        print(f"   🔘 {i}: error - {e}")
                
                return False
            
            print("   ✅ Continue/Next button clicked, waiting for result...")
            await asyncio.sleep(5)
            
            # Check result
            current_url = page.url.lower()
            current_title = (await page.title()).lower()
            
            print(f"   🔗 After birthday URL: {current_url}")
            print(f"   📄 After birthday title: {current_title}")
            
            try:
                await page.screenshot(path="./debug_after_birthday_submit.png")
            except Exception as e:
                print("   ⚠️ Screenshot skipped: %s", e)
            
            self.status = 2
            final_status_determined = True
            print("   ✅ Version 2 form submitted successfully, OTP verification required")
            
            return True
            
        except Exception as e:
            logger.error(f"   ❌ Version 2 processing failed: {e}")
            try:
                await page.screenshot(path="./debug_version_2_error.png")
            except Exception as e:
                print("   ⚠️ Screenshot skipped: %s", e)
            self.status = 4
            return False

    async def _process_form_dynamically(self, page, email: str, password: str, full_name: str, username: str,
                                        birth_year: int, birth_month: int, birth_day: int) -> bool:
        """
        Fully dynamic form processing that adapts to any form structure.
        
        This method:
        1. Detects all visible form fields on the current page
        2. Identifies field types based on attributes (placeholder, aria-label, name, type)
        3. Fills detected fields with appropriate values
        4. Clicks the submit/next button
        5. Waits for page changes and repeats until reaching OTP page
        
        Supports any form flow:
        - Single page with all fields
        - Multi-step with fields appearing after each submit
        - Username appearing on second submission
        - Birthday on separate page
        - Any random combination of fields
        """
        print("   🔄 Starting FULLY DYNAMIC form processing...")
        print("   📝 Will check for ALL field types on EVERY page")
        
        max_steps = MAX_FORM_STEPS  # Use constant for max form steps
        current_step = 0
        fields_filled_total = set()  # Track which field types have been filled
        
        # Data mapping for field types
        field_values = {
            'email': email,
            'password': password,
            'fullname': full_name,
            'username': username,
            'month': birth_month,
            'day': birth_day,
            'year': birth_year
        }
        
        while current_step < max_steps:
            current_step += 1
            print(f"\n   ═══════════════════════════════════════")
            print(f"   📋 DYNAMIC STEP {current_step}/{max_steps}")
            print(f"   ═══════════════════════════════════════")
            
            try:
                await page.screenshot(path=f"./debug_dynamic_step_{current_step}.png")
            except Exception:
                pass
            
            # Wait for page to stabilize (longer wait after first step)
            wait_time = 2 if current_step == 1 else 4
            await asyncio.sleep(wait_time)
            
            # ========== CHECK IF WE'RE ON OTP PAGE ==========
            if await self._is_otp_page(page):
                print("   🎉 Reached OTP/Confirmation page!")
                self.status = 2
                return True
            
            # ========== CHECK FOR ERROR MESSAGES ==========
            error_detected = await self._check_for_form_errors(page)
            if error_detected:
                print(f"   ⚠️ Form error detected: {error_detected}")
                # Continue anyway, might be able to fix with more fields
            
            # ========== COMPREHENSIVE FIELD DETECTION ==========
            # Check for ALL possible field types on this page
            print("   🔍 Comprehensive scan: checking for ALL field types...")
            
            detected_fields = {}
            has_birthday = False
            
            # 1. Check for standard input fields (email, password, fullname, username)
            standard_fields = await self._detect_all_form_fields(page)
            detected_fields.update(standard_fields)
            
            # 2. Always check for birthday fields (select/combobox)
            birthday_fields = await self._detect_birthday_fields_comprehensive(page)
            if birthday_fields:
                detected_fields.update(birthday_fields)
                has_birthday = True
            
            # 3. Print what we found
            print(f"   📊 Found {len(detected_fields)} fields on this page:")
            for field_type in ['email', 'password', 'fullname', 'username', 'month', 'day', 'year']:
                if field_type in detected_fields:
                    status = "✅ filled" if field_type in fields_filled_total else "⬚ to fill"
                    print(f"      ✓ {field_type}: {status}")
                else:
                    print(f"      ✗ {field_type}: not found")
            
            # ========== FILL ALL DETECTED UNFILLED FIELDS ==========
            fields_filled_this_step = 0
            
            # Fill standard fields first
            for field_type in ['email', 'password', 'fullname', 'username']:
                if field_type in detected_fields and field_type not in fields_filled_total:
                    value = field_values.get(field_type)
                    if value:
                        success = await self._fill_field_dynamically(page, detected_fields[field_type], field_type, value)
                        if success:
                            fields_filled_total.add(field_type)
                            fields_filled_this_step += 1
                            print(f"   ✅ Filled {field_type}")
                        else:
                            print(f"   ⚠️ Failed to fill {field_type}")
            
            # Fill birthday fields using specialized method if detected
            birthday_needed = any(f not in fields_filled_total for f in ['month', 'day', 'year'])
            if has_birthday and birthday_needed:
                print("   🎂 Filling birthday fields...")
                birthday_success = await self._fill_birthday_fields_v3(page, birth_year, birth_month, birth_day, "dynamic")
                if birthday_success:
                    fields_filled_total.add('month')
                    fields_filled_total.add('day')
                    fields_filled_total.add('year')
                    fields_filled_this_step += 3
                    print("   ✅ Birthday fields filled!")
            
            print(f"   📊 Total filled this step: {fields_filled_this_step}")
            
            # ========== CHECK IF WE SHOULD CONTINUE ==========
            # If we didn't fill anything and no fields detected, might be on OTP
            if fields_filled_this_step == 0 and len(detected_fields) == 0:
                print("   ⚠️ No fields found or filled, checking for OTP...")
                if await self._is_otp_page(page):
                    print("   🎉 Already on OTP page!")
                    self.status = 2
                    return True
            
            # ========== VERIFY ALL FIELDS ARE FILLED BEFORE SUBMIT ==========
            print("   🔍 Verifying all fields are filled before submit...")
            verification_result = await self._verify_all_fields_filled_before_submit(page, detected_fields, has_birthday)
            
            if not verification_result['all_filled']:
                print(f"   ⚠️ Some fields not filled properly: {verification_result['unfilled_fields']}")
                # Try to refill unfilled fields
                for field_type in verification_result['unfilled_fields']:
                    print(f"   🔄 Retrying to fill {field_type}...")
                    if field_type == 'email' and detected_fields.get('email'):
                        await self._fill_field_dynamically(detected_fields['email'], email, 'email')
                    elif field_type == 'password' and detected_fields.get('password'):
                        await self._fill_field_dynamically(detected_fields['password'], password, 'password')
                    elif field_type == 'username' and detected_fields.get('username'):
                        await self._fill_field_dynamically(detected_fields['username'], username, 'username')
                    elif field_type == 'fullname' and detected_fields.get('fullname'):
                        await self._fill_field_dynamically(detected_fields['fullname'], full_name, 'fullname')
                    elif field_type in ['month', 'day', 'year'] and has_birthday:
                        print(f"   🎂 Retrying birthday fill for {field_type}...")
                        await self._fill_birthday_fields_v3(page, birth_year, birth_month, birth_day, "retry")
                
                # Verify again after retry
                verification_result = await self._verify_all_fields_filled_before_submit(page, detected_fields, has_birthday)
                if verification_result['all_filled']:
                    print("   ✅ All fields now filled after retry!")
                else:
                    print(f"   ⚠️ Still unfilled after retry: {verification_result['unfilled_fields']}")
            else:
                print("   ✅ All fields verified as filled!")
            
            # ========== CLICK SUBMIT/NEXT BUTTON ==========
            print("   🔘 Looking for submit button...")
            
            # Scroll to reveal button
            await self._scroll_page_to_bottom(page)
            await asyncio.sleep(0.5)
            
            # Determine button type based on what fields we have
            if has_birthday:
                button_step = "birthday"
            else:
                button_step = "signup"
            
            button_clicked = await self._detect_and_click_submit_button(page, button_step)
            
            if not button_clicked:
                print("   ⚠️ No submit button found, trying Enter key...")
                await page.keyboard.press('Enter')
                await asyncio.sleep(1)
            
            # Wait for navigation or new fields to appear
            print("   ⏳ Waiting for page response...")
            await asyncio.sleep(3)
            
            # Check if page changed
            new_url = page.url
            print(f"   🔗 Current URL: {new_url}")
        
        print("   ❌ Max steps reached without completing form")
        return False
    
    async def _verify_all_fields_filled_before_submit(self, page, detected_fields: Dict, has_birthday: bool) -> Dict:
        """
        Verify that all detected form fields are properly filled before submitting.
        Returns a dict with 'all_filled' bool and 'unfilled_fields' list.
        """
        result = {
            'all_filled': True,
            'unfilled_fields': [],
            'field_values': {}
        }
        
        try:
            # Check standard input fields
            for field_type, element in detected_fields.items():
                if field_type in ['month', 'day', 'year']:
                    continue  # Check birthday fields separately
                
                if element is None:
                    continue
                
                try:
                    # Get current value
                    tag_name = await element.evaluate("el => el.tagName.toLowerCase()")
                    
                    if tag_name in ['input', 'textarea']:
                        value = await element.evaluate("el => el.value")
                    else:
                        value = await element.text_content() or ""
                    
                    result['field_values'][field_type] = value
                    
                    # Check if field is empty
                    if not value or not value.strip():
                        result['all_filled'] = False
                        result['unfilled_fields'].append(field_type)
                        print(f"      ⚠️ {field_type}: EMPTY")
                    else:
                        # Truncate for display
                        display_val = value[:20] + "..." if len(value) > 20 else value
                        print(f"      ✓ {field_type}: '{display_val}'")
                        
                except Exception as e:
                    print(f"      ⚠️ {field_type}: check failed - {str(e)[:50]}")
            
            # Check birthday fields if present
            if has_birthday:
                birthday_selectors = [
                    ('month', 'select[name*="month" i], select[aria-label*="month" i], [role="combobox"][aria-label*="month" i]'),
                    ('day', 'select[name*="day" i], select[aria-label*="day" i], [role="combobox"][aria-label*="day" i]'),
                    ('year', 'select[name*="year" i], select[aria-label*="year" i], [role="combobox"][aria-label*="year" i]')
                ]
                
                for field_type, selector in birthday_selectors:
                    try:
                        element = await page.query_selector(selector)
                        if element and await element.is_visible():
                            tag_name = await element.evaluate("el => el.tagName.toLowerCase()")
                            
                            if tag_name == 'select':
                                # For select elements, check selected option
                                selected_value = await element.evaluate("""
                                    el => {
                                        const opt = el.options[el.selectedIndex];
                                        return opt ? opt.value || opt.text : '';
                                    }
                                """)
                            else:
                                # For combobox, get text content
                                selected_value = await element.text_content() or ""
                            
                            result['field_values'][field_type] = selected_value
                            
                            # Check if a valid option is selected (not empty, not placeholder)
                            if not selected_value or selected_value.strip() == "" or selected_value == "0":
                                result['all_filled'] = False
                                result['unfilled_fields'].append(field_type)
                                print(f"      ⚠️ {field_type}: NOT SELECTED")
                            else:
                                print(f"      ✓ {field_type}: '{selected_value}'")
                                
                    except Exception as e:
                        print(f"      ⚠️ {field_type}: birthday check failed - {str(e)[:50]}")
            
            return result
            
        except Exception as e:
            print(f"   ⚠️ Field verification error: {e}")
            return result
    
    async def _detect_birthday_fields_comprehensive(self, page) -> Dict[str, Any]:
        """
        Comprehensively detect birthday fields (month, day, year) on the current page.
        Checks for select elements, comboboxes, and other birthday-related elements.
        Returns a dictionary with detected birthday fields.
        """
        birthday_fields = {}
        
        try:
            # Strategy 1: Look for select elements with birthday-related attributes
            select_elements = await page.query_selector_all('select')
            
            for select in select_elements:
                try:
                    if not await select.is_visible():
                        continue
                    
                    # Get attributes
                    name = await select.get_attribute('name') or ''
                    aria_label = await select.get_attribute('aria-label') or ''
                    title = await select.get_attribute('title') or ''
                    searchable = f"{name} {aria_label} {title}".lower()
                    
                    # Check for month
                    if any(p in searchable for p in BIRTHDAY_FIELD_PATTERNS.get('month', [])):
                        birthday_fields['month'] = select
                        continue
                    
                    # Check for day
                    if any(p in searchable for p in BIRTHDAY_FIELD_PATTERNS.get('day', [])):
                        birthday_fields['day'] = select
                        continue
                    
                    # Check for year
                    if any(p in searchable for p in BIRTHDAY_FIELD_PATTERNS.get('year', [])):
                        birthday_fields['year'] = select
                        continue
                    
                    # Analyze options to determine type
                    options = await select.query_selector_all('option')
                    option_values = []
                    for opt in options[:15]:  # Check first 15 options
                        try:
                            val = await opt.get_attribute('value')
                            if val and val.isdigit():
                                option_values.append(int(val))
                        except Exception:
                            continue
                    
                    if option_values:
                        min_val = min(option_values) if option_values else 0
                        max_val = max(option_values) if option_values else 0
                        count = len(option_values)
                        
                        # Month: 1-12 or 12 options
                        if (min_val == 1 and max_val == 12) or count == 12:
                            if 'month' not in birthday_fields:
                                birthday_fields['month'] = select
                        # Day: 1-31 or 28-31 options
                        elif (min_val == 1 and max_val >= 28 and max_val <= 31) or (count >= 28 and count <= 31):
                            if 'day' not in birthday_fields:
                                birthday_fields['day'] = select
                        # Year: 1900-2024 range
                        elif min_val >= 1900 and max_val <= 2025:
                            if 'year' not in birthday_fields:
                                birthday_fields['year'] = select
                                
                except Exception:
                    continue
            
            # Strategy 2: Look for combobox elements
            comboboxes = await page.query_selector_all('[role="combobox"], [role="listbox"]')
            
            for combo in comboboxes:
                try:
                    if not await combo.is_visible():
                        continue
                    
                    tag = await combo.evaluate("(el) => el.tagName.toLowerCase()")
                    if tag == 'input':  # Skip input elements
                        continue
                    
                    aria_label = await combo.get_attribute('aria-label') or ''
                    text = await combo.text_content() or ''
                    searchable = f"{aria_label} {text}".lower()
                    
                    for field_type, patterns in BIRTHDAY_FIELD_PATTERNS.items():
                        if field_type not in birthday_fields:
                            if any(p in searchable for p in patterns):
                                birthday_fields[field_type] = combo
                                break
                                
                except Exception:
                    continue
            
            if birthday_fields:
                print(f"   🎂 Found birthday fields: {list(birthday_fields.keys())}")
            
        except Exception as e:
            print(f"   ⚠️ Birthday field detection error: {e}")
        
        return birthday_fields

    async def _detect_all_form_fields(self, page) -> Dict[str, Any]:
        """
        Detect all visible form fields on the current page.
        Returns a dictionary mapping field types to their elements.
        """
        detected_fields = {}
        
        try:
            # Get all potential form elements
            all_elements = await page.query_selector_all(
                'input:not([type="hidden"]):not([type="submit"]):not([type="button"]), '
                'select, [role="combobox"], [role="listbox"]'
            )
            
            for element in all_elements:
                try:
                    # Check if visible
                    if not await element.is_visible():
                        continue
                    
                    bbox = await element.bounding_box()
                    if not bbox or bbox['width'] <= 0 or bbox['height'] <= 0:
                        continue
                    
                    # Get element attributes
                    attrs = await self._get_element_attributes(page, element)
                    
                    # Determine field type
                    field_type = await self._determine_field_type(attrs)
                    
                    if field_type and field_type not in detected_fields:
                        detected_fields[field_type] = element
                        
                except Exception:
                    continue
            
        except Exception as e:
            print(f"   ⚠️ Field detection error: {e}")
        
        return detected_fields
    
    async def _determine_field_type(self, attrs: Dict[str, Any]) -> Optional[str]:
        """
        Determine the field type based on element attributes.
        Uses FIELD_PATTERNS for multi-language support.
        Birthday fields (month, day, year) are ONLY detected for select elements, never for input.
        """
        # Combine all searchable text (excluding textContent which may contain unrelated text)
        searchable = ' '.join([
            attrs.get('placeholder', ''),
            attrs.get('ariaLabel', ''),
            attrs.get('name', ''),
            attrs.get('id', ''),
            attrs.get('autocomplete', '')
        ]).lower()
        
        input_type = attrs.get('type', '').lower()
        tag_name = attrs.get('tagName', '').lower()
        role = attrs.get('role', '').lower()
        
        # STRICT CHECK: Input elements should NEVER be detected as birthday fields
        is_input_element = tag_name == 'input'
        
        # Only select elements with proper role can be birthday fields
        is_select_element = tag_name == 'select'
        is_combobox = role in ['combobox', 'listbox'] and not is_input_element
        is_birthday_capable = is_select_element or is_combobox
        
        # Priority 1: Input type (strongest indicator)
        if input_type == 'password':
            return 'password'
        if input_type == 'email':
            return 'email'
        
        # Priority 2: Autocomplete attribute
        autocomplete = attrs.get('autocomplete', '').lower()
        autocomplete_map = {
            'email': 'email',
            'username': 'username',
            'new-password': 'password',
            'current-password': 'password',
            'name': 'fullname',
        }
        # Birthday autocomplete only for select/combobox elements
        birthday_autocomplete = {
            'bday-month': 'month',
            'bday-day': 'day',
            'bday-year': 'year'
        }
        
        if autocomplete in autocomplete_map:
            return autocomplete_map[autocomplete]
        
        if is_birthday_capable and autocomplete in birthday_autocomplete:
            return birthday_autocomplete[autocomplete]
        
        # Priority 3: Pattern matching for standard form fields
        for field_type, patterns in FIELD_PATTERNS.items():
            for pattern in patterns:
                if pattern.lower() in searchable:
                    return field_type
        
        # Priority 4: Birthday fields - STRICTLY for select/combobox elements ONLY
        if is_birthday_capable:
            for field_type, patterns in BIRTHDAY_FIELD_PATTERNS.items():
                for pattern in patterns:
                    if pattern.lower() in searchable:
                        return field_type
        
        # Priority 5: Fallback patterns for name/username (less strict)
        # Only check these if nothing else matched and it's a text input
        if is_input_element and input_type in ['text', '']:
            # Check for generic name patterns
            if 'name' in searchable and 'user' not in searchable:
                return 'fullname'
            if 'user' in searchable or 'nama pengguna' in searchable:
                return 'username'
        
        return None
    
    async def _fill_field_dynamically(self, page, element, field_type: str, value) -> bool:
        """
        Fill a form field dynamically based on its type.
        """
        try:
            tag_name = await element.evaluate("(el) => el.tagName.toLowerCase()")
            role = await element.get_attribute('role') or ''
            
            # Handle birthday fields (select/combobox)
            if field_type in ['month', 'day', 'year']:
                return await self._fill_birthday_with_smart_selection(page, element, value, field_type)
            
            # Handle text input fields
            if tag_name == 'input':
                await element.click()
                await asyncio.sleep(0.3)
                await element.fill("")
                await asyncio.sleep(0.2)
                
                value_str = str(value)
                
                # Use slow typing only for short values (like username)
                # Use faster fill for longer values (like email, password)
                if len(value_str) <= SLOW_TYPING_THRESHOLD:
                    # Type with human-like delay for short values
                    for char in value_str:
                        await element.type(char, delay=random.randint(30, 80))
                        await asyncio.sleep(random.uniform(0.02, 0.05))
                else:
                    # Use faster typing for longer values
                    await element.type(value_str, delay=30)
                
                await asyncio.sleep(0.5)
                return True
            
            # Handle select elements
            if tag_name == 'select':
                try:
                    await element.select_option(value=str(value))
                    return True
                except Exception:
                    try:
                        await element.select_option(label=str(value))
                        return True
                    except Exception:
                        pass
            
            # Handle combobox
            if role == 'combobox':
                await element.click()
                await asyncio.sleep(0.5)
                await element.fill(str(value))
                await asyncio.sleep(0.3)
                await element.press('Enter')
                return True
            
            return False
            
        except Exception as e:
            print(f"   ⚠️ Error filling {field_type}: {e}")
            return False
    
    async def _is_otp_page(self, page) -> bool:
        """
        Check if we're on the OTP/confirmation code page.
        """
        try:
            # Check for OTP input fields
            otp_selectors = [
                'input[placeholder*="confirmation" i]',
                'input[placeholder*="code" i]',
                'input[aria-label*="confirmation" i]',
                'input[aria-label*="code" i]',
                'input[name*="code" i]',
                'input[placeholder*="kode" i]',
                'input[placeholder*="verification" i]'
            ]
            
            for selector in otp_selectors:
                element = await page.query_selector(selector)
                if element and await element.is_visible():
                    return True
            
            # Check page text content
            page_text = await page.evaluate("() => document.body.innerText.toLowerCase()")
            otp_indicators = [
                'confirmation code', 'verification code', 'enter the code',
                'enter code', 'we sent', 'check your email',
                'kode konfirmasi', 'masukkan kode',
                'código de confirmación'
            ]
            
            for indicator in otp_indicators:
                if indicator in page_text:
                    return True
            
            return False
            
        except Exception:
            return False
    
    async def _check_for_form_errors(self, page) -> Optional[str]:
        """
        Check for form validation errors on the page.
        Excludes false positives from birthday field labels.
        """
        try:
            # Words to skip - these are not errors, just field labels
            skip_words = [
                'month', 'day', 'year', 'january', 'february', 'march', 'april',
                'may', 'june', 'july', 'august', 'september', 'october', 'november', 'december',
                'bulan', 'hari', 'tahun', 'januari', 'februari', 'maret', 'april', 'mei', 'juni',
                'juli', 'agustus', 'september', 'oktober', 'november', 'desember',
                'select', 'choose', 'pilih', 'birthday', 'password', 'username', 'email',
                'full name', 'nama lengkap'
            ]
            
            error_selectors = [
                '[aria-invalid="true"]',
                '[class*="error"]',
                '[class*="invalid"]',
                '[role="alert"]'
            ]
            
            for selector in error_selectors:
                elements = await page.query_selector_all(selector)
                for element in elements:
                    if await element.is_visible():
                        text = await element.text_content()
                        if text and text.strip():
                            text_lower = text.strip().lower()
                            
                            # Skip if text is just a field label or month name
                            is_label = any(skip_word in text_lower for skip_word in skip_words)
                            
                            # Also skip if it's just a short word (likely a label)
                            if len(text.strip()) < 20 and is_label:
                                continue
                            
                            # Skip if text matches pattern like "MonthJanuary" (combobox display)
                            if re.match(r'^(Month|Day|Year|Bulan|Hari|Tahun)', text.strip()):
                                continue
                            
                            return text.strip()[:MAX_ERROR_LENGTH]
            
            return None
            
        except Exception:
            return None

    async def _detect_birthday_page(self, page) -> bool:
        """
        Detect if the current page is a birthday entry page.
        Checks for birthday-related text and select/combobox elements.
        """
        try:
            # Check for birthday text on page
            page_text = await page.evaluate("() => document.body.innerText.toLowerCase()")
            birthday_indicators = [
                'birthday', 'date of birth', 'tanggal lahir', 'fecha de nacimiento',
                'date de naissance', 'geburtsdatum', 'add your birthday',
                'enter your birthday', 'when were you born'
            ]
            
            has_birthday_text = any(indicator in page_text for indicator in birthday_indicators)
            
            if not has_birthday_text:
                return False
            
            # Check for select elements or comboboxes (birthday dropdowns)
            birthday_selectors = [
                'select[name*="birthday" i]',
                'select[name*="month" i]',
                'select[name*="day" i]',
                'select[name*="year" i]',
                'select[aria-label*="month" i]',
                'select[aria-label*="day" i]',
                'select[aria-label*="year" i]',
                'select[title*="month" i]',
                'select[title*="day" i]',
                'select[title*="year" i]',
                '[role="combobox"]',
                '[role="listbox"]',
                'select'  # Fallback: any select element
            ]
            
            for selector in birthday_selectors:
                elements = await page.query_selector_all(selector)
                visible_count = 0
                for element in elements:
                    try:
                        if await element.is_visible():
                            visible_count += 1
                    except Exception:
                        continue
                
                # If we found visible select elements, likely birthday page
                if visible_count >= 1:
                    print(f"   🎂 Found {visible_count} visible select/combobox elements")
                    return True
            
            return False
            
        except Exception as e:
            print(f"   ⚠️ Birthday page detection error: {e}")
            return False

    async def _fill_birthday_fields_v3(self, page, birth_year: int, birth_month: int, birth_day: int, form_version: str = "version_3") -> bool:
        """Enhanced birthday filling untuk Version 3 dengan dynamic detection"""
        
        print(f"   🎂 Birthday filling for {form_version}...")
        print(f"   📅 Target date: {birth_year}-{birth_month:02d}-{birth_day:02d}")
        
        try:
            # ========== STRATEGY 0: ENHANCED DYNAMIC FORM FIELD DETECTION ==========
            print("   🔄 Strategy 0: Enhanced dynamic field detection using FIELD_PATTERNS...")
            
            detected_fields = await self._detect_form_fields_dynamically(page)
            
            if detected_fields.get('confidence', 0) > 0.3:
                birthday_detected = False
                
                # Fill month if detected
                if 'month' in detected_fields:
                    success = await self._fill_birthday_with_smart_selection(page, detected_fields['month'], birth_month, 'month')
                    if success:
                        birthday_detected = True
                    await asyncio.sleep(0.5)
                
                # Fill day if detected
                if 'day' in detected_fields:
                    success = await self._fill_birthday_with_smart_selection(page, detected_fields['day'], birth_day, 'day')
                    if success:
                        birthday_detected = True
                    await asyncio.sleep(0.5)
                
                # Fill year if detected
                if 'year' in detected_fields:
                    success = await self._fill_birthday_with_smart_selection(page, detected_fields['year'], birth_year, 'year')
                    if success:
                        birthday_detected = True
                
                if birthday_detected:
                    print(f"   ✅ Birthday filled via enhanced dynamic detection (confidence: {detected_fields['confidence']:.1%})")
                    return True
            
            # ========== STRATEGY 1: LEGACY DYNAMIC BIRTHDAY FIELD DETECTION ==========
            print("   🔄 Strategy 1: Legacy dynamic field detection...")
            
            # Cari semua elemen yang mungkin birthday-related
            all_possible_selectors = await page.query_selector_all('select, input, [role="combobox"], [aria-haspopup="listbox"]')
            print(f"   📍 Found {len(all_possible_selectors)} possible birthday elements")
            
            # Analisa elements untuk identifikasi birthday fields
            birthday_fields = await self._identify_birthday_fields(page, all_possible_selectors)
            
            if len(birthday_fields) >= 3:
                print(f"   ✅ Identified {len(birthday_fields)} birthday fields")
                return await self._fill_identified_birthday_fields(page, birthday_fields, birth_year, birth_month, birth_day)
            
            # ========== STRATEGY 2: BIRTHDAY SECTION DETECTION ==========
            print("   🔄 Strategy 2: Birthday section detection...")
            
            birthday_section = await self._detect_birthday_section(page)
            if birthday_section:
                section_fields = await birthday_section.query_selector_all('select, input, [role="combobox"]')
                if len(section_fields) >= 3:
                    success = await self._fill_birthday_fields_in_section(section_fields, birth_year, birth_month, birth_day)
                    if success:
                        return True
            
            # ========== STRATEGY 3: SMART COMBOBOX DETECTION ==========
            print("   🔄 Strategy 3: Smart combobox detection...")
            
            # Cari comboboxes dengan pattern tertentu
            comboboxes = await page.query_selector_all('[role="combobox"], [aria-haspopup="listbox"]')
            
            if len(comboboxes) >= 3:
                print(f"   📍 Found {len(comboboxes)} comboboxes, attempting smart fill...")
                
                # Coba identifikasi urutan fields (year, month, day)
                identified_order = await self._identify_birthday_field_order(comboboxes)
                
                if identified_order:
                    return await self._fill_birthday_by_order(comboboxes, identified_order, birth_year, birth_month, birth_day)
                else:
                    # Fallback: coba isi secara sequential
                    return await self._fill_comboboxes_sequential(comboboxes, birth_year, birth_month, birth_day)
            
            # ========== STRATEGY 4: PLACEHOLDER-BASED DETECTION (ENHANCED) ==========
            print("   🔄 Strategy 4: Enhanced placeholder-based detection...")
            
            # Build comprehensive placeholder selectors from FIELD_PATTERNS
            month_patterns = FIELD_PATTERNS.get('month', [])
            day_patterns = FIELD_PATTERNS.get('day', [])
            year_patterns = FIELD_PATTERNS.get('year', [])
            
            month_selectors = ', '.join([f'input[placeholder*="{p}" i], [aria-label*="{p}" i]' for p in month_patterns])
            day_selectors = ', '.join([f'input[placeholder*="{p}" i], [aria-label*="{p}" i]' for p in day_patterns])
            year_selectors = ', '.join([f'input[placeholder*="{p}" i], [aria-label*="{p}" i]' for p in year_patterns])
            
            month_field = await page.query_selector(month_selectors)
            day_field = await page.query_selector(day_selectors)
            year_field = await page.query_selector(year_selectors)
            
            if month_field and day_field and year_field:
                print("   📍 Found all birthday fields via placeholder patterns")
                success_count = 0
                
                if await self._fill_birthday_with_smart_selection(page, month_field, birth_month, 'month'):
                    success_count += 1
                await asyncio.sleep(0.3)
                
                if await self._fill_birthday_with_smart_selection(page, day_field, birth_day, 'day'):
                    success_count += 1
                await asyncio.sleep(0.3)
                
                if await self._fill_birthday_with_smart_selection(page, year_field, birth_year, 'year'):
                    success_count += 1
                
                if success_count >= 2:
                    print(f"   ✅ Birthday filled via placeholder patterns ({success_count}/3)")
                    return True
            
            # ========== STRATEGY 5: VISUAL POSITION-BASED DETECTION ==========
            print("   🔄 Strategy 5: Visual position-based detection...")
            
            # Cari semua select elements dan urutkan berdasarkan posisi
            all_selects = await page.query_selector_all('select')
            if len(all_selects) >= 3:
                print(f"   📍 Found {len(all_selects)} select elements, trying position-based...")
                
                # Urutkan berdasarkan posisi X (left to right)
                positioned_selects = []
                for select in all_selects:
                    try:
                        box = await select.bounding_box()
                        if box:
                            positioned_selects.append((box['x'], select))
                    except Exception:
                        continue
                
                positioned_selects.sort(key=lambda x: x[0])
                
                if len(positioned_selects) >= 3:
                    # Asumsikan urutan: month, day, year (format US)
                    try:
                        # Month (first select)
                        await self._fill_birthday_with_smart_selection(page, positioned_selects[0][1], birth_month, 'month')
                        await asyncio.sleep(0.3)
                        # Day (second select)  
                        await self._fill_birthday_with_smart_selection(page, positioned_selects[1][1], birth_day, 'day')
                        await asyncio.sleep(0.3)
                        # Year (third select)
                        await self._fill_birthday_with_smart_selection(page, positioned_selects[2][1], birth_year, 'year')
                        
                        print("   ✅ Birthday filled with position-based strategy")
                        return True
                    except Exception as e:
                        print(f"   ⚠️ Position-based strategy failed: {e}")
            
            # ========== STRATEGY 6: FALLBACK MECHANISM ==========
            print("   🔄 Strategy 6: Fallback mechanism...")
            
            result = await self._fill_birthday_with_fallback(page, birth_year, birth_month, birth_day)
            if result:
                print("   ✅ Birthday filled via fallback mechanism")
                return True
            
            print("   ❌ All birthday filling strategies failed")
            return False
            
        except Exception as e:
            print(f"   ❌ Birthday filling error: {e}")
            import traceback
            traceback.print_exc()
            return False

    async def _identify_birthday_fields(self, page, elements) -> list:
        """Identify which elements are birthday fields"""
        birthday_fields = []
        
        for element in elements:
            try:
                # Check berbagai attribute untuk identifikasi birthday field
                element_html = await page.evaluate("(element) => element.outerHTML", element)
                element_text = await element.text_content() or ""
                
                # Check untuk indicators
                indicators = [
                    'year', 'month', 'day', 'birthday', 'birth', 'date',
                    'yyyy', 'mm', 'dd', 'anno', 'mes', 'dia', 'tahun', 'bulan', 'hari'
                ]
                
                for indicator in indicators:
                    if (indicator in element_html.lower() or 
                        indicator in element_text.lower()):
                        birthday_fields.append(element)
                        break
                        
            except Exception:
                continue
        
        return birthday_fields

    async def _fill_identified_birthday_fields(self, page, fields, year, month, day) -> bool:
        """Fill identified birthday fields dengan smart matching"""
        
        # Coba identifikasi field types
        field_types = {}
        
        for field in fields:
            try:
                html = await page.evaluate("(element) => element.outerHTML", field)
                text = await field.text_content() or ""
                
                # Determine field type
                if any(indicator in html.lower() or indicator in text.lower() 
                    for indicator in ['year', 'yyyy', 'tahun', 'anno']):
                    field_types['year'] = field
                elif any(indicator in html.lower() or indicator in text.lower()
                        for indicator in ['month', 'mm', 'bulan', 'mes']):
                    field_types['month'] = field
                elif any(indicator in html.lower() or indicator in text.lower()
                        for indicator in ['day', 'dd', 'hari', 'dia']):
                    field_types['day'] = field
                    
            except Exception:
                continue
        
        # Fill fields berdasarkan type
        success_count = 0
        
        if 'year' in field_types:
            try:
                await self._fill_birthday_field(field_types['year'], year, 'year')
                success_count += 1
            except Exception:
                pass
        
        if 'month' in field_types:
            try:
                await self._fill_birthday_field(field_types['month'], month, 'month')
                success_count += 1
            except Exception:
                pass
        
        if 'day' in field_types:
            try:
                await self._fill_birthday_field(field_types['day'], day, 'day')
                success_count += 1
            except Exception:
                pass
        
        return success_count >= 2  # Minimal 2/3 fields terisi

    async def _fill_birthday_field(self, field, value, field_type: str) -> bool:
        """Fill individual birthday field dengan multiple strategies"""
        try:
            tag_name = await field.evaluate("(element) => element.tagName.toLowerCase()")
            
            if tag_name == 'select':
                # Try multiple value formats
                value_formats = [str(value), str(value).zfill(2)]
                
                for val in value_formats:
                    try:
                        await field.select_option(value=val)
                        print(f"   ✅ {field_type} selected: {value}")
                        return True
                    except Exception:
                        continue
            
            elif tag_name == 'input':
                await field.click()
                await asyncio.sleep(0.3)
                await field.fill("")
                await asyncio.sleep(0.2)
                
                value_str = str(value) if field_type == 'year' else str(value).zfill(2)
                for char in value_str:
                    await field.type(char, delay=100)
                    await asyncio.sleep(0.05)
                
                print(f"   ✅ {field_type} input filled: {value}")
                return True
            
            # Handle combobox - use click + select option approach (combobox elements don't support .fill())
            role = await field.get_attribute('role')
            if role == 'combobox' or role == 'listbox':
                await field.click()
                await asyncio.sleep(0.8)
                
                # Build search values based on field type
                value_str = str(value) if field_type == 'year' else str(value).zfill(2)
                search_values = [value_str, str(value)]
                
                # For month, also try month names
                if field_type == 'month':
                    month_int = int(value)
                    if 1 <= month_int <= 12:
                        for months in MONTH_NAMES.values():
                            search_values.append(months[month_int - 1])
                
                # Try to find and click the matching option
                from playwright.async_api import Page
                for search_val in search_values:
                    option_selectors = [
                        f'[role="option"]:has-text("{search_val}")',
                        f'li:has-text("{search_val}")',
                        f'div[role="option"]:has-text("{search_val}")',
                        f'span:has-text("{search_val}")'
                    ]
                    
                    for selector in option_selectors:
                        try:
                            # Use page to find option (combobox opens dropdown in page context)
                            option = await field.page.query_selector(selector)
                            if option and await option.is_visible():
                                await option.click()
                                print(f"   ✅ {field_type} combobox option clicked: {search_val}")
                                await asyncio.sleep(0.3)
                                return True
                        except Exception:
                            continue
                
                # Fallback: use keyboard navigation for combobox
                try:
                    await field.press('ArrowDown')
                    await asyncio.sleep(0.2)
                    # Type to filter options if combobox supports it
                    await field.press('Enter')
                    await asyncio.sleep(0.3)
                    print(f"   ✅ {field_type} combobox selected via keyboard")
                    return True
                except Exception:
                    pass
                
                print(f"   ⚠️ Combobox {field_type} selection failed, trying alternatives...")
                return False
                
        except Exception as e:
            print(f"   ❌ Failed to fill {field_type}: {e}")
        
        return False

    async def _detect_form_fields_dynamically(self, page) -> Dict[str, Any]:
        """
        Dynamic form field detection berdasarkan placeholder, aria-label, name attribute.
        Supports multiple languages and various form structures.
        
        Returns:
            Dict containing detected fields: {
                'email': element,
                'password': element,
                'fullname': element,
                'username': element,
                'month': element,
                'day': element,
                'year': element,
                'detection_method': str,
                'confidence': float
            }
        """
        print("   🔍 Starting dynamic form field detection...")
        
        detected_fields = {
            'detection_method': 'dynamic',
            'confidence': 0.0,
            'debug_info': []
        }
        
        try:
            # ========== STEP 1: Scan all visible form elements ==========
            all_elements = await page.query_selector_all(
                'input:not([type="hidden"]):not([type="submit"]):not([type="button"]), '
                'select, [role="combobox"], [role="listbox"]'
            )
            
            visible_elements = []
            for element in all_elements:
                try:
                    if await element.is_visible():
                        bbox = await element.bounding_box()
                        if bbox and bbox['width'] > 0 and bbox['height'] > 0:
                            # Collect element attributes
                            attrs = await self._get_element_attributes(page, element)
                            attrs['element'] = element
                            attrs['bbox'] = bbox
                            visible_elements.append(attrs)
                except Exception:
                    continue
            
            print(f"   📊 Found {len(visible_elements)} visible form elements")
            detected_fields['debug_info'].append(f"Total visible elements: {len(visible_elements)}")
            
            # ========== STEP 2: Analyze each element ==========
            for elem_data in visible_elements:
                field_type = await self._analyze_element_for_field_type(elem_data)
                
                if field_type and field_type not in detected_fields:
                    detected_fields[field_type] = elem_data['element']
                    method_used = elem_data.get('detection_method', 'attribute')
                    print(f"   ✅ Detected {field_type} field via {method_used}")
                    detected_fields['debug_info'].append(f"{field_type}: {method_used}")
            
            # ========== STEP 3: Calculate confidence ==========
            total_possible = 7  # email, password, fullname, username, month, day, year
            detected_count = len([k for k in detected_fields.keys() 
                                  if k in ['email', 'password', 'fullname', 'username', 'month', 'day', 'year']])
            detected_fields['confidence'] = detected_count / total_possible
            
            print(f"   📈 Detection confidence: {detected_fields['confidence']:.1%} ({detected_count}/{total_possible})")
            
            return detected_fields
            
        except Exception as e:
            print(f"   ❌ Dynamic detection error: {e}")
            detected_fields['error'] = str(e)
            return detected_fields
    
    async def _get_element_attributes(self, page, element) -> Dict[str, Any]:
        """Get all relevant attributes from an element for analysis"""
        try:
            attrs = await page.evaluate("""(element) => {
                return {
                    tagName: element.tagName.toLowerCase(),
                    type: element.type || '',
                    name: element.name || '',
                    id: element.id || '',
                    placeholder: element.placeholder || '',
                    ariaLabel: element.getAttribute('aria-label') || '',
                    role: element.getAttribute('role') || '',
                    autocomplete: element.getAttribute('autocomplete') || '',
                    className: element.className || '',
                    value: element.value || '',
                    textContent: element.textContent ? element.textContent.substring(0, 100) : ''
                };
            }""", element)
            return attrs
        except Exception:
            return {}
    
    async def _analyze_element_for_field_type(self, elem_data: Dict[str, Any]) -> Optional[str]:
        """
        Analyze element attributes to determine field type.
        Uses FIELD_PATTERNS for multi-language support.
        Birthday fields (month, day, year) are ONLY detected for select elements, never for input.
        """
        # Combine all searchable text (excluding textContent which may contain unrelated text)
        searchable_text = ' '.join([
            elem_data.get('placeholder', ''),
            elem_data.get('ariaLabel', ''),
            elem_data.get('name', ''),
            elem_data.get('id', ''),
            elem_data.get('autocomplete', '')
        ]).lower()
        
        input_type = elem_data.get('type', '').lower()
        tag_name = elem_data.get('tagName', '').lower()
        role = elem_data.get('role', '').lower() if elem_data.get('role') else ''
        
        # STRICT CHECK: Input elements should NEVER be detected as birthday fields
        is_input_element = tag_name == 'input'
        
        # Only select elements with proper role can be birthday fields
        is_select_element = tag_name == 'select'
        is_combobox = role in ['combobox', 'listbox'] and not is_input_element
        is_birthday_capable = is_select_element or is_combobox
        
        # ========== PRIORITY 1: Type-based detection ==========
        if input_type == 'password':
            elem_data['detection_method'] = 'type_attribute'
            return 'password'
        
        if input_type == 'email':
            elem_data['detection_method'] = 'type_attribute'
            return 'email'
        
        # ========== PRIORITY 2: Autocomplete-based detection ==========
        autocomplete = elem_data.get('autocomplete', '').lower()
        autocomplete_mapping = {
            'email': 'email',
            'username': 'username',
            'new-password': 'password',
            'current-password': 'password',
            'name': 'fullname',
        }
        # Birthday autocomplete only for select/combobox elements
        birthday_autocomplete = {
            'bday-month': 'month',
            'bday-day': 'day',
            'bday-year': 'year'
        }
        
        if autocomplete in autocomplete_mapping:
            elem_data['detection_method'] = 'autocomplete'
            return autocomplete_mapping[autocomplete]
        
        if is_birthday_capable and autocomplete in birthday_autocomplete:
            elem_data['detection_method'] = 'autocomplete:birthday'
            return birthday_autocomplete[autocomplete]
        
        # ========== PRIORITY 3: Pattern-based detection for standard fields ==========
        for field_type, patterns in FIELD_PATTERNS.items():
            for pattern in patterns:
                if pattern.lower() in searchable_text:
                    elem_data['detection_method'] = f'pattern:{pattern}'
                    return field_type
        
        # ========== PRIORITY 4: Birthday field pattern matching - STRICTLY for select/combobox ONLY ==========
        if is_birthday_capable:
            for field_type, patterns in BIRTHDAY_FIELD_PATTERNS.items():
                for pattern in patterns:
                    if pattern.lower() in searchable_text:
                        elem_data['detection_method'] = f'birthday_pattern:{pattern}'
                        return field_type
        
        # ========== PRIORITY 5: Select/combobox analysis for birthday by option values ==========
        if is_birthday_capable:
            # Analyze options for birthday field detection
            birthday_type = await self._analyze_select_for_birthday(elem_data)
            if birthday_type:
                elem_data['detection_method'] = 'options_range'
                return birthday_type
        
        # ========== PRIORITY 6: Fallback patterns for name/username (less strict) ==========
        if is_input_element and input_type in ['text', '']:
            if 'name' in searchable_text and 'user' not in searchable_text:
                elem_data['detection_method'] = 'fallback:name'
                return 'fullname'
            if 'user' in searchable_text or 'nama pengguna' in searchable_text:
                elem_data['detection_method'] = 'fallback:user'
                return 'username'
        
        return None
    
    async def _analyze_select_for_birthday(self, elem_data: Dict[str, Any]) -> Optional[str]:
        """
        Analyze select/combobox options to determine if it's a birthday field.
        Uses option value ranges to detect month (1-12), day (1-31), year (1900-2024).
        """
        try:
            element = elem_data.get('element')
            if not element:
                return None
            
            # Get options from select element
            options = await element.query_selector_all('option')
            option_values = []
            
            for option in options:
                try:
                    value = await option.get_attribute('value')
                    text = await option.text_content()
                    if value:
                        option_values.append(value)
                    if text:
                        option_values.append(text.strip())
                except Exception:
                    continue
            
            # Analyze value ranges
            numeric_values = []
            for val in option_values:
                try:
                    num = int(val)
                    numeric_values.append(num)
                except ValueError:
                    # Check for month names
                    stripped_val = val.strip()
                    for lang_months in MONTH_NAMES.values():
                        if stripped_val.title() in lang_months or stripped_val in lang_months:
                            return 'month'
            
            if not numeric_values:
                return None
            
            min_val = min(numeric_values)
            max_val = max(numeric_values)
            count = len(numeric_values)
            
            # Month detection: 1-12 range or 12 options
            if (min_val == 1 and max_val == 12) or count == 12:
                return 'month'
            
            # Day detection: 1-31 range or 28-31 options
            if min_val == 1 and 28 <= max_val <= 31:
                return 'day'
            
            # Year detection: years in past (typically 1900-current year)
            if min_val >= 1900 and max_val <= 2025 and count > 50:
                return 'year'
            
            return None
            
        except Exception:
            return None
    
    async def _detect_birthday_section(self, page) -> Optional[Any]:
        """
        Detect birthday section berdasarkan text content.
        Supports multiple languages.
        """
        birthday_keywords = [
            'birthday', 'date of birth', 'birth date', 'dob',
            'tanggal lahir', 'ulang tahun',
            'fecha de nacimiento', 'cumpleaños',
            'date de naissance', 'anniversaire',
            'geburtsdatum', 'geburtstag',
            'data di nascita', 'compleanno'
        ]
        
        try:
            # Find parent containers with birthday text
            for keyword in birthday_keywords:
                # Try different selector approaches
                selectors = [
                    f'div:has-text("{keyword}")',
                    f'section:has-text("{keyword}")',
                    f'fieldset:has-text("{keyword}")',
                    f'label:has-text("{keyword}")'
                ]
                
                for selector in selectors:
                    try:
                        section = await page.query_selector(selector)
                        if section:
                            print(f"   🎂 Found birthday section with keyword: {keyword}")
                            return section
                    except Exception:
                        continue
            
            return None
            
        except Exception as e:
            print(f"   ⚠️ Birthday section detection error: {e}")
            return None
    
    async def _fill_birthday_with_smart_selection(self, page, field, value, field_type: str) -> bool:
        """
        Smart field value selection for birthday fields.
        Handles month names, formats, and scrolling for long dropdowns.
        """
        try:
            tag_name = await field.evaluate("(element) => element.tagName.toLowerCase()")
            role = await field.get_attribute('role')
            
            # ========== SELECT ELEMENT HANDLING ==========
            if tag_name == 'select':
                return await self._fill_select_birthday_field(page, field, value, field_type)
            
            # ========== COMBOBOX HANDLING ==========
            if role == 'combobox':
                return await self._fill_combobox_birthday_field(page, field, value, field_type)
            
            # ========== INPUT FIELD HANDLING ==========
            if tag_name == 'input':
                return await self._fill_input_birthday_field(page, field, value, field_type)
            
            return False
            
        except Exception as e:
            print(f"   ❌ Smart selection failed for {field_type}: {e}")
            return False
    
    async def _fill_select_birthday_field(self, page, field, value, field_type: str) -> bool:
        """Fill select element for birthday field with multiple value formats"""
        try:
            # Build list of possible values to try
            possible_values = []
            
            if field_type == 'month':
                month_int = int(value)
                # Try numeric formats
                possible_values.extend([str(month_int), str(month_int).zfill(2)])
                # Try month names in different languages
                for lang, months in MONTH_NAMES.items():
                    if 1 <= month_int <= 12:
                        possible_values.append(months[month_int - 1])
                        possible_values.append(months[month_int - 1].lower())
                        
            elif field_type == 'day':
                day_int = int(value)
                possible_values.extend([str(day_int), str(day_int).zfill(2)])
                
            elif field_type == 'year':
                possible_values.append(str(value))
            
            # Try each possible value
            for val in possible_values:
                try:
                    await field.select_option(value=val)
                    print(f"   ✅ {field_type} selected with value: {val}")
                    return True
                except Exception:
                    pass
                
                # Also try selecting by visible text
                try:
                    await field.select_option(label=val)
                    print(f"   ✅ {field_type} selected with label: {val}")
                    return True
                except Exception:
                    pass
            
            # Fallback: try index-based selection for year (scroll support)
            if field_type == 'year':
                return await self._select_year_with_scroll(page, field, value)
            
            return False
            
        except Exception as e:
            print(f"   ❌ Select fill failed for {field_type}: {e}")
            return False
    
    async def _fill_combobox_birthday_field(self, page, field, value, field_type: str) -> bool:
        """Fill combobox for birthday field with dropdown handling"""
        try:
            # Click to open dropdown
            await field.click()
            await asyncio.sleep(0.8)
            
            # Build search text based on field type
            if field_type == 'month':
                month_int = int(value)
                # Try month name first, then number
                search_texts = []
                for months in MONTH_NAMES.values():
                    if 1 <= month_int <= 12:
                        search_texts.append(months[month_int - 1])
                search_texts.extend([str(month_int), str(month_int).zfill(2)])
            elif field_type == 'day':
                search_texts = [str(value), str(value).zfill(2)]
            else:  # year
                search_texts = [str(value)]
            
            # Try to find and click the option
            for search_text in search_texts:
                option_selectors = [
                    f'[role="option"]:has-text("{search_text}")',
                    f'li:has-text("{search_text}")',
                    f'div[role="option"]:has-text("{search_text}")',
                    f'span:has-text("{search_text}")'
                ]
                
                for selector in option_selectors:
                    try:
                        option = await page.query_selector(selector)
                        if option and await option.is_visible():
                            await option.click()
                            print(f"   ✅ {field_type} combobox option clicked: {search_text}")
                            await asyncio.sleep(0.3)
                            return True
                    except Exception:
                        continue
            
            # Fallback: use keyboard navigation for combobox (combobox elements don't support .fill())
            try:
                # Try typing using keyboard (works for some combobox implementations)
                value_str = str(value)
                for char in value_str:
                    await page.keyboard.press(char)
                    await asyncio.sleep(0.1)
                await asyncio.sleep(0.3)
                await field.press('Enter')
                print(f"   ✅ {field_type} filled via keyboard typing: {value}")
                return True
            except Exception:
                pass
            
            # Another fallback: use arrow keys to navigate
            try:
                await field.press('ArrowDown')
                await asyncio.sleep(0.2)
                await field.press('Enter')
                print(f"   ✅ {field_type} selected via arrow keys")
                return True
            except Exception:
                pass
            
            return False
            
        except Exception as e:
            print(f"   ❌ Combobox fill failed for {field_type}: {e}")
            return False
    
    async def _fill_input_birthday_field(self, page, field, value, field_type: str) -> bool:
        """Fill input field for birthday with human-like typing"""
        try:
            await field.click()
            await asyncio.sleep(0.2)
            
            # Clear existing value
            await field.fill("")
            await asyncio.sleep(0.1)
            
            # Format value
            if field_type == 'year':
                value_str = str(value)
            else:
                value_str = str(value).zfill(2)
            
            # Type character by character
            for char in value_str:
                await field.type(char, delay=random.randint(50, 120))
                await asyncio.sleep(random.uniform(0.03, 0.08))
            
            print(f"   ✅ {field_type} input filled: {value_str}")
            return True
            
        except Exception as e:
            print(f"   ❌ Input fill failed for {field_type}: {e}")
            return False
    
    async def _select_year_with_scroll(self, page, field, year_value) -> bool:
        """Select year from long dropdown with scrolling support"""
        try:
            # Get all options
            options = await field.query_selector_all('option')
            
            for option in options:
                try:
                    value = await option.get_attribute('value')
                    text = await option.text_content()
                    
                    if str(year_value) in [value, text]:
                        # Scroll option into view
                        await option.scroll_into_view_if_needed()
                        await asyncio.sleep(0.2)
                        
                        # Select the option
                        await field.select_option(value=value)
                        print(f"   ✅ Year selected with scroll: {year_value}")
                        return True
                except Exception:
                    continue
            
            return False
            
        except Exception as e:
            print(f"   ❌ Year scroll selection failed: {e}")
            return False
    
    async def _fill_birthday_with_fallback(self, page, birth_year: int, birth_month: int, birth_day: int) -> bool:
        """
        Fallback mechanism for birthday filling when dynamic detection fails.
        Tries multiple approaches in sequence.
        """
        print("   🔄 Starting birthday fallback mechanism...")
        
        fallback_attempts = []
        
        # ========== FALLBACK 1: Position-based detection ==========
        print("   📍 Fallback 1: Position-based detection...")
        try:
            result = await self._fill_birthday_by_position(page, birth_year, birth_month, birth_day)
            if result:
                print("   ✅ Fallback 1 succeeded: Position-based")
                return True
            fallback_attempts.append("Position-based: Failed")
        except Exception as e:
            fallback_attempts.append(f"Position-based: Error - {e}")
        
        # ========== FALLBACK 2: Keyboard input directly ==========
        print("   ⌨️ Fallback 2: Keyboard input...")
        try:
            result = await self._fill_birthday_keyboard_input(page, birth_year, birth_month, birth_day)
            if result:
                print("   ✅ Fallback 2 succeeded: Keyboard input")
                return True
            fallback_attempts.append("Keyboard input: Failed")
        except Exception as e:
            fallback_attempts.append(f"Keyboard input: Error - {e}")
        
        # ========== FALLBACK 3: Tab navigation ==========
        print("   ⇥ Fallback 3: Tab navigation...")
        try:
            result = await self._fill_birthday_tab_navigation(page, birth_year, birth_month, birth_day)
            if result:
                print("   ✅ Fallback 3 succeeded: Tab navigation")
                return True
            fallback_attempts.append("Tab navigation: Failed")
        except Exception as e:
            fallback_attempts.append(f"Tab navigation: Error - {e}")
        
        # Log all attempts for debugging
        print("   📋 Fallback Summary:")
        for attempt in fallback_attempts:
            print(f"      - {attempt}")
        
        return False
    
    async def _fill_birthday_by_position(self, page, birth_year: int, birth_month: int, birth_day: int) -> bool:
        """Fill birthday by detecting field positions (left to right order)"""
        try:
            # Get all select/combobox elements
            all_fields = await page.query_selector_all('select, [role="combobox"]')
            
            # Filter visible and get positions
            positioned_fields = []
            for field in all_fields:
                try:
                    if await field.is_visible():
                        bbox = await field.bounding_box()
                        if bbox:
                            positioned_fields.append({
                                'element': field,
                                'x': bbox['x'],
                                'y': bbox['y']
                            })
                except Exception:
                    continue
            
            # Sort by position (assuming same row, left to right = month, day, year)
            positioned_fields.sort(key=lambda x: (x['y'], x['x']))
            
            if len(positioned_fields) >= 3:
                # Assume US format: Month, Day, Year
                success_count = 0
                
                # Month (first)
                if await self._fill_birthday_with_smart_selection(page, positioned_fields[0]['element'], birth_month, 'month'):
                    success_count += 1
                await asyncio.sleep(0.3)
                
                # Day (second)
                if await self._fill_birthday_with_smart_selection(page, positioned_fields[1]['element'], birth_day, 'day'):
                    success_count += 1
                await asyncio.sleep(0.3)
                
                # Year (third)
                if await self._fill_birthday_with_smart_selection(page, positioned_fields[2]['element'], birth_year, 'year'):
                    success_count += 1
                
                return success_count >= 2
            
            return False
            
        except Exception as e:
            print(f"   ❌ Position-based fill error: {e}")
            return False
    
    async def _fill_birthday_keyboard_input(self, page, birth_year: int, birth_month: int, birth_day: int) -> bool:
        """Fill birthday using keyboard input directly"""
        try:
            # Focus on first birthday field
            first_field = await page.query_selector('select, [role="combobox"], input[placeholder*="Month" i], input[placeholder*="MM" i]')
            if not first_field:
                return False
            
            await first_field.click()
            await asyncio.sleep(0.3)
            
            # Type month
            await page.keyboard.type(str(birth_month).zfill(2))
            await asyncio.sleep(0.3)
            await page.keyboard.press('Tab')
            await asyncio.sleep(0.3)
            
            # Type day
            await page.keyboard.type(str(birth_day).zfill(2))
            await asyncio.sleep(0.3)
            await page.keyboard.press('Tab')
            await asyncio.sleep(0.3)
            
            # Type year
            await page.keyboard.type(str(birth_year))
            await asyncio.sleep(0.3)
            
            return True
            
        except Exception as e:
            print(f"   ❌ Keyboard input error: {e}")
            return False
    
    async def _fill_birthday_tab_navigation(self, page, birth_year: int, birth_month: int, birth_day: int) -> bool:
        """Fill birthday using tab key navigation between fields"""
        try:
            # Find any birthday-related field to start
            start_selectors = [
                'select[name*="month" i]', 'select[name*="birthday" i]',
                '[role="combobox"][aria-label*="month" i]',
                'input[placeholder*="Month" i]', 'input[placeholder*="MM" i]'
            ]
            
            start_field = None
            for selector in start_selectors:
                start_field = await page.query_selector(selector)
                if start_field:
                    break
            
            if not start_field:
                return False
            
            await start_field.focus()
            await asyncio.sleep(0.2)
            
            # Fill month
            await page.keyboard.type(str(birth_month))
            await page.keyboard.press('Tab')
            await asyncio.sleep(0.3)
            
            # Fill day
            await page.keyboard.type(str(birth_day))
            await page.keyboard.press('Tab')
            await asyncio.sleep(0.3)
            
            # Fill year
            await page.keyboard.type(str(birth_year))
            await asyncio.sleep(0.3)
            
            return True
            
        except Exception as e:
            print(f"   ❌ Tab navigation error: {e}")
            return False

    async def _fill_birthday_fields_in_section(self, section_fields, year, month, day) -> bool:
        """Fill birthday fields dalam section tertentu"""
        try:
            # Asumsikan urutan: month, day, year (format US umum)
            if len(section_fields) >= 3:
                await self._fill_birthday_field(section_fields[0], month, 'month')
                await asyncio.sleep(0.5)
                await self._fill_birthday_field(section_fields[1], day, 'day')
                await asyncio.sleep(0.5)
                await self._fill_birthday_field(section_fields[2], year, 'year')
                
                print("   ✅ Birthday filled in section")
                return True
        except Exception as e:
            print(f"   ⚠️ Section filling failed: {e}")
        
        return False

    async def _fill_comboboxes_safe(self, page, comboboxes, birth_year: int, birth_month: int, birth_day: int) -> bool:
        """Safe combobox filling dengan better error handling"""
        try:
            # Fill month (first combobox)
            await comboboxes[0].click()
            await asyncio.sleep(2)
            
            # Enhanced month selection
            month_filled = False
            month_names = ['January', 'February', 'March', 'April', 'May', 'June', 
                        'July', 'August', 'September', 'October', 'November', 'December']
            month_name = month_names[birth_month - 1]
            
            month_selectors = [
                f'[role="option"]:has-text("{month_name}")',
                f'[role="option"]:has-text("{birth_month}")',
                f'[role="option"]:has-text("{str(birth_month).zfill(2)}")'
            ]
            
            for selector in month_selectors:
                month_option = await page.query_selector(selector)
                if month_option and await month_option.is_visible():
                    await month_option.click()
                    print(f"   ✅ Month selected: {month_name}")
                    month_filled = True
                    break
            
            if not month_filled:
                first_option = await page.query_selector('[role="option"]')
                if first_option:
                    await first_option.click()
                    print("   ⚠️ Month filled with first option")
            
            await asyncio.sleep(1)
            
            # Fill day (second combobox)
            await comboboxes[1].click()
            await asyncio.sleep(2)
            
            day_filled = False
            day_selectors = [
                f'[role="option"]:has-text("{birth_day}")',
                f'[role="option"]:has-text("{str(birth_day).zfill(2)}")'
            ]
            
            for selector in day_selectors:
                day_option = await page.query_selector(selector)
                if day_option and await day_option.is_visible():
                    await day_option.click()
                    print(f"   ✅ Day selected: {birth_day}")
                    day_filled = True
                    break
            
            if not day_filled:
                first_option = await page.query_selector('[role="option"]')
                if first_option:
                    await first_option.click()
                    print("   ⚠️ Day filled with first option")
            
            await asyncio.sleep(1)
            
            # Fill year (third combobox)
            await comboboxes[2].click()
            await asyncio.sleep(2)
            
            year_filled = False
            year_selectors = [
                f'[role="option"]:has-text("{birth_year}")'
            ]
            
            for selector in year_selectors:
                year_option = await page.query_selector(selector)
                if year_option and await year_option.is_visible():
                    await year_option.click()
                    print(f"   ✅ Year selected: {birth_year}")
                    year_filled = True
                    break
            
            if not year_filled:
                first_option = await page.query_selector('[role="option"]')
                if first_option:
                    await first_option.click()
                    print("   ⚠️ Year filled with first option")
            
            await asyncio.sleep(2)
            
            return await self._is_birthday_filled(page)
            
        except Exception as e:
            print(f"   ❌ Safe combobox filling failed: {e}")
            return False

    async def _is_birthday_filled(self, page) -> bool:
        """Check if birthday is already filled"""
        try:
            # Check if any birthday field has a value
            year_field = await page.query_selector('select[name="birthday_year"]')
            if year_field:
                year_value = await year_field.evaluate("element => element.value")
                if year_value and year_value != "":
                    return True
            
            # Check combobox values
            comboboxes = await page.query_selector_all('[role="combobox"]')
            for combobox in comboboxes:
                value = await combobox.evaluate("element => element.textContent || element.value")
                if value and value.strip():
                    return True
                    
            return False
        except:
            return False

    async def _fill_birthday_fields(self, page, birth_year: int, birth_month: int, birth_day: int) -> bool:
        """Fill birthday fields for Version 2 - Enhanced with dynamic detection"""
        print("   🎂 Filling birthday fields with enhanced dynamic approach...")
        print(f"   📅 Target date: {birth_year}-{birth_month:02d}-{birth_day:02d}")
        
        try:
            # Take screenshot untuk debugging
            try:
                await page.screenshot(path="./debug_birthday_page.png")
            except Exception as e:
                print("   ⚠️ Screenshot skipped: %s", e)
            
            # Tunggu sebentar untuk memastikan halaman fully loaded
            await asyncio.sleep(3)
            
            # ========== ENHANCED: Try dynamic detection first ==========
            print("   🔍 Step 1: Enhanced dynamic field detection...")
            
            detected_fields = await self._detect_form_fields_dynamically(page)
            
            if detected_fields.get('confidence', 0) > 0.2:
                birthday_filled = 0
                
                # Fill detected birthday fields
                if 'month' in detected_fields:
                    success = await self._fill_birthday_with_smart_selection(page, detected_fields['month'], birth_month, 'month')
                    if success:
                        birthday_filled += 1
                    await asyncio.sleep(0.5)
                
                if 'day' in detected_fields:
                    success = await self._fill_birthday_with_smart_selection(page, detected_fields['day'], birth_day, 'day')
                    if success:
                        birthday_filled += 1
                    await asyncio.sleep(0.5)
                
                if 'year' in detected_fields:
                    success = await self._fill_birthday_with_smart_selection(page, detected_fields['year'], birth_year, 'year')
                    if success:
                        birthday_filled += 1
                
                if birthday_filled >= 2:
                    print(f"   ✅ Birthday filled via dynamic detection ({birthday_filled}/3)")
                    return True
            
            # ========== Strategy 2: Direct select element selection ==========
            print("   🔍 Step 2: Looking for select elements directly...")
            
            # Cari semua select elements di halaman
            select_elements = await page.query_selector_all('select')
            print(f"   📊 Found {len(select_elements)} select elements")
            
            # Filter hanya yang visible dan kemungkinan birthday fields
            visible_selects = []
            for i, select in enumerate(select_elements):
                try:
                    # Gunakan force visibility check
                    is_visible = await select.is_visible()
                    select_name = await select.get_attribute('name') or ''
                    print(f"   🔘 Select {i}: visible={is_visible}, name='{select_name}'")
                    
                    if is_visible:
                        visible_selects.append(select)
                except Exception as e:
                    print(f"   ⚠️ Error checking select {i}: {e}")
            
            print(f"   ✅ Visible select elements: {len(visible_selects)}")
            
            # Jika ada 3 select elements, asumsikan itu birthday fields
            if len(visible_selects) >= 3:
                print("   🎯 Found 3 select elements, assuming birthday fields")
                
                # Urutkan berdasarkan posisi
                positioned_selects = []
                for select in visible_selects:
                    try:
                        bbox = await select.bounding_box()
                        if bbox:
                            positioned_selects.append({
                                'element': select,
                                'y': bbox['y'],
                                'x': bbox['x']
                            })
                    except Exception as e:
                        print(f"   ⚠️ Error getting position: {e}")
                
                if len(positioned_selects) >= 3:
                    positioned_selects.sort(key=lambda x: (x['y'], x['x']))
                    
                    print("   📅 Filling birthday selects by position with smart selection...")
                    
                    try:
                        # Month - first select (use smart selection)
                        await self._fill_birthday_with_smart_selection(page, positioned_selects[0]['element'], birth_month, 'month')
                        await asyncio.sleep(1)
                        
                        # Day - second select  
                        await self._fill_birthday_with_smart_selection(page, positioned_selects[1]['element'], birth_day, 'day')
                        await asyncio.sleep(1)
                        
                        # Year - third select
                        await self._fill_birthday_with_smart_selection(page, positioned_selects[2]['element'], birth_year, 'year')
                        print(f"   ✅ Year selected: {birth_year}")
                        await asyncio.sleep(1)
                        
                        print("   ✅ Birthday fields filled successfully via direct select")
                        try:
                            await page.screenshot(path="./debug_birthday_select_filled.png", timeout=5000)
                        except Exception as e:
                            print("   ⚠️ Screenshot skipped: %s", e)
                        return True
                        
                    except Exception as e:
                        print(f"   ❌ Direct select filling failed: {e}")
            
            # Strategy 2: Coba custom combobox dengan wait yang lebih lama
            print("   🔄 Strategy 2: Custom combobox with longer wait...")
            
            # Tunggu lebih lama untuk elements muncul
            await asyncio.sleep(2)
            
            # Cari elements dengan role combobox atau input
            combobox_elements = await page.query_selector_all('[role="combobox"], input[type="text"]')
            print(f"   📊 Found {len(combobox_elements)} combobox/text elements")
            
            visible_comboboxes = []
            for i, elem in enumerate(combobox_elements):
                try:
                    is_visible = await elem.is_visible()
                    aria_label = await elem.get_attribute('aria-label') or ''
                    placeholder = await elem.get_attribute('placeholder') or ''
                    print(f"   🔘 Combobox {i}: visible={is_visible}, aria='{aria_label}', placeholder='{placeholder}'")
                    
                    if is_visible and (aria_label or placeholder):
                        visible_comboboxes.append(elem)
                except Exception as e:
                    print(f"   ⚠️ Error checking combobox {i}: {e}")
            
            # Jika ada 3 combobox, coba isi
            if len(visible_comboboxes) >= 3:
                print("   🎯 Found 3 combobox elements, trying to fill...")
                
                # Urutkan berdasarkan posisi
                positioned_combos = []
                for combo in visible_comboboxes:
                    try:
                        bbox = await combo.bounding_box()
                        if bbox:
                            positioned_combos.append({
                                'element': combo,
                                'y': bbox['y'],
                                'x': bbox['x']
                            })
                    except Exception:
                        continue
                
                if len(positioned_combos) >= 3:
                    positioned_combos.sort(key=lambda x: (x['y'], x['x']))
                    
                    try:
                        # Month
                        await positioned_combos[0]['element'].click()
                        await asyncio.sleep(2)  # Tunggu lebih lama untuk dropdown muncul
                        month_option = await page.wait_for_selector(f'[role="option"]:has-text("{birth_month}")', timeout=5000)
                        if month_option:
                            await month_option.click()
                            print(f"   ✅ Month selected via combobox: {birth_month}")
                        await asyncio.sleep(1)
                        
                        # Day
                        await positioned_combos[1]['element'].click()
                        await asyncio.sleep(2)
                        day_option = await page.wait_for_selector(f'[role="option"]:has-text("{birth_day}")', timeout=5000)
                        if day_option:
                            await day_option.click()
                            print(f"   ✅ Day selected via combobox: {birth_day}")
                        await asyncio.sleep(1)
                        
                        # Year
                        await positioned_combos[2]['element'].click()
                        await asyncio.sleep(2)
                        year_option = await page.wait_for_selector(f'[role="option"]:has-text("{birth_year}")', timeout=5000)
                        if year_option:
                            await year_option.click()
                            print(f"   ✅ Year selected via combobox: {birth_year}")
                        await asyncio.sleep(1)
                        
                        print("   ✅ Birthday fields filled via combobox")
                        try:
                            await page.screenshot(path="./debug_birthday_combobox_filled.png")
                        except Exception as e:
                            print("   ⚠️ Screenshot skipped: %s", e)
                        return True
                        
                    except Exception as e:
                        print(f"   ❌ Combobox filling failed: {e}")
            
            # Strategy 3: Coba isi berdasarkan pattern yang umum di Instagram
            print("   🔄 Strategy 3: Pattern-based filling...")
            
            # Coba berbagai selector pattern yang umum untuk birthday fields
            patterns = [
                # Pattern 1: Select elements dengan name tertentu
                ('select[name="birthday_month"]', str(birth_month)),
                ('select[name="birthday_day"]', str(birth_day)),
                ('select[name="birthday_year"]', str(birth_year)),
                
                # Pattern 2: Elements dengan aria-label
                ('[aria-label*="Month" i]', str(birth_month)),
                ('[aria-label*="Day" i]', str(birth_day)),
                ('[aria-label*="Year" i]', str(birth_year)),
                
                # Pattern 3: Input fields dengan placeholder
                ('input[placeholder*="Month" i]', str(birth_month)),
                ('input[placeholder*="Day" i]', str(birth_day)),
                ('input[placeholder*="Year" i]', str(birth_year)),
            ]
            
            filled_count = 0
            for selector, value in patterns:
                try:
                    element = await page.query_selector(selector)
                    if element and await element.is_visible():
                        if 'select' in selector:
                            await element.select_option(value=value)
                        else:
                            await element.click()
                            await asyncio.sleep(1)
                            # Untuk non-select elements, mungkin perlu memilih dari dropdown
                            option = await page.query_selector(f'[role="option"]:has-text("{value}")')
                            if option:
                                await option.click()
                        
                        print(f"   ✅ Filled {selector} with {value}")
                        filled_count += 1
                        await asyncio.sleep(1)
                except Exception as e:
                    print(f"   ⚠️ Pattern {selector} failed: {e}")
            
            if filled_count >= 2:
                print(f"   ✅ Successfully filled {filled_count}/3 birthday fields")
                try:
                    await page.screenshot(path="./debug_birthday_pattern_filled.png")
                except Exception as e:
                    print("   ⚠️ Screenshot skipped: %s", e)
                return True
            
            logger.error("   ❌ All birthday filling strategies failed")
            try:
                await page.screenshot(path="./debug_birthday_all_failed.png")
            except Exception as e:
                print("   ⚠️ Screenshot skipped: %s", e)
            return False
            
        except Exception as e:
            logger.error(f"   ❌ Birthday filling failed: {e}")
            try:
                await page.screenshot(path="./debug_birthday_error.png")
            except Exception as e:
                print("   ⚠️ Screenshot skipped: %s", e)
            return False

    async def _click_button_by_text(self, page, button_texts) -> bool:
        """Click button by text content - CASE INSENSITIVE"""
        buttons = await page.query_selector_all('button, [role="button"]')
        
        for button in buttons:
            try:
                if await button.is_visible() and await button.is_enabled():
                    text = (await button.text_content() or "").strip()
                    text_lower = text.lower()
                    
                    # Check if any of the target texts are in the button text (case insensitive)
                    for target_text in button_texts:
                        if target_text.lower() in text_lower:
                            # Ensure button is clickable
                            await button.scroll_into_view_if_needed()
                            await asyncio.sleep(0.5)
                            
                            # Try multiple click methods
                            try:
                                await button.click()
                                print(f"   ✅ Clicked button: '{text}'")
                                return True
                            except Exception as e:
                                print(f"   ⚠️ Normal click failed, trying JS click: {e}")
                                try:
                                    await button.evaluate("el => el.click()")
                                    print(f"   ✅ Clicked button via JS: '{text}'")
                                    return True
                                except Exception as e2:
                                    print(f"   ⚠️ JS click failed: {e2}")
                                    continue
            except Exception:
                continue
        
        return False

    async def _detect_and_click_submit_button(self, page, step: str = "signup") -> bool:
        """
        Enhanced button detection for different form steps.
        Includes scrolling to find buttons that may be below the fold.
        
        Steps:
        - 'signup': Sign up / Daftar / Masuk / Create Account
        - 'birthday': Continue / Next / Lanjutkan / Berikutnya
        - 'otp': Continue / Next / Finish / Done / Verify / Selesai
        
        Returns True if button was found and clicked.
        """
        print(f"   🔘 Detecting button for step: {step}...")
        
        # Define button texts for each step (multi-language support)
        button_patterns = {
            'signup': [
                # English
                'sign up', 'create account', 'register', 'submit', 'join',
                # Indonesian
                'daftar', 'masuk', 'buat akun', 'gabung',
                # Spanish
                'registrar', 'crear cuenta', 'unirse',
                # French
                's\'inscrire', 'créer un compte',
                # German
                'registrieren', 'konto erstellen'
            ],
            'birthday': [
                # English
                'next', 'continue', 'proceed', 'submit',
                # Indonesian
                'lanjut', 'lanjutkan', 'berikutnya', 'kirim',
                # Spanish
                'siguiente', 'continuar', 'enviar',
                # French
                'suivant', 'continuer',
                # German
                'weiter', 'fortfahren'
            ],
            'otp': [
                # English
                'next', 'continue', 'finish', 'done', 'verify', 'confirm', 'submit', 'complete',
                # Indonesian
                'lanjut', 'selesai', 'verifikasi', 'konfirmasi', 'kirim',
                # Spanish
                'siguiente', 'terminar', 'verificar', 'confirmar',
                # French
                'terminer', 'vérifier', 'confirmer',
                # German
                'fertig', 'bestätigen', 'verifizieren'
            ]
        }
        
        target_texts = button_patterns.get(step, button_patterns['signup'])
        
        # ========== PRE-SCROLL: Scroll down to reveal hidden buttons ==========
        print(f"   📜 Pre-scroll: Checking for hidden buttons...")
        await self._scroll_to_find_button(page)
        await asyncio.sleep(0.5)
        
        # Strategy 1: Direct text matching
        print(f"   🔍 Strategy 1: Text-based button detection...")
        result = await self._click_button_by_text_with_scroll(page, target_texts)
        if result:
            return True
        
        # Strategy 2: Search in submit-type buttons
        print(f"   🔍 Strategy 2: Submit button detection...")
        submit_selectors = [
            'button[type="submit"]',
            'input[type="submit"]',
            'button[type="button"]'
        ]
        
        for selector in submit_selectors:
            try:
                buttons = await page.query_selector_all(selector)
                for button in buttons:
                    # Try to scroll to button first
                    try:
                        await button.scroll_into_view_if_needed()
                        await asyncio.sleep(0.2)
                    except Exception:
                        pass
                    
                    if await button.is_visible() and await button.is_enabled():
                        text = (await button.text_content() or "").strip().lower()
                        aria_label = (await button.get_attribute('aria-label') or "").lower()
                        
                        for target in target_texts:
                            if target.lower() in text or target.lower() in aria_label:
                                await button.scroll_into_view_if_needed()
                                await asyncio.sleep(0.3)
                                await button.click()
                                print(f"   ✅ Clicked submit button: '{text or aria_label}'")
                                return True
            except Exception:
                continue
        
        # Strategy 3: Primary/accent button detection (by style)
        print(f"   🔍 Strategy 3: Primary button detection by style...")
        style_selectors = [
            'button[class*="primary"]',
            'button[class*="submit"]',
            'button[class*="action"]',
            'button[class*="btn-primary"]',
            'button[class*="_acan"]',  # Instagram specific
            'button[class*="_acap"]'   # Instagram specific
        ]
        
        for selector in style_selectors:
            try:
                button = await page.query_selector(selector)
                if button:
                    # Scroll to button first
                    try:
                        await button.scroll_into_view_if_needed()
                        await asyncio.sleep(0.2)
                    except Exception:
                        pass
                    
                    if await button.is_visible() and await button.is_enabled():
                        text = (await button.text_content() or "").strip()
                        await button.click()
                        print(f"   ✅ Clicked primary button: '{text}'")
                        return True
            except Exception:
                continue
        
        # Strategy 4: Scroll and find all buttons
        print(f"   🔍 Strategy 4: Full page scroll + button detection...")
        result = await self._scroll_and_find_button(page, target_texts)
        if result:
            return True
        
        # Strategy 5: Last resort - click any enabled button at bottom of form
        print(f"   🔍 Strategy 5: Position-based button detection...")
        try:
            all_buttons = await page.query_selector_all('button')
            visible_buttons = []
            
            for button in all_buttons:
                # Try scrolling to each button
                try:
                    await button.scroll_into_view_if_needed()
                    await asyncio.sleep(0.1)
                except Exception:
                    pass
                
                if await button.is_visible() and await button.is_enabled():
                    bbox = await button.bounding_box()
                    if bbox:
                        text = (await button.text_content() or "").strip()
                        visible_buttons.append({
                            'element': button,
                            'y': bbox['y'],
                            'text': text
                        })
            
            # Sort by Y position (bottom buttons are usually submit)
            visible_buttons.sort(key=lambda x: x['y'], reverse=True)
            
            # Try buttons from bottom to top
            for btn_data in visible_buttons[:3]:
                text = btn_data['text'].lower()
                # Skip obvious non-submit buttons using global constant
                if any(skip in text for skip in BUTTON_SKIP_WORDS):
                    continue
                
                await btn_data['element'].scroll_into_view_if_needed()
                await asyncio.sleep(0.3)
                await btn_data['element'].click()
                print(f"   ✅ Clicked position-based button: '{btn_data['text']}'")
                return True
                
        except Exception as e:
            print(f"   ⚠️ Position-based detection failed: {e}")
        
        print(f"   ❌ No button found for step: {step}")
        return False

    async def _scroll_to_find_button(self, page) -> None:
        """
        Scroll down the page to reveal buttons that might be hidden below the fold.
        """
        try:
            # Get viewport height
            viewport_height = await page.evaluate("() => window.innerHeight")
            scroll_height = await page.evaluate("() => document.body.scrollHeight")
            
            # If content is taller than viewport, scroll down
            if scroll_height > viewport_height:
                # Scroll in small increments
                scroll_amount = min(300, scroll_height - viewport_height)
                
                for _ in range(3):  # Try scrolling up to 3 times
                    await page.evaluate(f"window.scrollBy(0, {scroll_amount})")
                    await asyncio.sleep(0.3)
                    
                    # Check if we can see a button now
                    buttons = await page.query_selector_all('button[type="submit"], button:has-text("Sign up"), button:has-text("Next"), button:has-text("Continue")')
                    for button in buttons:
                        if await button.is_visible():
                            print(f"   📜 Found button after scrolling")
                            return
                
                # Scroll back to top if no button found
                await page.evaluate("window.scrollTo(0, 0)")
                
        except Exception as e:
            print(f"   ⚠️ Scroll error: {e}")

    async def _click_button_by_text_with_scroll(self, page, button_texts) -> bool:
        """
        Click button by text content with scroll support.
        First tries without scroll, then scrolls to find hidden buttons.
        """
        # First try without scrolling
        buttons = await page.query_selector_all('button, [role="button"], input[type="submit"]')
        
        for button in buttons:
            try:
                # First, try to scroll button into view
                try:
                    await button.scroll_into_view_if_needed()
                    await asyncio.sleep(0.2)
                except Exception:
                    pass
                
                if await button.is_visible() and await button.is_enabled():
                    text = (await button.text_content() or "").strip()
                    aria_label = (await button.get_attribute('aria-label') or "")
                    text_lower = text.lower()
                    aria_lower = aria_label.lower()
                    
                    for target_text in button_texts:
                        if target_text.lower() in text_lower or target_text.lower() in aria_lower:
                            await asyncio.sleep(0.3)
                            
                            try:
                                await button.click()
                                print(f"   ✅ Clicked button: '{text}'")
                                return True
                            except Exception as e:
                                print(f"   ⚠️ Normal click failed, trying JS click: {e}")
                                try:
                                    await button.evaluate("el => el.click()")
                                    print(f"   ✅ Clicked button via JS: '{text}'")
                                    return True
                                except Exception as e2:
                                    print(f"   ⚠️ JS click failed: {e2}")
                                    continue
            except Exception:
                continue
        
        return False

    async def _scroll_and_find_button(self, page, target_texts) -> bool:
        """
        Scroll through the entire page to find and click a button.
        Useful when button is completely hidden below the fold.
        """
        try:
            # Get page dimensions
            scroll_height = await page.evaluate("() => document.body.scrollHeight")
            viewport_height = await page.evaluate("() => window.innerHeight")
            
            # Scroll from top to bottom in increments
            current_scroll = 0
            scroll_step = viewport_height // 2  # Scroll half viewport at a time
            
            # Start from top
            await page.evaluate("window.scrollTo(0, 0)")
            await asyncio.sleep(0.3)
            
            while current_scroll < scroll_height:
                # Check for buttons at current scroll position
                buttons = await page.query_selector_all('button, [role="button"], input[type="submit"]')
                
                for button in buttons:
                    try:
                        if await button.is_visible() and await button.is_enabled():
                            text = (await button.text_content() or "").strip()
                            text_lower = text.lower()
                            
                            for target_text in target_texts:
                                if target_text.lower() in text_lower:
                                    await button.scroll_into_view_if_needed()
                                    await asyncio.sleep(0.3)
                                    await button.click()
                                    print(f"   ✅ Found button after scroll: '{text}'")
                                    return True
                    except Exception:
                        continue
                
                # Scroll down
                current_scroll += scroll_step
                await page.evaluate(f"window.scrollTo(0, {current_scroll})")
                await asyncio.sleep(0.3)
            
            # Final check at bottom of page
            await page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
            await asyncio.sleep(0.5)
            
            # Try one more time to find button
            buttons = await page.query_selector_all('button, [role="button"], input[type="submit"]')
            for button in buttons:
                try:
                    if await button.is_visible() and await button.is_enabled():
                        text = (await button.text_content() or "").strip()
                        text_lower = text.lower()
                        
                        for target_text in target_texts:
                            if target_text.lower() in text_lower:
                                await button.click()
                                print(f"   ✅ Found button at page bottom: '{text}'")
                                return True
                except Exception:
                    continue
            
            return False
            
        except Exception as e:
            print(f"   ⚠️ Scroll and find error: {e}")
            return False

    async def _scroll_page_to_bottom(self, page) -> None:
        """
        Scroll page to bottom to ensure all elements are loaded and visible.
        """
        try:
            # Smooth scroll to bottom
            await page.evaluate("""
                () => {
                    return new Promise((resolve) => {
                        const scrollStep = 100;
                        const scrollInterval = setInterval(() => {
                            window.scrollBy(0, scrollStep);
                            if ((window.innerHeight + window.scrollY) >= document.body.scrollHeight) {
                                clearInterval(scrollInterval);
                                resolve();
                            }
                        }, 50);
                        
                        // Timeout after 3 seconds
                        setTimeout(() => {
                            clearInterval(scrollInterval);
                            resolve();
                        }, 3000);
                    });
                }
            """)
            await asyncio.sleep(0.5)
        except Exception as e:
            print(f"   ⚠️ Scroll to bottom error: {e}")

    async def _detect_form_method(self, page) -> str:
        """
        Detect which form method is being used:
        
        Method 1 (multi_step):
        - Step 1: Username, Email, Password, Full Name → Sign up
        - Step 2: Birthday → Continue/Next
        - Step 3: Confirmation Code → Continue/Next/Finish
        
        Method 2 (single_step):
        - Step 1: Username, Email, Password, Birthday, Full Name → Sign up
        - Step 2: Confirmation Code → Continue/Next/Finish
        
        Returns: 'multi_step' or 'single_step'
        """
        print("   🔍 Detecting form method...")
        
        try:
            # Check for birthday fields on the initial page
            birthday_selectors = [
                'select[name*="birthday"]',
                'select[title*="Year"]',
                'select[aria-label*="Year"]',
                'select[aria-label*="Month"]',
                'select[aria-label*="Day"]',
                '[role="combobox"][aria-label*="birthday" i]',
                '[role="combobox"][aria-label*="month" i]',
                '[role="combobox"][aria-label*="year" i]',
                '[aria-label*="date of birth" i]'
            ]
            
            birthday_found = False
            birthday_count = 0
            
            for selector in birthday_selectors:
                try:
                    elements = await page.query_selector_all(selector)
                    for element in elements:
                        if await element.is_visible():
                            birthday_found = True
                            birthday_count += 1
                except Exception:
                    continue
            
            # Also check for birthday text labels
            birthday_text_patterns = [
                'text=Birthday',
                'text=Date of Birth',
                'text=Tanggal Lahir',
                'text=Fecha de nacimiento',
                ':has-text("Birthday")',
                ':has-text("Date of Birth")'
            ]
            
            for pattern in birthday_text_patterns:
                try:
                    element = await page.query_selector(pattern)
                    if element and await element.is_visible():
                        birthday_found = True
                        break
                except Exception:
                    continue
            
            print(f"   📊 Birthday fields found: {birthday_found} (count: {birthday_count})")
            
            if birthday_found and birthday_count >= 2:
                print("   ✅ SINGLE_STEP method detected (birthday on initial page)")
                return "single_step"
            else:
                print("   ✅ MULTI_STEP method detected (no birthday on initial page)")
                return "multi_step"
                
        except Exception as e:
            print(f"   ⚠️ Form method detection error: {e}")
            # Default to multi_step as it's more common
            return "multi_step"

    async def _wait_for_birthday_page(self, page, timeout: int = 10) -> bool:
        """
        Wait for birthday page to appear after clicking sign up (for multi_step method).
        Returns True if birthday page detected, False if timeout.
        """
        print("   ⏳ Waiting for birthday page...")
        
        start_time = asyncio.get_event_loop().time()
        
        while (asyncio.get_event_loop().time() - start_time) < timeout:
            try:
                # Check for birthday field indicators
                birthday_indicators = [
                    'select[name*="birthday"]',
                    '[aria-label*="birthday" i]',
                    '[aria-label*="month" i]',
                    '[aria-label*="year" i]',
                    '[role="combobox"]',
                    'select'
                ]
                
                for selector in birthday_indicators:
                    element = await page.query_selector(selector)
                    if element and await element.is_visible():
                        # Verify it's actually a birthday field by checking nearby text
                        parent_text = await page.evaluate("""() => {
                            return document.body.innerText.toLowerCase();
                        }""")
                        
                        if any(word in parent_text for word in ['birthday', 'birth', 'tanggal lahir', 'date of birth']):
                            print("   ✅ Birthday page detected!")
                            return True
                
                await asyncio.sleep(0.5)
                
            except Exception:
                await asyncio.sleep(0.5)
                continue
        
        print("   ⚠️ Birthday page not detected within timeout")
        return False

    async def _wait_for_otp_page(self, page, timeout: int = 15) -> bool:
        """
        Wait for OTP/confirmation code page to appear.
        Returns True if OTP page detected, False if timeout.
        """
        print("   ⏳ Waiting for OTP page...")
        
        start_time = asyncio.get_event_loop().time()
        
        while (asyncio.get_event_loop().time() - start_time) < timeout:
            try:
                # Check for OTP input field
                otp_selectors = [
                    'input[placeholder*="confirmation" i]',
                    'input[placeholder*="code" i]',
                    'input[aria-label*="confirmation" i]',
                    'input[aria-label*="code" i]',
                    'input[name*="code" i]',
                    'input[name*="otp" i]',
                    'input[placeholder*="kode" i]',  # Indonesian
                    'input[placeholder*="verification" i]'
                ]
                
                for selector in otp_selectors:
                    element = await page.query_selector(selector)
                    if element and await element.is_visible():
                        print("   ✅ OTP page detected!")
                        return True
                
                # Also check page content
                page_text = await page.evaluate("() => document.body.innerText.toLowerCase()")
                otp_indicators = [
                    'confirmation code', 'verification code', 'enter the code',
                    'kode konfirmasi', 'masukkan kode',
                    'código de confirmación', 'code de confirmation'
                ]
                
                if any(indicator in page_text for indicator in otp_indicators):
                    print("   ✅ OTP page detected via text content!")
                    return True
                
                await asyncio.sleep(0.5)
                
            except Exception:
                await asyncio.sleep(0.5)
                continue
        
        print("   ⚠️ OTP page not detected within timeout")
        return False

    async def _handle_otp_verification(self, page, email: str) -> bool:
        """OTP verification with STRICT success detection, human confirmation handling, and retry mechanism"""
        print("   📧 Starting OTP verification process...")
        
        max_retries = 2
        retry_count = 0
        
        while retry_count <= max_retries:
            try:
                if retry_count > 0:
                    print(f"   🔄 RETRY ATTEMPT {retry_count}/{max_retries}")
                    # Refresh page and start over
                    await page.reload()
                    await asyncio.sleep(3)
                
                # Wait for OTP page specifically
                print("   ⏳ Waiting for OTP page to load...")
                try:
                    await page.wait_for_selector('input[placeholder*="Confirmation Code" i], input[aria-label*="Confirmation Code" i]', timeout=10000)
                except Exception as e:
                    print(f"   ❌ OTP page not loaded: {e}")
                    if retry_count < max_retries:
                        retry_count += 1
                        continue
                    else:
                        return False
                
                await asyncio.sleep(2)

                # Get OTP code (get fresh code for each retry)
                print("   🔄 Retrieving OTP code...")
                otp_code = await self.get_otp_from_email(email)
                if not otp_code:
                    print("   ❌ Could not retrieve OTP code - closing session for new attempt")
                    # Return special status to indicate OTP not received - need new session
                    self.status = STATUS_OTP_NOT_RECEIVED
                    return False
                
                print(f"   ✅ OTP Code received: {otp_code}")

                # Fill OTP
                otp_input = await page.query_selector('input[placeholder*="Confirmation Code" i], input[aria-label*="Confirmation Code" i]')
                if not otp_input:
                    print("   ❌ OTP input not found")
                    if retry_count < max_retries:
                        retry_count += 1
                        continue
                    else:
                        return False
                        
                await otp_input.click()
                await asyncio.sleep(0.3)
                await otp_input.fill("")
                await asyncio.sleep(0.2)
                await otp_input.type(otp_code, delay=80)
                await asyncio.sleep(1)
                print("   ✅ OTP code entered")

                # Submit OTP
                submit_btn = await page.query_selector('button:has-text("Continue"), button:has-text("Next"), button[type="submit"], button:has-text("Finish")')
                if submit_btn:
                    await submit_btn.click()
                    print("   ✅ OTP submitted")
                else:
                    await page.keyboard.press('Enter')
                    print("   ⌨️ Enter key pressed")

                # ========== CONTINUOUS PAGE DETECTION LOOP ==========
                # Loop through pages until we reach home or detect suspend
                print("   ⏳ Starting continuous page detection...")
                
                max_total_time = 120  # Maximum 2 minutes for entire flow
                start_time = asyncio.get_event_loop().time()
                loading_stuck_count = 0
                same_state_count = 0
                last_state = None
                
                while (asyncio.get_event_loop().time() - start_time) < max_total_time:
                    current_time = asyncio.get_event_loop().time() - start_time
                    print(f"\n   🔍 Page check at {current_time:.1f}s...")
                    
                    # 1. Wait for page loading to complete (including button loading)
                    if await self._is_page_loading(page):
                        loading_stuck_count += 1
                        print(f"   ⏳ Page/button loading... ({loading_stuck_count}/10)")
                        
                        if loading_stuck_count >= 10:
                            print("   🔄 Loading stuck too long, attempting reload...")
                            reload_success = await self._handle_stuck_loading(page, otp_code)
                            if reload_success:
                                loading_stuck_count = 0
                                continue
                            else:
                                break  # Exit to retry
                        
                        await asyncio.sleep(2)
                        continue
                    else:
                        if loading_stuck_count > 0:
                            print(f"   ✅ Loading completed after {loading_stuck_count} checks")
                        loading_stuck_count = 0
                    
                    # 2. Check current page state
                    current_url = page.url.lower()
                    print(f"   🔗 URL: {current_url}")
                    
                    # 3. CHECK: Are we on home page? = SUCCESS
                    if await self._is_on_home_page(page):
                        print("   🎉 SUCCESS: Reached home page!")
                        return True
                    
                    # 3.5. CHECK: Phone verification required? = CLOSE SESSION
                    if await self._is_phone_verification_page(page):
                        print("   📱 Phone verification required - closing session immediately")
                        print("   🔄 Will create new session with fresh account")
                        self.status = STATUS_PHONE_REQUIRED
                        try:
                            await page.close()
                        except Exception:
                            pass
                        return False
                    
                    # 4. CHECK: Is account suspended? Try to recover via human confirmation
                    if await self._is_account_suspended(page):
                        print("   🚫 Account suspended detected, attempting recovery...")
                        recovery_result = await self._handle_suspend_recovery(page)
                        if recovery_result == 'success':
                            print("   ✅ Suspend recovery successful!")
                            return True
                        elif recovery_result == 'continue':
                            print("   🔄 Suspend recovery in progress, continuing...")
                            same_state_count = 0
                            await asyncio.sleep(2)
                            continue
                        elif recovery_result == 'phone_required':
                            print("   📱 Phone verification required - closing session")
                            print("   🔄 Will create new session with fresh account")
                            self.status = STATUS_PHONE_REQUIRED
                            # Close current page/context to force new session
                            try:
                                await page.close()
                            except Exception:
                                pass
                            return False
                        else:
                            print("   🚫 FAILED: Account suspended, recovery failed!")
                            self.status = 5
                            return False
                    
                    # 5. CHECK: Any form fields to fill?
                    page_result = await self._detect_and_fill_current_page(page, otp_code)
                    
                    if page_result == 'filled':
                        print("   ✅ Fields filled, waiting for loading to complete...")
                        same_state_count = 0
                        # Wait for loading after submit
                        await self._wait_for_loading_complete(page, timeout=20)
                        await asyncio.sleep(2)
                        continue
                    elif page_result == 'otp_entered':
                        print("   ✅ OTP entered, waiting for loading to complete...")
                        same_state_count = 0
                        # Wait for loading after OTP submit
                        await self._wait_for_loading_complete(page, timeout=20)
                        await asyncio.sleep(2)
                        continue
                    elif page_result == 'no_fields':
                        # No fields found - check if stuck
                        current_state = await self._get_page_state(page)
                        if current_state == last_state:
                            same_state_count += 1
                            print(f"   ⚠️ Same state detected ({same_state_count}/5)")
                            
                            if same_state_count >= 5:
                                # Stuck on same page - try clicking any visible button
                                print("   🔄 Stuck, trying to find action...")
                                await self._try_unstuck_action(page)
                                # Wait for loading after action
                                await self._wait_for_loading_complete(page, timeout=15)
                                same_state_count = 0
                        else:
                            same_state_count = 0
                            last_state = current_state
                    
                    await asyncio.sleep(2)
                
                # Timeout - do final verification
                print("   ⏰ Timeout reached, doing final verification...")
                return await self._final_verification(page)
                
            except Exception as e:
                logger.error(f"   ❌ OTP verification failed (attempt {retry_count + 1}): {e}")
                if retry_count < max_retries:
                    retry_count += 1
                    await asyncio.sleep(2)
                    continue
                else:
                    return False
        
        print("   ❌ All retry attempts exhausted")
        return False

    async def _get_page_state(self, page) -> str:
        """Get current page state for stuck detection"""
        try:
            # Combine URL and visible elements to create state fingerprint
            url = page.url
            visible_elements = []
            
            # Check for key elements
            key_selectors = [
                'input[placeholder*="Confirmation Code" i]',
                'button:has-text("Continue")',
                'button:has-text("Next")',
                'text=Confirm you\'re human',
                'div[role="alert"]',
                'nav[role="navigation"]',
                'article'
            ]
            
            for selector in key_selectors:
                if await page.query_selector(selector):
                    visible_elements.append(selector)
            
            state = f"{url}|{','.join(sorted(visible_elements))}"
            return state
            
        except Exception as e:
            return f"error:{e}"

    async def _check_human_confirmation_page(self, page) -> bool:
        """Check for human confirmation page - jika ada, berarti checkpoint"""
        try:
            current_url = page.url.lower()
            page_content = await page.content()
            page_text = page_content.lower()
            
            # Human confirmation/checkpoint indicators
            confirmation_indicators = [
                "confirm you're human",
                "human verification", 
                "security check",
                "we need to confirm",
                "unusual activity",
                "suspicious activity",
                "help us confirm",
                "confirm its you"
            ]
            
            for indicator in confirmation_indicators:
                if indicator in page_text:
                    print(f"   🚨 Checkpoint detected: '{indicator}'")
                    return True
            
            # Check URL patterns untuk challenge/confirmation
            challenge_url_patterns = ['/challenge', 'challenge', 'confirm', 'verify', 'security']
            if any(pattern in current_url for pattern in challenge_url_patterns):
                print(f"   🚨 Checkpoint URL detected: {current_url}")
                return True
            
            # Check untuk specific buttons yang indicate checkpoint
            checkpoint_buttons = [
                'button:has-text("Continue")',
                'button:has-text("Verify")', 
                'button:has-text("Confirm")',
                'button:has-text("Get Help")'
            ]
            
            for button_selector in checkpoint_buttons:
                if await page.query_selector(button_selector):
                    # Verify this is actually a checkpoint page, not just a normal button
                    page_text = await page.evaluate("() => document.body.innerText")
                    if any(indicator in page_text.lower() for indicator in confirmation_indicators):
                        print(f"   🚨 Checkpoint button detected: {button_selector}")
                        return True
                
            return False
            
        except Exception as e:
            print(f"   ⚠️ Human confirmation check error: {e}")
            return False

    async def _handle_human_confirmation(self, page) -> bool:
        """Handle human confirmation - IMMEDIATE STOP karena checkpoint"""
        print("   🚨 HUMAN CONFIRMATION DETECTED - ACCOUNT CHECKPOINTED")
        print("   ⚠️ Stopping registration - this account needs manual intervention")
        
        # Take screenshot untuk documentation
        try:
            timestamp = int(time.time())
            await page.screenshot(path=f"debug_checkpoint_{timestamp}.png", timeout=3000)
            print(f"   📸 Checkpoint screenshot saved: debug_checkpoint_{timestamp}.png")
        except Exception as e:
            print(f"   ⚠️ Could not take screenshot: {e}")
        
        # Log checkpoint details untuk analysis
        current_url = page.url
        page_title = await page.title()
        print(f"   🔗 URL: {current_url}")
        print(f"   📄 Title: {page_title}")
        
        return False

    async def _verify_after_human_confirmation(self, page) -> bool:
        """Verify what happens after clicking Continue on human confirmation"""
        print("   🔍 Verifying result after human confirmation...")
        
        max_wait = 15
        start_time = asyncio.get_event_loop().time()
        stuck_count = 0
        last_state = None
        
        while (asyncio.get_event_loop().time() - start_time) < max_wait:
            try:
                current_state = await self._get_page_state(page)
                
                # Stuck detection
                if current_state == last_state:
                    stuck_count += 1
                    if stuck_count >= 2:
                        print("   🚨 Stuck after human confirmation, may need refresh")
                        return False
                else:
                    stuck_count = 0
                    last_state = current_state
                
                # Check if we're successfully logged in (HOME page)
                if await self._is_on_home_page(page):
                    print("   🏠 SUCCESS: Account successfully logged in to home page!")
                    return True
                
                # Check if we hit a checkpoint
                if await self._is_on_checkpoint_page(page):
                    print("   🚨 CHECKPOINT: Account hit checkpoint after human confirmation")
                    return False
                
                # Check if we're still on human confirmation page (failed)
                if await self._check_human_confirmation_page(page):
                    print("   ⚠️ Still on human confirmation page, waiting...")
                    await asyncio.sleep(2)
                    continue
                
                # Check for other error states
                if await self._has_login_errors(page):
                    print("   ❌ Login error detected after human confirmation")
                    return False
                
                # If we're on some other page that's not home, checkpoint, or human confirmation
                current_url = page.url
                if "instagram.com" in current_url and "/accounts/login" not in current_url:
                    print(f"   🔄 On intermediate page: {current_url}, waiting...")
                
                await asyncio.sleep(2)
                
            except Exception as e:
                logger.error(f"Error during verification: {e}")
                await asyncio.sleep(2)
        
        print("   ⏰ Timeout verifying human confirmation result")
        # Final check
        return await self._is_on_home_page(page)

    async def _is_on_home_page(self, page) -> bool:
        """Check if we're successfully on Instagram home page"""
        try:
            # Check URL pattern for home page
            current_url = page.url.lower()
            
            # STRICT CHECK: These URLs are definitely NOT home page
            not_home_patterns = [
                '/accounts/login',
                '/accounts/emailsignup',
                '/accounts/signup',
                '/accounts/password',
                '/accounts/suspended',
                '/accounts/disabled',
                '/challenge',
                '/add',
                'confirm',
                'verification',
                'onetap'
            ]
            
            # If URL contains any of these patterns, NOT on home
            for pattern in not_home_patterns:
                if pattern in current_url:
                    return False
            
            # Must be on instagram.com
            if "instagram.com" not in current_url:
                return False
            
            # Home page should be at root or specific sections
            home_url_patterns = [
                'instagram.com/$',  # Exact root
                'instagram.com/?',  # Root with query params
                'instagram.com/explore',
                'instagram.com/direct',
                'instagram.com/reels',
            ]
            
            is_home_url = any(pattern.rstrip('$') in current_url for pattern in home_url_patterns)
            
            # Also check for profile URL pattern (username page after signup)
            # instagram.com/username (no slashes after username except for trailing)
            if re.match(r'https?://(?:www\.)?instagram\.com/[a-zA-Z0-9_.]+/?$', current_url):
                is_home_url = True
            
            if not is_home_url:
                # Check if it's the root domain
                parsed = urlparse(current_url)
                if parsed.path in ['/', ''] or parsed.path.startswith('/?'):
                    is_home_url = True
            
            if not is_home_url:
                return False
            
            # Check for home page indicators (UI elements)
            home_indicators = [
                'nav[role="navigation"]',
                'a[href*="/direct/inbox"]',
                'svg[aria-label="Home"]',
                'svg[aria-label="Beranda"]',  # Indonesian
                'a[href="/"]',
                'a[href="/explore/"]',
            ]
            
            for indicator in home_indicators:
                try:
                    element = await page.query_selector(indicator)
                    if element and await element.is_visible():
                        print(f"   ✅ Home page confirmed via: {indicator}")
                        return True
                except Exception:
                    continue
            
            # Additional check for feed content (only if URL looks like home)
            feed_selectors = [
                'article',
                'main[role="main"]',
                'section main',
            ]
            
            for selector in feed_selectors:
                try:
                    element = await page.query_selector(selector)
                    if element:
                        return True
                except Exception:
                    continue
            
            return False
        except Exception as e:
            logger.error(f"Error checking home page: {e}")
            return False

    async def _is_account_suspended(self, page) -> bool:
        """Check if account is suspended/disabled after OTP verification
        
        IMPORTANT: Only call this AFTER page has fully loaded (not during loading state)
        to avoid false positives from intermediate page states.
        """
        try:
            current_url = page.url.lower()
            content = await page.content()
            content_lower = content.lower()
            
            # First check: If we're on a success page (home/feed), definitely not suspended
            success_indicators = [
                'instagram.com/explore',
                'instagram.com/direct',
                '/accounts/onetap/'  # One-tap login page is success
            ]
            # Check if URL indicates home/success
            if 'instagram.com' in current_url and '/accounts/emailsignup' not in current_url:
                # Could be on home page - check for feed elements
                home_elements = await page.query_selector('nav, [role="navigation"], svg[aria-label="Home"]')
                if home_elements:
                    return False  # On home page, not suspended
            
            # URL patterns indicating suspension (must be specific to suspension pages)
            suspend_url_patterns = [
                '/suspended',
                '/disabled',
                '/appeal',
                '/blocked',
                '/restriction',
                '/challenge/action/suspended',
                '/accounts/suspended'
            ]
            
            if any(pattern in current_url for pattern in suspend_url_patterns):
                print("   🚫 ACCOUNT SUSPENDED - URL pattern detected")
                return True
            
            # Text indicators for suspended account - must be SPECIFIC phrases
            # Avoid generic terms that might appear on normal pages
            suspend_text_indicators = [
                'your account has been disabled',
                'your account has been suspended',
                'account is temporarily locked',
                'your account was disabled',
                'we suspended your account',
                'we\'ve disabled your account',
                'your account was removed',
                'your account is disabled',
                'your account was suspended',
                'we disable accounts',
                'appeal this decision',
                'request a review of this decision',
                'akun anda telah dinonaktifkan',  # Indonesian
                'akun anda ditangguhkan',
                'akun anda diblokir'
            ]
            
            # Count how many indicators match (need at least 1 for explicit suspend phrases)
            matched_indicators = []
            for indicator in suspend_text_indicators:
                if indicator in content_lower:
                    matched_indicators.append(indicator)
            
            if matched_indicators:
                print(f"   🚫 ACCOUNT SUSPENDED - Text indicators found: {matched_indicators[:3]}")
                return True
            
            # Check for specific suspended account page elements
            # REMOVED: 'a[href*="help.instagram.com"]' - too generic, appears on many pages
            suspend_selectors = [
                'text="Your account has been disabled"',
                'text="Your Account Has Been Disabled"',
                'text="Account Suspended"',
                'button:has-text("Request Review")',
                'button:has-text("Appeal")',
                '[data-testid="suspended-account-banner"]'
            ]
            
            for selector in suspend_selectors:
                try:
                    element = await page.query_selector(selector)
                    if element:
                        # Double-check it's visible
                        is_visible = await element.is_visible()
                        if is_visible:
                            print(f"   🚫 ACCOUNT SUSPENDED - Selector found: {selector}")
                            return True
                except Exception:
                    continue
            
            return False
            
        except Exception as e:
            logger.error(f"Error checking suspend status: {e}")
            return False

    async def _handle_suspended_account(self, page) -> dict:
        """Handle suspended account - return status and info"""
        try:
            result = {
                'is_suspended': True,
                'reason': 'Unknown',
                'can_appeal': False,
                'appeal_url': None
            }
            
            content = await page.content()
            content_lower = content.lower()
            
            # Try to extract suspension reason
            reasons = {
                'community guidelines': 'Violated community guidelines',
                'terms of service': 'Violated terms of service',
                'suspicious activity': 'Suspicious activity detected',
                'spam': 'Detected as spam',
                'compromised': 'Account may have been compromised',
                'automated': 'Automated behavior detected'
            }
            
            for keyword, reason in reasons.items():
                if keyword in content_lower:
                    result['reason'] = reason
                    break
            
            # Check if appeal is possible
            appeal_button = await page.query_selector('button:has-text("Appeal"), button:has-text("Request Review")')
            if appeal_button:
                result['can_appeal'] = True
                
            # Try to find appeal URL
            appeal_link = await page.query_selector('a[href*="help.instagram.com"], a[href*="appeal"]')
            if appeal_link:
                result['appeal_url'] = await appeal_link.get_attribute('href')
            
            print(f"   🚫 Suspension details:")
            print(f"      - Reason: {result['reason']}")
            print(f"      - Can Appeal: {result['can_appeal']}")
            if result['appeal_url']:
                print(f"      - Appeal URL: {result['appeal_url']}")
            
            return result
            
        except Exception as e:
            logger.error(f"Error handling suspended account: {e}")
            return {'is_suspended': True, 'reason': str(e)}

    async def _handle_suspend_recovery(self, page) -> str:
        """
        Handle suspend recovery by attempting human confirmation flow.
        
        Flow options:
        1. Suspend → Confirm Human (Continue) → Home = SUCCESS
        2. Suspend → Confirm Human (Continue) → Captcha → Continue → Home = SUCCESS
        3. Suspend → Confirm Human (Continue) → Captcha → Continue → Phone = PHONE_REQUIRED
        4. Cannot recover = FAILED
        
        Returns: 'success', 'continue', 'phone_required', or 'failed'
        """
        print("   🔄 Starting suspend recovery process...")
        
        try:
            max_recovery_steps = 10
            
            for step in range(max_recovery_steps):
                print(f"\n   📋 Recovery Step {step + 1}/{max_recovery_steps}")
                
                # Wait for loading to complete first
                await self._wait_for_loading_complete(page, timeout=15)
                current_url = page.url.lower()
                print(f"   🔗 URL: {current_url}")
                
                # Take screenshot for debugging every step
                try:
                    screenshot_path = f"./debug_recovery_step_{step + 1}.png"
                    await page.screenshot(path=screenshot_path)
                    print(f"   📸 Screenshot saved: {screenshot_path}")
                except Exception as e:
                    print(f"   ⚠️ Screenshot failed: {e}")
                
                # Check if we reached home page = SUCCESS
                if await self._is_on_home_page(page):
                    print("   🎉 Recovery SUCCESS: Reached home page!")
                    return 'success'
                
                # Check for phone verification requirement
                if await self._is_phone_verification_page(page):
                    print("   📱 Phone verification required")
                    return 'phone_required'
                
                # Check for captcha/image verification page
                if await self._is_captcha_page(page):
                    print("   🔢 Captcha page detected, attempting to solve...")
                    captcha_result = await self._handle_captcha_page(page)
                    if captcha_result:
                        # Captcha solved and reached home or still in progress
                        if await self._is_on_home_page(page):
                            return 'success'
                        # Check if we need phone verification after captcha
                        if await self._is_phone_verification_page(page):
                            return 'phone_required'
                        continue
                    else:
                        # Check if failed due to phone verification
                        if await self._is_phone_verification_page(page):
                            return 'phone_required'
                        print("   ❌ Captcha solving failed")
                        return 'failed'
                
                # Check for appeal in progress page - wait for redirect
                if await self._is_appeal_in_progress_page(page):
                    print("   ⏳ Appeal in progress, waiting for redirect...")
                    await asyncio.sleep(5)
                    continue
                
                # Check for "Confirm you're human" / human verification page
                if await self._is_human_confirmation_suspend_page(page):
                    print("   👤 Human confirmation page detected")
                    
                    # FIRST: Check if there's a captcha image that needs to be solved
                    captcha_solved = await self._handle_human_verification_captcha(page)
                    
                    if captcha_solved:
                        print("   ✅ Captcha solved, waiting for page update...")
                        await asyncio.sleep(2)
                        continue
                    
                    # If no captcha or captcha failed, try clicking Continue button
                    # Debug: List all buttons on the page
                    print("   🔍 Searching for buttons on page...")
                    all_buttons = await page.query_selector_all('button, [role="button"], a, div[tabindex="0"]')
                    print(f"   📊 Found {len(all_buttons)} clickable elements")
                    
                    for i, btn in enumerate(all_buttons[:10]):  # Show first 10
                        try:
                            text = (await btn.text_content() or "").strip()[:50]
                            is_visible = await btn.is_visible()
                            tag = await btn.evaluate("(el) => el.tagName")
                            print(f"      [{i}] {tag}: '{text}' (visible: {is_visible})")
                        except Exception:
                            pass
                    
                    clicked = await self._click_continue_button(page)
                    if clicked:
                        print("   ✅ Clicked Continue/Selanjutnya button")
                        await asyncio.sleep(2)
                        continue
                    else:
                        print("   ⚠️ Could not find Continue button, trying alternative strategies...")
                        
                        # Strategy 1: Try clicking any visible button
                        for btn in all_buttons:
                            try:
                                is_visible = await btn.is_visible()
                                if is_visible:
                                    text = (await btn.text_content() or "").strip().lower()
                                    # Skip known bad buttons
                                    if any(skip in text for skip in ['log in', 'masuk', 'help', 'bantuan', 'back', 'kembali']):
                                        continue
                                    await btn.click()
                                    print(f"   ✅ Clicked fallback button: '{text[:30]}'")
                                    await asyncio.sleep(2)
                                    break
                            except Exception:
                                continue
                        continue
                
                # Try to find and click any Continue/Next button
                clicked = await self._click_continue_button(page)
                if clicked:
                    print("   ✅ Clicked action button")
                    await asyncio.sleep(2)
                    continue
                
                # If we're still on suspended page with no action, try opening the link
                if '/suspended' in current_url or '/challenge' in current_url:
                    # Check if there's a specific action link
                    action_link = await page.query_selector('a[href*="challenge"], a[href*="confirm"]')
                    if action_link:
                        try:
                            await action_link.click()
                            print("   ✅ Clicked action link")
                            await asyncio.sleep(2)
                            continue
                        except Exception:
                            pass
                    
                    # Try clicking any link that looks like an action
                    links = await page.query_selector_all('a')
                    for link in links:
                        try:
                            is_visible = await link.is_visible()
                            href = await link.get_attribute('href') or ''
                            text = (await link.text_content() or '').strip().lower()
                            
                            if is_visible and href and not any(skip in text for skip in ['help', 'bantuan', 'privacy', 'terms']):
                                if 'instagram' in href or href.startswith('/'):
                                    print(f"   🔗 Trying link: {text[:30]} -> {href[:50]}")
                                    await link.click()
                                    await asyncio.sleep(2)
                                    break
                        except Exception:
                            continue
                
                # No progress made
                print("   ⏳ Waiting for page update...")
                await asyncio.sleep(3)
            
            # Max steps reached - do final check
            print("   ⏰ Recovery max steps reached, final check...")
            if await self._is_on_home_page(page):
                return 'success'
            if await self._is_phone_verification_page(page):
                return 'phone_required'
            return 'failed'
            
        except Exception as e:
            logger.error(f"Error in suspend recovery: {e}")
            return 'failed'

    async def _is_phone_verification_page(self, page) -> bool:
        """Check if we're on a phone verification page"""
        try:
            current_url = page.url.lower()
            
            # URL patterns for phone verification
            phone_url_patterns = ['/challenge/phone', '/phone', 'phonenumber', '/sms']
            if any(pattern in current_url for pattern in phone_url_patterns):
                return True
            
            # Check for phone input field
            phone_selectors = [
                'input[type="tel"]',
                'input[placeholder*="phone" i]',
                'input[placeholder*="nomor" i]',
                'input[name*="phone" i]',
                'input[aria-label*="phone" i]',
                'input[placeholder*="mobile" i]'
            ]
            
            for selector in phone_selectors:
                element = await page.query_selector(selector)
                if element and await element.is_visible():
                    return True
            
            # Check for phone-related text
            content = await page.evaluate("() => document.body.innerText")
            content_lower = content.lower()
            phone_indicators = [
                'enter phone number',
                'add phone number',
                'verify your phone',
                'masukkan nomor telepon',
                'tambahkan nomor telepon',
                'verifikasi nomor telepon',
                'we\'ll send you a code',
                'kirim kode ke nomor'
            ]
            
            if any(indicator in content_lower for indicator in phone_indicators):
                return True
            
            return False
        except Exception as e:
            logger.error(f"Error checking phone verification page: {e}")
            return False

    async def _is_captcha_page(self, page) -> bool:
        """Check if we're on a captcha/image verification page"""
        try:
            # First check URL for captcha/challenge patterns
            current_url = page.url.lower()
            if any(pattern in current_url for pattern in ['challenge', 'captcha', 'recaptcha']):
                return True
            
            # Check for captcha-related text FIRST (more reliable)
            content = await page.evaluate("() => document.body.innerText")
            content_lower = content.lower()
            
            # STRONG captcha indicators - if these are found, it's definitely captcha
            strong_captcha_indicators = [
                'type the code in the image',
                'ketik kode yang ada di gambar',
                'enter the text you see',
                'type the characters',
                'enter the code from the image',
                'masukkan kode yang terlihat di gambar'
            ]
            
            has_strong_indicator = any(indicator in content_lower for indicator in strong_captcha_indicators)
            
            if has_strong_indicator:
                # Wait a moment for image to potentially load
                await asyncio.sleep(1)
                
                # Confirm by checking for a visible image element
                captcha_image_selectors = [
                    'img[alt*="captcha" i]',
                    'img[alt*="security" i]',
                    'img[alt*="code" i]',
                    'img[src*="captcha" i]',
                    'img[src*="challenge" i]',
                    'canvas',
                    'form img'
                ]
                
                for selector in captcha_image_selectors:
                    try:
                        img_element = await page.query_selector(selector)
                        if img_element and await img_element.is_visible():
                            bbox = await img_element.bounding_box()
                            # Captcha images are typically medium sized
                            if bbox and 40 < bbox['width'] < 500 and 15 < bbox['height'] < 250:
                                print(f"   🔍 Captcha page confirmed (image found: {bbox['width']}x{bbox['height']})")
                                return True
                    except Exception:
                        continue
                
                # If we have strong text indicator but no image yet, might still be loading
                print("   ⚠️ Captcha text found but image not visible yet")
                return True  # Return true anyway, image might load later
            
            # WEAK indicators - need image confirmation
            weak_captcha_indicators = [
                'security check',
                'verify you are human',
                'pemeriksaan keamanan',
                'verifikasi bahwa anda manusia'
            ]
            
            has_weak_indicator = any(indicator in content_lower for indicator in weak_captcha_indicators)
            
            if has_weak_indicator:
                # But not if it's OTP confirmation code page
                if 'confirmation code' in content_lower or 'kode konfirmasi' in content_lower:
                    return False
                
                # Check for specific captcha elements
                captcha_selectors = [
                    'img[alt*="captcha" i]',
                    'img[alt*="security" i]',
                    '[data-testid="captcha"]',
                    'div[class*="captcha"]'
                ]
                
                for selector in captcha_selectors:
                    element = await page.query_selector(selector)
                    if element and await element.is_visible():
                        return True
            
            return False
        except Exception as e:
            logger.error(f"Error checking captcha page: {e}")
            return False

    async def _handle_captcha_page(self, page) -> bool:
        """Handle captcha page - try OCR first, then fallback to manual input"""
        try:
            print("   🔢 CAPTCHA DETECTED")
            
            # Wait for captcha image to appear before trying to detect it
            print("   ⏳ Waiting for captcha image to load...")
            captcha_image_data = await self._wait_for_captcha_image(page, timeout=15)
            captcha_code = None
            
            if captcha_image_data and HAVE_OCR:
                # Try OCR to read the captcha
                print("   🤖 Attempting OCR to read captcha...")
                captcha_code = await self._solve_captcha_with_ocr(captcha_image_data)
                
                if captcha_code:
                    print(f"   ✅ OCR detected code: {captcha_code}")
                else:
                    print("   ⚠️ OCR could not read captcha clearly")
            
            # If OCR failed or not available, try manual input
            if not captcha_code:
                # Take screenshot for reference
                try:
                    timestamp = int(time.time())
                    screenshot_path = f"captcha_{timestamp}.png"
                    await page.screenshot(path=screenshot_path, timeout=3000)
                    print(f"   📸 Captcha screenshot saved: {screenshot_path}")
                except Exception:
                    pass
                
                print("   📷 Manual input required")
                captcha_code = input("   ❓ Enter the captcha code from the image: ").strip()
                
                if not captcha_code:
                    print("   ⏭️ Captcha skipped by user")
                    return False
            
            # Find the captcha input field
            captcha_input = await self._find_captcha_input(page)
            
            if not captcha_input:
                print("   ❌ Could not find captcha input field")
                return False
            
            # Enter the captcha code
            await captcha_input.click()
            await asyncio.sleep(0.3)
            await captcha_input.fill("")
            await asyncio.sleep(0.2)
            await captcha_input.type(captcha_code, delay=50)
            await asyncio.sleep(0.5)
            
            print(f"   ✅ Captcha code entered: {captcha_code}")
            
            # Click continue/submit button
            clicked = await self._click_continue_button(page)
            if clicked:
                print("   ✅ Submitted captcha")
            else:
                # Try pressing Enter
                await page.keyboard.press('Enter')
                print("   ⌨️ Pressed Enter to submit captcha")
            
            await asyncio.sleep(2)
            await self._wait_for_loading_complete(page, timeout=15)
            
            # Check if captcha was wrong (still on same page with error)
            if await self._is_captcha_error(page):
                print("   ❌ Captcha was incorrect, retrying...")
                # Retry with manual input
                return await self._handle_captcha_retry(page)
            
            # After captcha, wait for result - could be appeal page or phone verification
            result = await self._wait_for_post_captcha_result(page)
            return result
                
        except Exception as e:
            logger.error(f"Error handling captcha: {e}")
            return False

    async def _get_captcha_image(self, page) -> Optional[bytes]:
        """Extract captcha image from page"""
        try:
            # Try to find captcha image element
            image_selectors = [
                'img[alt*="captcha" i]',
                'img[alt*="security" i]',
                'img[alt*="code" i]',
                'img[src*="captcha" i]',
                'img[src*="security" i]',
                'div[class*="captcha"] img',
                'form img',
                # Generic image near input field
                'img'
            ]
            
            for selector in image_selectors:
                try:
                    img_element = await page.query_selector(selector)
                    if img_element and await img_element.is_visible():
                        # Get bounding box to check if it's reasonably sized for captcha
                        bbox = await img_element.bounding_box()
                        if bbox and 50 < bbox['width'] < 500 and 20 < bbox['height'] < 200:
                            # Take screenshot of just the image element
                            image_bytes = await img_element.screenshot()
                            if image_bytes:
                                print(f"   📷 Captured captcha image ({bbox['width']}x{bbox['height']})")
                                return image_bytes
                except Exception:
                    continue
            
            # Fallback: Try to get image from canvas
            try:
                canvas = await page.query_selector('canvas')
                if canvas and await canvas.is_visible():
                    image_bytes = await canvas.screenshot()
                    if image_bytes:
                        print("   📷 Captured captcha from canvas")
                        return image_bytes
            except Exception:
                pass
            
            return None
        except Exception as e:
            logger.error(f"Error getting captcha image: {e}")
            return None

    async def _wait_for_captcha_image(self, page, timeout: int = 15) -> Optional[bytes]:
        """Wait for captcha image to fully load before attempting to read it"""
        print(f"   ⏳ Waiting up to {timeout}s for captcha image to load...")
        
        # Image selectors that could contain captcha
        captcha_image_selectors = [
            'img[alt*="captcha" i]',
            'img[alt*="security" i]',
            'img[alt*="code" i]',
            'img[src*="captcha" i]',
            'img[src*="security" i]',
            'img[src*="challenge" i]',
            'div[class*="captcha"] img',
            'form img',
            'canvas',
        ]
        
        start_time = time.time()
        check_interval = 0.5
        last_screenshot = None
        stable_count = 0
        
        while time.time() - start_time < timeout:
            elapsed = time.time() - start_time
            
            # Try each selector
            for selector in captcha_image_selectors:
                try:
                    element = await page.query_selector(selector)
                    if element and await element.is_visible():
                        # Check if it's the right size (not too small, not too large)
                        bbox = await element.bounding_box()
                        if bbox and 40 < bbox['width'] < 600 and 15 < bbox['height'] < 300:
                            # Wait for image to fully load (check if naturalWidth > 0)
                            try:
                                if selector != 'canvas':
                                    is_loaded = await element.evaluate("""
                                        (el) => {
                                            if (el.tagName === 'IMG') {
                                                return el.complete && el.naturalWidth > 0;
                                            }
                                            return true;
                                        }
                                    """)
                                    if not is_loaded:
                                        print(f"   ⏳ Image found but still loading... ({elapsed:.1f}s)")
                                        await asyncio.sleep(check_interval)
                                        continue
                            except Exception:
                                pass
                            
                            # Take a screenshot of the element
                            try:
                                current_screenshot = await element.screenshot()
                                if current_screenshot and len(current_screenshot) > 1000:  # Reasonable size check
                                    # Check if image is stable (same as previous)
                                    if last_screenshot and current_screenshot == last_screenshot:
                                        stable_count += 1
                                        if stable_count >= 2:  # Image stable for 2 consecutive checks
                                            print(f"   ✅ Captcha image loaded and stable ({bbox['width']}x{bbox['height']})")
                                            return current_screenshot
                                    else:
                                        stable_count = 0
                                        last_screenshot = current_screenshot
                                        print(f"   🔄 Captcha image updating... ({elapsed:.1f}s)")
                            except Exception as e:
                                print(f"   ⚠️ Failed to capture image: {e}")
                                
                except Exception:
                    continue
            
            # Wait before next check
            await asyncio.sleep(check_interval)
        
        # Timeout - try to get whatever image we can find
        print("   ⚠️ Timeout waiting for stable captcha image, trying to capture anyway...")
        return await self._get_captcha_image(page)

    async def _solve_captcha_with_ocr(self, image_data: bytes) -> Optional[str]:
        """Use OCR to read text/numbers from captcha image"""
        try:
            if not HAVE_OCR:
                return None
            
            # Load image from bytes
            image = Image.open(io.BytesIO(image_data))
            
            # Preprocess image for better OCR
            image = self._preprocess_captcha_image(image)
            
            # Try different OCR configurations
            configs = [
                # Numbers only (most common for Instagram captcha)
                '--psm 7 -c tessedit_char_whitelist=0123456789',
                # Single line, numbers only
                '--psm 8 -c tessedit_char_whitelist=0123456789',
                # Single word
                '--psm 8',
                # Sparse text
                '--psm 11 -c tessedit_char_whitelist=0123456789',
                # Default
                '--psm 7',
            ]
            
            for config in configs:
                try:
                    text = pytesseract.image_to_string(image, config=config)
                    # Clean up the result
                    cleaned = ''.join(c for c in text if c.isdigit())
                    
                    # Instagram captcha usually 4-8 digits
                    if 4 <= len(cleaned) <= 8:
                        print(f"   🔍 OCR result with config '{config}': {cleaned}")
                        return cleaned
                except Exception:
                    continue
            
            # Try alphanumeric if numeric didn't work
            try:
                text = pytesseract.image_to_string(image, config='--psm 7')
                cleaned = ''.join(c for c in text if c.isalnum())
                if 4 <= len(cleaned) <= 10:
                    print(f"   🔍 OCR alphanumeric result: {cleaned}")
                    return cleaned
            except Exception:
                pass
            
            return None
        except Exception as e:
            logger.error(f"OCR error: {e}")
            return None

    def _preprocess_captcha_image(self, image: 'Image.Image') -> 'Image.Image':
        """Preprocess captcha image for better OCR accuracy"""
        try:
            # Convert to grayscale
            if image.mode != 'L':
                image = image.convert('L')
            
            # Resize for better OCR (2x)
            width, height = image.size
            image = image.resize((width * 2, height * 2), Image.LANCZOS)
            
            # Increase contrast
            from PIL import ImageEnhance
            enhancer = ImageEnhance.Contrast(image)
            image = enhancer.enhance(2.0)
            
            # Binarize (convert to black and white)
            threshold = 128
            image = image.point(lambda p: 255 if p > threshold else 0)
            
            return image
        except Exception:
            return image

    async def _find_captcha_input(self, page) -> Optional[Any]:
        """Find the captcha input field with extensive debugging"""
        print("   🔍 Searching for captcha input field...")
        
        # First, let's see all visible input elements on the page for debugging
        try:
            all_inputs = await page.query_selector_all('input')
            visible_inputs = []
            for inp in all_inputs:
                try:
                    if await inp.is_visible():
                        placeholder = await inp.get_attribute('placeholder') or ''
                        aria_label = await inp.get_attribute('aria-label') or ''
                        name = await inp.get_attribute('name') or ''
                        input_type = await inp.get_attribute('type') or 'text'
                        visible_inputs.append({
                            'placeholder': placeholder,
                            'aria_label': aria_label,
                            'name': name,
                            'type': input_type
                        })
                except Exception:
                    continue
            
            if visible_inputs:
                print(f"   📋 Found {len(visible_inputs)} visible input(s):")
                for i, inp_info in enumerate(visible_inputs):
                    print(f"      [{i}] type={inp_info['type']}, placeholder='{inp_info['placeholder'][:50]}', name='{inp_info['name']}', aria='{inp_info['aria_label'][:30]}'")
            else:
                print("   ⚠️ No visible input elements found on page")
        except Exception as e:
            print(f"   ⚠️ Error listing inputs: {e}")
        
        # Expanded selectors with "image" keyword and more variations
        input_selectors = [
            # Most specific first - matching "Enter the code from the image"
            'input[placeholder*="image" i]',
            'input[placeholder*="code from" i]',
            'input[placeholder*="enter the code" i]',
            'input[aria-label*="image" i]',
            'input[aria-label*="code from" i]',
            # Standard captcha patterns
            'input[placeholder*="code" i]',
            'input[aria-label*="code" i]',
            'input[placeholder*="captcha" i]',
            'input[aria-label*="captcha" i]',
            'input[name*="captcha" i]',
            'input[name*="code" i]',
            'input[name*="response" i]',
            'input[id*="captcha" i]',
            'input[id*="code" i]',
            # Security check patterns
            'input[placeholder*="security" i]',
            'input[placeholder*="verify" i]',
            'input[placeholder*="confirmation" i]',
            # Generic text input on captcha-like pages
            'input[type="text"]:not([name*="email"]):not([name*="password"]):not([name*="username"])',
            'input[type="number"]',
            'input[type="tel"]',
            # Last resort - any visible text input
            'input:not([type="hidden"]):not([type="email"]):not([type="password"]):not([type="checkbox"]):not([type="submit"]):not([type="button"])'
        ]
        
        for selector in input_selectors:
            try:
                element = await page.query_selector(selector)
                if element and await element.is_visible():
                    placeholder = await element.get_attribute('placeholder') or 'none'
                    print(f"   ✅ Found captcha input with selector: {selector}")
                    print(f"      Placeholder: '{placeholder}'")
                    return element
            except Exception:
                continue
        
        print("   ❌ No captcha input found with any selector")
        return None

    async def _is_captcha_error(self, page) -> bool:
        """Check if there's a captcha error (wrong code entered)"""
        try:
            content = await page.evaluate("() => document.body.innerText")
            content_lower = content.lower()
            
            error_indicators = [
                'incorrect',
                'wrong',
                'invalid',
                'try again',
                'salah',
                'tidak valid',
                'coba lagi',
                'error'
            ]
            
            # Check if still on captcha page with error
            if await self._is_captcha_page(page):
                if any(indicator in content_lower for indicator in error_indicators):
                    return True
            
            return False
        except Exception:
            return False

    async def _handle_captcha_retry(self, page) -> bool:
        """Retry captcha with manual input after OCR failure"""
        print("   🔄 Retrying captcha with manual input...")
        
        try:
            # Take new screenshot
            timestamp = int(time.time())
            screenshot_path = f"captcha_retry_{timestamp}.png"
            await page.screenshot(path=screenshot_path, timeout=3000)
            print(f"   📸 New screenshot saved: {screenshot_path}")
        except Exception:
            pass
        
        # Manual input
        captcha_code = input("   ❓ Enter the captcha code (retry): ").strip()
        
        if not captcha_code:
            print("   ⏭️ Captcha retry skipped")
            return False
        
        # Find and fill input
        captcha_input = await self._find_captcha_input(page)
        if not captcha_input:
            print("   ❌ Could not find captcha input for retry")
            return False
        
        await captcha_input.click()
        await asyncio.sleep(0.3)
        await captcha_input.fill("")
        await asyncio.sleep(0.2)
        await captcha_input.type(captcha_code, delay=50)
        await asyncio.sleep(0.5)
        
        print(f"   ✅ Retry captcha entered: {captcha_code}")
        
        # Submit
        clicked = await self._click_continue_button(page)
        if not clicked:
            await page.keyboard.press('Enter')
        
        await asyncio.sleep(2)
        await self._wait_for_loading_complete(page, timeout=15)
        
        return await self._wait_for_post_captcha_result(page)

    async def _wait_for_post_captcha_result(self, page) -> bool:
        """Wait for result after captcha submission - appeal page or phone verification"""
        print("   ⏳ Waiting for post-captcha result...")
        
        max_wait_time = 120  # Max 2 minutes to wait for appeal to redirect
        start_time = asyncio.get_event_loop().time()
        
        while (asyncio.get_event_loop().time() - start_time) < max_wait_time:
            try:
                await self._wait_for_loading_complete(page, timeout=10)
                current_url = page.url.lower()
                elapsed = asyncio.get_event_loop().time() - start_time
                
                print(f"   🔍 Post-captcha check at {elapsed:.1f}s - URL: {current_url[:60]}...")
                
                # SUCCESS: Reached home page
                if await self._is_on_home_page(page):
                    print("   🎉 SUCCESS: Reached home page after captcha!")
                    return True
                
                # FAIL: Phone verification required - close session immediately
                if await self._is_phone_verification_page(page):
                    print("   📱 Phone verification required after captcha - closing session")
                    return False
                
                # IN PROGRESS: Appeal page - wait for redirect
                if await self._is_appeal_in_progress_page(page):
                    print("   ⏳ Appeal in progress, waiting for redirect to homepage...")
                    await asyncio.sleep(5)
                    continue
                
                # Still on some intermediate page
                await asyncio.sleep(3)
                
            except Exception as e:
                logger.error(f"Error in post-captcha wait: {e}")
                await asyncio.sleep(2)
        
        print("   ⏰ Timeout waiting for post-captcha result")
        # Final check
        if await self._is_on_home_page(page):
            return True
        return False

    async def _is_appeal_in_progress_page(self, page) -> bool:
        """Check if we're on an appeal in progress page"""
        try:
            content = await page.evaluate("() => document.body.innerText")
            content_lower = content.lower()
            
            appeal_indicators = [
                'appeal',
                'banding',
                'review',
                'sedang diproses',
                'sedang ditinjau',
                'in progress',
                'under review',
                'we\'re reviewing',
                'kami sedang meninjau',
                'request received',
                'permintaan diterima',
                'please wait',
                'mohon tunggu',
                'we\'ll let you know',
                'kami akan memberi tahu'
            ]
            
            if any(indicator in content_lower for indicator in appeal_indicators):
                # But not if we're on home page
                if not await self._is_on_home_page(page):
                    return True
            
            # Check URL for appeal patterns
            current_url = page.url.lower()
            if '/appeal' in current_url or '/review' in current_url or '/pending' in current_url:
                return True
            
            return False
        except Exception as e:
            logger.error(f"Error checking appeal page: {e}")
            return False

    async def _is_human_confirmation_suspend_page(self, page) -> bool:
        """Check if we're on a human confirmation page from suspend"""
        try:
            content = await page.evaluate("() => document.body.innerText")
            content_lower = content.lower()
            
            human_indicators = [
                'confirm you\'re human',
                'konfirmasi bahwa anda manusia',
                'verify you\'re human',
                'verifikasi bahwa anda manusia',
                'we need to confirm',
                'kami perlu memastikan',
                'security check',
                'pemeriksaan keamanan'
            ]
            
            if any(indicator in content_lower for indicator in human_indicators):
                return True
            
            # Also check URL
            current_url = page.url.lower()
            if '/challenge' in current_url or '/confirm' in current_url:
                return True
            
            return False
        except Exception as e:
            logger.error(f"Error checking human confirmation page: {e}")
            return False

    async def _handle_human_verification_captcha(self, page) -> bool:
        """Handle captcha on human verification page - read image, fill code, submit"""
        try:
            print("   🔍 Checking for captcha image on this page...")
            
            # DEBUG: First, let's see what's actually on this page
            print("   📋 DEBUG: Analyzing page structure...")
            
            # Check for iframes (captcha might be inside iframe)
            iframes = await page.query_selector_all('iframe')
            print(f"   📋 Found {len(iframes)} iframe(s)")
            for i, iframe in enumerate(iframes):
                try:
                    src = await iframe.get_attribute('src') or 'no-src'
                    print(f"      [{i}] iframe src: {src[:80]}")
                except Exception:
                    pass
            
            # Check for images on the page
            images = await page.query_selector_all('img')
            visible_images = []
            print(f"   📋 Found {len(images)} image(s) total")
            for img in images:
                try:
                    if await img.is_visible():
                        src = await img.get_attribute('src') or ''
                        alt = await img.get_attribute('alt') or ''
                        bbox = await img.bounding_box()
                        width = bbox['width'] if bbox else 0
                        height = bbox['height'] if bbox else 0
                        visible_images.append({'src': src[:50], 'alt': alt, 'w': width, 'h': height})
                except Exception:
                    continue
            
            if visible_images:
                print(f"   📋 Visible images ({len(visible_images)}):")
                for i, img_info in enumerate(visible_images):
                    print(f"      [{i}] {img_info['w']:.0f}x{img_info['h']:.0f} alt='{img_info['alt']}' src='{img_info['src']}'")
            
            # Check for canvas elements (some captchas use canvas)
            canvas = await page.query_selector_all('canvas')
            print(f"   📋 Found {len(canvas)} canvas element(s)")
            
            # Get page text content for debugging
            try:
                page_text = await page.evaluate("() => document.body.innerText")
                # Look for captcha-related text
                text_lower = page_text.lower()
                if 'code' in text_lower or 'image' in text_lower or 'captcha' in text_lower:
                    # Find relevant lines
                    lines = [l.strip() for l in page_text.split('\n') if l.strip()]
                    captcha_lines = [l for l in lines if any(kw in l.lower() for kw in ['code', 'image', 'enter', 'type', 'captcha'])]
                    if captcha_lines:
                        print(f"   📋 Captcha-related text found:")
                        for line in captcha_lines[:5]:
                            print(f"      '{line[:60]}'")
            except Exception:
                pass
            
            # First, check if there's an input field for captcha code
            captcha_input = await self._find_captcha_input(page)
            if not captcha_input:
                print("   ℹ️ No captcha input field found - may not be a captcha page")
                return False
            
            # Check if input already has a value
            current_value = await captcha_input.input_value()
            if current_value and len(current_value) >= 4:
                print(f"   ℹ️ Captcha input already has value: {current_value}")
                # Try to submit
                clicked = await self._click_continue_button(page)
                if clicked:
                    print("   ✅ Clicked submit after existing captcha value")
                    return True
                return False
            
            print("   🔍 Looking for captcha image...")
            
            # Wait for captcha image to load
            captcha_image_data = await self._wait_for_captcha_image(page, timeout=10)
            
            if not captcha_image_data:
                print("   ⚠️ No captcha image found")
                return False
            
            print("   ✅ Captcha image captured!")
            
            # Save screenshot for debugging
            try:
                timestamp = int(time.time())
                screenshot_path = f"./debug_captcha_{timestamp}.png"
                await page.screenshot(path=screenshot_path, timeout=3000)
                print(f"   📸 Captcha page screenshot: {screenshot_path}")
            except Exception:
                pass
            
            captcha_code = None
            
            # Try OCR to read the captcha
            if HAVE_OCR:
                print("   🤖 Attempting OCR to read captcha...")
                captcha_code = await self._solve_captcha_with_ocr(captcha_image_data)
                
                if captcha_code:
                    print(f"   ✅ OCR detected code: {captcha_code}")
                else:
                    print("   ⚠️ OCR could not read captcha clearly")
            else:
                print("   ⚠️ OCR not available (pytesseract not installed)")
            
            # If OCR failed, ask for manual input
            if not captcha_code:
                print("   📷 Manual input required for captcha")
                try:
                    captcha_code = input("   ❓ Enter the captcha code from the image: ").strip()
                except Exception:
                    print("   ⚠️ Cannot get manual input")
                    return False
                
                if not captcha_code:
                    print("   ⏭️ Captcha skipped by user")
                    return False
            
            # Clear and fill the captcha input
            print(f"   ⌨️ Entering captcha code: {captcha_code}")
            await captcha_input.click()
            await asyncio.sleep(0.3)
            
            # Clear any existing value
            await captcha_input.fill("")
            await asyncio.sleep(0.2)
            
            # Type the captcha code
            await captcha_input.type(captcha_code, delay=50)
            await asyncio.sleep(0.5)
            
            print(f"   ✅ Captcha code entered: {captcha_code}")
            
            # Now click the Continue/Submit button
            await asyncio.sleep(0.5)
            clicked = await self._click_continue_button(page)
            
            if clicked:
                print("   ✅ Clicked submit button after captcha")
            else:
                # Try pressing Enter
                print("   ⌨️ Pressing Enter to submit captcha...")
                await page.keyboard.press('Enter')
            
            # Wait for page to update
            await asyncio.sleep(2)
            await self._wait_for_loading_complete(page, timeout=10)
            
            # Check if captcha was wrong (error message or still on same page with input)
            if await self._is_captcha_error(page):
                print("   ❌ Captcha was incorrect")
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"Error handling human verification captcha: {e}")
            return False

    async def _click_continue_button(self, page) -> bool:
        """Click Continue/Selanjutnya/Next button"""
        try:
            # Multi-language button texts
            button_texts = [
                'Continue',
                'Selanjutnya',
                'Next',
                'Lanjutkan',
                'Submit',
                'Kirim',
                'Verify',
                'Verifikasi',
                'Confirm',
                'Konfirmasi',
                'OK',
                'Done',
                'Selesai'
            ]
            
            for text in button_texts:
                # Try exact match first
                button = await page.query_selector(f'button:has-text("{text}")')
                if button:
                    try:
                        is_visible = await button.is_visible()
                        is_enabled = await button.is_enabled()
                        if is_visible and is_enabled:
                            await button.click()
                            return True
                    except Exception:
                        continue
                
                # Try role button
                button = await page.query_selector(f'[role="button"]:has-text("{text}")')
                if button:
                    try:
                        is_visible = await button.is_visible()
                        if is_visible:
                            await button.click()
                            return True
                    except Exception:
                        continue
                
                # Try div that looks like button
                button = await page.query_selector(f'div:has-text("{text}"):not(:has(div:has-text("{text}")))')
                if button:
                    try:
                        is_visible = await button.is_visible()
                        if is_visible:
                            await button.click()
                            return True
                    except Exception:
                        continue
            
            # Try submit button
            submit_btn = await page.query_selector('button[type="submit"]')
            if submit_btn:
                try:
                    is_visible = await submit_btn.is_visible()
                    is_enabled = await submit_btn.is_enabled()
                    if is_visible and is_enabled:
                        await submit_btn.click()
                        return True
                except Exception:
                    pass
            
            return False
        except Exception as e:
            logger.error(f"Error clicking continue button: {e}")
            return False

    async def _handle_stuck_loading(self, page, otp_code: str) -> bool:
        """Handle stuck loading by reloading page and re-entering OTP code"""
        try:
            print("   🔄 Handling stuck loading - reloading page...")
            
            # Reload the page
            await page.reload()
            await asyncio.sleep(3)
            
            # Check if we're still on OTP page
            otp_input = await page.query_selector('input[placeholder*="Confirmation Code" i], input[aria-label*="Confirmation Code" i]')
            
            if otp_input:
                print("   📝 Re-entering OTP code after reload...")
                await otp_input.click()
                await asyncio.sleep(0.3)
                await otp_input.fill("")
                await asyncio.sleep(0.2)
                await otp_input.type(otp_code, delay=80)
                await asyncio.sleep(1)
                
                # Submit again
                submit_btn = await page.query_selector('button:has-text("Continue"), button:has-text("Next"), button[type="submit"], button:has-text("Finish")')
                if submit_btn:
                    await submit_btn.click()
                else:
                    await page.keyboard.press('Enter')
                
                print("   ✅ OTP re-submitted after reload")
                return True
            else:
                # Might have successfully navigated
                if await self._is_on_home_page(page):
                    return True
                elif await self._is_account_suspended(page):
                    return False
                    
            return False
            
        except Exception as e:
            logger.error(f"Error handling stuck loading: {e}")
            return False

    async def _verify_post_otp_result(self, page) -> str:
        """Verify the result after OTP - returns 'success', 'suspended', 'checkpoint', or 'unknown'"""
        try:
            await asyncio.sleep(2)
            
            # Check for success first (home page)
            if await self._is_on_home_page(page):
                print("   ✅ POST-OTP: Successfully on home page!")
                return 'success'
            
            # Check for suspended account
            if await self._is_account_suspended(page):
                print("   🚫 POST-OTP: Account is suspended!")
                return 'suspended'
            
            # Check for checkpoint
            if await self._is_on_checkpoint_page(page):
                print("   ⚠️ POST-OTP: Checkpoint detected!")
                return 'checkpoint'
            
            # Check URL for other indications
            current_url = page.url.lower()
            
            if 'instagram.com/' in current_url and 'accounts' not in current_url:
                # Might be on a profile or other valid page
                print("   ✅ POST-OTP: On valid Instagram page")
                return 'success'
            
            return 'unknown'
            
        except Exception as e:
            logger.error(f"Error verifying post-OTP result: {e}")
            return 'unknown'

    async def _detect_post_otp_fields(self, page) -> dict:
        """Detect if there are additional fields to fill after OTP verification
        
        Some Instagram flows show fullname/username fields AFTER OTP verification.
        Flow: Email → Password → Birthday → OTP → Full Name → Username
        """
        try:
            fields = {}
            
            # Check if we're still on a signup-related page
            current_url = page.url.lower()
            if 'emailsignup' not in current_url and 'accounts' not in current_url:
                return {}  # Not on signup page, no post-OTP fields
            
            # Look for fullname field (empty/unfilled)
            fullname_selectors = [
                'input[name="fullName"]',
                'input[aria-label*="Full Name" i]',
                'input[placeholder*="Full Name" i]',
                'input[aria-label*="Nama Lengkap" i]',
                'input[placeholder*="Nama Lengkap" i]',
            ]
            
            for selector in fullname_selectors:
                try:
                    element = await page.query_selector(selector)
                    if element:
                        is_visible = await element.is_visible()
                        current_value = await element.get_attribute('value') or ''
                        if is_visible and not current_value.strip():
                            fields['fullname'] = element
                            print(f"   📝 Found empty fullname field: {selector}")
                            break
                except Exception:
                    continue
            
            # Look for username field (empty/unfilled)
            username_selectors = [
                'input[name="username"]',
                'input[aria-label*="Username" i]',
                'input[placeholder*="Username" i]',
                'input[aria-label*="Nama Pengguna" i]',
                'input[placeholder*="Nama Pengguna" i]',
            ]
            
            for selector in username_selectors:
                try:
                    element = await page.query_selector(selector)
                    if element:
                        is_visible = await element.is_visible()
                        current_value = await element.get_attribute('value') or ''
                        if is_visible and not current_value.strip():
                            fields['username'] = element
                            print(f"   📝 Found empty username field: {selector}")
                            break
                except Exception:
                    continue
            
            # Only return if we found at least one field AND no OTP input visible
            otp_input = await page.query_selector('input[placeholder*="Confirmation Code" i], input[aria-label*="Confirmation Code" i]')
            if otp_input:
                otp_visible = await otp_input.is_visible()
                if otp_visible:
                    return {}  # Still on OTP page, not post-OTP
            
            return fields
            
        except Exception as e:
            logger.error(f"Error detecting post-OTP fields: {e}")
            return {}

    async def _fill_post_otp_fields(self, page, fields: dict) -> bool:
        """Fill the additional fields that appear after OTP verification"""
        try:
            filled_count = 0
            
            # Fill fullname if found
            if 'fullname' in fields:
                try:
                    element = fields['fullname']
                    await element.click()
                    await asyncio.sleep(0.3)
                    await element.fill("")
                    await asyncio.sleep(0.2)
                    await element.type(self.full_name, delay=50)
                    print(f"   ✅ POST-OTP: Filled full name: {self.full_name}")
                    filled_count += 1
                    await asyncio.sleep(0.5)
                except Exception as e:
                    print(f"   ⚠️ Failed to fill fullname: {e}")
            
            # Fill username if found
            if 'username' in fields:
                try:
                    element = fields['username']
                    await element.click()
                    await asyncio.sleep(0.3)
                    await element.fill("")
                    await asyncio.sleep(0.2)
                    await element.type(self.username, delay=50)
                    print(f"   ✅ POST-OTP: Filled username: {self.username}")
                    filled_count += 1
                    await asyncio.sleep(0.5)
                except Exception as e:
                    print(f"   ⚠️ Failed to fill username: {e}")
            
            return filled_count > 0
            
        except Exception as e:
            logger.error(f"Error filling post-OTP fields: {e}")
            return False

    async def _click_post_otp_continue(self, page) -> bool:
        """Click continue/next button after filling post-OTP fields"""
        try:
            # Look for continue/next/signup buttons
            button_selectors = [
                'button:has-text("Continue")',
                'button:has-text("Next")',
                'button:has-text("Sign up")',
                'button:has-text("Lanjutkan")',
                'button:has-text("Daftar")',
                'button[type="submit"]',
            ]
            
            for selector in button_selectors:
                try:
                    button = await page.query_selector(selector)
                    if button:
                        is_visible = await button.is_visible()
                        is_enabled = await button.is_enabled()
                        if is_visible and is_enabled:
                            await button.click()
                            print(f"   ✅ POST-OTP: Clicked button: {selector}")
                            return True
                except Exception:
                    continue
            
            # Fallback to Enter key
            await page.keyboard.press('Enter')
            print("   ⌨️ POST-OTP: Pressed Enter key")
            return True
            
        except Exception as e:
            logger.error(f"Error clicking post-OTP continue: {e}")
            return False

    async def _detect_and_fill_current_page(self, page, otp_code: str = None) -> str:
        """
        Detect what's on current page and fill any fields found.
        
        Returns:
            'filled' - fields were filled and submitted
            'otp_entered' - OTP code was entered
            'no_fields' - no fillable fields found
            'error' - error occurred
        """
        try:
            print("   📋 Detecting current page fields...")
            
            # ========== 1. CHECK FOR OTP INPUT ==========
            otp_input = await page.query_selector('input[placeholder*="Confirmation Code" i], input[aria-label*="Confirmation Code" i], input[placeholder*="Kode Konfirmasi" i]')
            if otp_input:
                is_visible = await otp_input.is_visible()
                current_value = await otp_input.get_attribute('value') or ''
                
                if is_visible and not current_value.strip() and otp_code:
                    print("   📧 OTP input found - entering code...")
                    await otp_input.click()
                    await asyncio.sleep(0.3)
                    await otp_input.fill("")
                    await asyncio.sleep(0.2)
                    await otp_input.type(otp_code, delay=80)
                    await asyncio.sleep(0.5)
                    
                    # Click submit
                    submit_btn = await page.query_selector('button:has-text("Continue"), button:has-text("Next"), button[type="submit"], button:has-text("Confirm")')
                    if submit_btn:
                        await submit_btn.click()
                    else:
                        await page.keyboard.press('Enter')
                    
                    return 'otp_entered'
            
            # ========== 2. CHECK FOR STANDARD FORM FIELDS ==========
            fields_found = {}
            fields_filled = 0
            
            # Email field
            email_selectors = ['input[name="emailOrPhone"]', 'input[aria-label*="Email" i]', 'input[placeholder*="Email" i]', 'input[type="email"]']
            for selector in email_selectors:
                el = await page.query_selector(selector)
                if el and await el.is_visible():
                    val = await el.get_attribute('value') or ''
                    if not val.strip():
                        fields_found['email'] = el
                        break
            
            # Password field
            password_selectors = ['input[name="password"]', 'input[aria-label*="Password" i]', 'input[placeholder*="Password" i]', 'input[type="password"]']
            for selector in password_selectors:
                el = await page.query_selector(selector)
                if el and await el.is_visible():
                    val = await el.get_attribute('value') or ''
                    if not val.strip():
                        fields_found['password'] = el
                        break
            
            # Full name field
            fullname_selectors = ['input[name="fullName"]', 'input[aria-label*="Full Name" i]', 'input[placeholder*="Full Name" i]', 'input[aria-label*="Nama Lengkap" i]']
            for selector in fullname_selectors:
                el = await page.query_selector(selector)
                if el and await el.is_visible():
                    val = await el.get_attribute('value') or ''
                    if not val.strip():
                        fields_found['fullname'] = el
                        break
            
            # Username field
            username_selectors = ['input[name="username"]', 'input[aria-label*="Username" i]', 'input[placeholder*="Username" i]', 'input[aria-label*="Nama Pengguna" i]']
            for selector in username_selectors:
                el = await page.query_selector(selector)
                if el and await el.is_visible():
                    val = await el.get_attribute('value') or ''
                    if not val.strip():
                        fields_found['username'] = el
                        break
            
            # Birthday fields (month, day, year) - only select/combobox
            birthday_selectors = [
                ('month', 'select[aria-label*="Month" i], select[title*="Month" i], [role="combobox"][aria-label*="Month" i]'),
                ('day', 'select[aria-label*="Day" i], select[title*="Day" i], [role="combobox"][aria-label*="Day" i]'),
                ('year', 'select[aria-label*="Year" i], select[title*="Year" i], [role="combobox"][aria-label*="Year" i]'),
            ]
            
            for field_type, selector in birthday_selectors:
                el = await page.query_selector(selector)
                if el and await el.is_visible():
                    # Check if it's at default value
                    tag = await el.evaluate('el => el.tagName.toLowerCase()')
                    if tag == 'select':
                        selected_index = await el.evaluate('el => el.selectedIndex')
                        if selected_index == 0:  # Usually first option is placeholder
                            fields_found[field_type] = el
                    else:
                        fields_found[field_type] = el
            
            print(f"   📊 Fields found: {list(fields_found.keys())}")
            
            if not fields_found:
                return 'no_fields'
            
            # ========== 3. FILL THE FIELDS ==========
            if 'email' in fields_found:
                try:
                    el = fields_found['email']
                    await el.click()
                    await asyncio.sleep(0.2)
                    await el.fill(self.email_new)
                    print(f"   ✅ Filled email: {self.email_new}")
                    fields_filled += 1
                except Exception as e:
                    print(f"   ⚠️ Failed to fill email: {e}")
            
            if 'password' in fields_found:
                try:
                    el = fields_found['password']
                    await el.click()
                    await asyncio.sleep(0.2)
                    await el.fill(self.password)
                    print(f"   ✅ Filled password")
                    fields_filled += 1
                except Exception as e:
                    print(f"   ⚠️ Failed to fill password: {e}")
            
            if 'fullname' in fields_found:
                try:
                    el = fields_found['fullname']
                    await el.click()
                    await asyncio.sleep(0.2)
                    await el.fill(self.full_name)
                    print(f"   ✅ Filled fullname: {self.full_name}")
                    fields_filled += 1
                except Exception as e:
                    print(f"   ⚠️ Failed to fill fullname: {e}")
            
            if 'username' in fields_found:
                try:
                    el = fields_found['username']
                    await el.click()
                    await asyncio.sleep(0.2)
                    await el.fill(self.username)
                    print(f"   ✅ Filled username: {self.username}")
                    fields_filled += 1
                except Exception as e:
                    print(f"   ⚠️ Failed to fill username: {e}")
            
            # Fill birthday fields
            if any(k in fields_found for k in ['month', 'day', 'year']):
                birthday_filled = await self._fill_birthday_fields_v3(page)
                if birthday_filled:
                    print("   ✅ Filled birthday fields")
                    fields_filled += 1
            
            if fields_filled > 0:
                # Wait for button to be ready (not loading)
                print("   ⏳ Waiting for submit button to be ready...")
                await self._wait_for_button_ready(page, timeout=10)
                
                # Click submit button
                await asyncio.sleep(0.5)
                clicked = await self._click_post_otp_continue(page)
                
                if clicked:
                    # Wait a moment for loading to start
                    await asyncio.sleep(1)
                
                return 'filled'
            
            return 'no_fields'
            
        except Exception as e:
            logger.error(f"Error detecting/filling page: {e}")
            return 'error'

    async def _try_unstuck_action(self, page) -> bool:
        """Try to unstuck page by clicking any visible action button"""
        try:
            # Look for any clickable button that might progress the flow
            button_selectors = [
                'button:has-text("Continue")',
                'button:has-text("Next")',
                'button:has-text("Lanjutkan")',
                'button:has-text("OK")',
                'button:has-text("Done")',
                'button:has-text("Confirm")',
                'button[type="submit"]',
            ]
            
            for selector in button_selectors:
                try:
                    button = await page.query_selector(selector)
                    if button:
                        is_visible = await button.is_visible()
                        is_enabled = await button.is_enabled()
                        if is_visible and is_enabled:
                            btn_text = await button.text_content()
                            # Skip known skip words
                            skip_words = ['why', 'learn', 'help', 'terms', 'privacy', 'back', 'cancel']
                            if not any(sw in (btn_text or '').lower() for sw in skip_words):
                                await button.click()
                                print(f"   🔄 Unstuck: Clicked '{btn_text}'")
                                return True
                except Exception:
                    continue
            
            # Try pressing Enter
            await page.keyboard.press('Enter')
            print("   🔄 Unstuck: Pressed Enter")
            return True
            
        except Exception as e:
            logger.error(f"Error trying unstuck action: {e}")
            return False

    async def _is_on_checkpoint_page(self, page) -> bool:
        """Check if we're on Instagram checkpoint/challenge page"""
        try:
            # Check URL for challenge
            current_url = page.url
            if "/challenge" in current_url or "challenge" in current_url:
                return True
            
            # Check for checkpoint text
            checkpoint_indicators = [
                'text=We detected something unusual',
                'text=Confirm Its You',
                'text=Help us confirm',
                'text=Security Check',
                'text=Suspicious Login Attempt',
                'text=Get help signing in',
                'input[name="email"]',  # Challenge email input
                'button:has-text("Send Code")',
                'button:has-text("Get Code")'
            ]
            
            for indicator in checkpoint_indicators:
                if await page.query_selector(indicator):
                    return True
            
            return False
        except Exception as e:
            logger.error(f"Error checking checkpoint page: {e}")
            return False

    async def _has_login_errors(self, page) -> bool:
        """Check for login error messages"""
        try:
            error_indicators = [
                'text=Please check the code we sent you',
                'text=Invalid code',
                'text=Wrong code',
                'text=Try again',
                'text=Error',
                'div[role="alert"]',
                'p[id*="error"]'
            ]
            
            for indicator in error_indicators:
                if await page.query_selector(indicator):
                    return True
            
            return False
        except Exception as e:
            logger.error(f"Error checking login errors: {e}")
            return False

    async def _is_page_loading(self, page) -> bool:
        """Check if page is in loading state - comprehensive detection"""
        try:
            # ========== 1. PAGE-LEVEL LOADING INDICATORS ==========
            page_loading_selectors = [
                # General loading spinners
                '[aria-busy="true"]',
                '[class*="loading"]',
                '[class*="spinner"]',
                '[class*="Loading"]',
                '[class*="Spinner"]',
                '._a9_1',  # Instagram specific
                
                # SVG loading indicators
                'svg[aria-label="Loading..."]',
                'svg[aria-label="Loading"]',
                'svg[aria-label*="loading" i]',
                
                # Skeleton/placeholder loading
                '[class*="skeleton"]',
                '[class*="Skeleton"]',
                '[class*="placeholder"]',
                
                # Progress indicators
                '[role="progressbar"]',
                '[class*="progress"]',
            ]
            
            for selector in page_loading_selectors:
                try:
                    el = await page.query_selector(selector)
                    if el:
                        is_visible = await el.is_visible()
                        if is_visible:
                            return True
                except Exception:
                    continue
            
            # ========== 2. BUTTON LOADING INDICATORS ==========
            # Check if any submit button is in loading state
            button_selectors = [
                'button[type="submit"]',
                'button:has-text("Continue")',
                'button:has-text("Next")',
                'button:has-text("Sign up")',
                'button:has-text("Confirm")',
            ]
            
            for selector in button_selectors:
                try:
                    button = await page.query_selector(selector)
                    if button:
                        # Check if button is disabled (loading state)
                        is_disabled = await button.is_disabled()
                        
                        # Check for spinner inside button
                        spinner_inside = await button.query_selector('[class*="spinner"], [class*="loading"], svg[aria-label*="loading" i]')
                        
                        # Check aria-busy on button
                        aria_busy = await button.get_attribute('aria-busy')
                        
                        # Check for loading class on button
                        button_class = await button.get_attribute('class') or ''
                        has_loading_class = 'loading' in button_class.lower() or 'disabled' in button_class.lower()
                        
                        if is_disabled or spinner_inside or aria_busy == 'true' or has_loading_class:
                            return True
                except Exception:
                    continue
            
            # ========== 3. URL-BASED LOADING ==========
            if page.url.endswith('/loading/') or '/loading' in page.url.lower():
                return True
            
            # ========== 4. DOCUMENT READY STATE ==========
            try:
                ready_state = await page.evaluate('document.readyState')
                if ready_state != 'complete':
                    return True
            except Exception:
                pass
            
            return False
            
        except Exception as e:
            logger.error(f"Error checking loading state: {e}")
            return False

    async def _wait_for_loading_complete(self, page, timeout: int = 30) -> bool:
        """Wait until page loading is complete"""
        try:
            start_time = asyncio.get_event_loop().time()
            check_count = 0
            
            while (asyncio.get_event_loop().time() - start_time) < timeout:
                check_count += 1
                
                if not await self._is_page_loading(page):
                    # Double check after short delay
                    await asyncio.sleep(0.5)
                    if not await self._is_page_loading(page):
                        print(f"   ✅ Loading complete after {check_count} checks")
                        return True
                
                elapsed = asyncio.get_event_loop().time() - start_time
                print(f"   ⏳ Waiting for loading... ({elapsed:.1f}s)")
                await asyncio.sleep(2)
            
            print(f"   ⚠️ Loading timeout after {timeout}s")
            return False
            
        except Exception as e:
            logger.error(f"Error waiting for loading: {e}")
            return False

    async def _wait_for_button_ready(self, page, button_selector: str = None, timeout: int = 15) -> bool:
        """Wait for submit button to be ready (not loading/disabled)"""
        try:
            start_time = asyncio.get_event_loop().time()
            
            # Default button selectors if not specified
            if not button_selector:
                button_selectors = [
                    'button[type="submit"]',
                    'button:has-text("Continue")',
                    'button:has-text("Next")',
                    'button:has-text("Sign up")',
                ]
            else:
                button_selectors = [button_selector]
            
            while (asyncio.get_event_loop().time() - start_time) < timeout:
                for selector in button_selectors:
                    try:
                        button = await page.query_selector(selector)
                        if button:
                            is_visible = await button.is_visible()
                            is_enabled = await button.is_enabled()
                            
                            # Check for loading state inside button
                            spinner = await button.query_selector('[class*="spinner"], [class*="loading"]')
                            aria_busy = await button.get_attribute('aria-busy')
                            
                            if is_visible and is_enabled and not spinner and aria_busy != 'true':
                                return True
                    except Exception:
                        continue
                
                await asyncio.sleep(1)
            
            return False
            
        except Exception as e:
            logger.error(f"Error waiting for button: {e}")
            return False

    async def _strict_success_check(self, page, elapsed_time: float) -> bool:
        """STRICT success verification - FIXED untuk menghindari false positive"""
        current_url = page.url.lower()
        current_title = (await page.title()).lower()
        content = await page.content()
        content_lower = content.lower()
        
        # ========== MUST-HAVE INDICATORS ==========
        
        # 1. URL MUST be a real Instagram page (NOT signup/verification)
        verification_urls = ['emailsignup', 'accounts/emailsignup', 'challenge', 'verify']
        is_still_on_verification = any(url in current_url for url in verification_urls)
        
        real_instagram_urls = [
            'instagram.com/',
            'instagram.com/home',
            'instagram.com/feed', 
            'instagram.com/direct/inbox',
            'instagram.com/explore',
            'instagram.com/accounts/edit'
        ]
        is_on_real_instagram = any(url in current_url for url in real_instagram_urls)
        
        # 2. MUST have logged-in UI elements
        logged_in_elements = [
            await page.query_selector('[data-testid="nav-profile"]'),  # Profile icon
            await page.query_selector('[aria-label="Home"]'),  # Home button
            await page.query_selector('nav[role="navigation"]'),  # Main nav
        ]
        
        visible_logged_in_elements = 0
        for element in logged_in_elements:
            if element and await element.is_visible():
                visible_logged_in_elements += 1
        
        # 3. MUST NOT have OTP elements anymore
        otp_elements = [
            await page.query_selector('input[placeholder*="Confirmation Code" i]'),
            await page.query_selector('input[aria-label*="Confirmation Code" i]'),
            await page.query_selector('button:has-text("Resend")'),
        ]
        
        has_otp_elements = any(otp_elements)
        
        # ========== SUCCESS CRITERIA ==========
        success_criteria = [
            # Must be on real Instagram page
            is_on_real_instagram,
            
            # Must have at least 2 logged-in UI elements visible
            visible_logged_in_elements >= 2,  # Reduced from 3 to 2
            
            # Must NOT have OTP elements
            not has_otp_elements,
            
            # Must NOT be on verification pages
            not is_still_on_verification,
            
            # Additional content checks (optional)
            'welcome to instagram' in content_lower or 'get started' in content_lower,
        ]
        
        # Must meet at least 3 out of 5 criteria (reduced from 4)
        met_criteria = sum(success_criteria)
        print(f"   📊 Strict check: {met_criteria}/5 criteria met")
        
        # Debug info
        if met_criteria >= 3:
            print(f"   🔍 Success details: URL={is_on_real_instagram}, Elements={visible_logged_in_elements}, NoOTP={not has_otp_elements}")
        
        return met_criteria >= 3  # Reduced threshold

    async def _is_definite_failure(self, page, elapsed_time: float) -> bool:
        """Check for definite failure conditions"""
        current_url = page.url.lower()
        content = await page.content()
        content_lower = content.lower()
        
        # Error messages
        error_keywords = ['invalid', 'wrong', 'error', 'incorrect', 'try again', 'expired', 'too many attempts']
        error_elements = await page.query_selector_all('[aria-invalid="true"], [class*="error"], [class*="invalid"], [role="alert"]')
        
        for element in error_elements:
            error_text = await element.text_content()
            if error_text and any(keyword in error_text.lower() for keyword in error_keywords):
                print(f"   🚨 DEFINITE FAILURE: {error_text.strip()}")
                return True
        
        # Still on OTP page after long time with no progress
        if any(url in current_url for url in ['challenge', 'verify', 'emailsignup']) and elapsed_time > 25:
            # BUT check if this is a post-OTP page with fullname/username fields
            post_otp_fields = await self._detect_post_otp_fields(page)
            if post_otp_fields:
                print(f"   📝 Not failure - POST-OTP page with fields: {list(post_otp_fields.keys())}")
                return False  # Not a failure, just needs more fields
            
            print("   ❌ DEFINITE FAILURE: Stuck on verification page >25s")
            return True
        
        # OTP field disappeared but we're not on success page
        otp_field = await page.query_selector('input[placeholder*="Confirmation Code" i]')
        if not otp_field and any(url in current_url for url in ['challenge', 'verify', 'emailsignup']):
            # Check if this is a post-OTP page with fullname/username fields
            post_otp_fields = await self._detect_post_otp_fields(page)
            if post_otp_fields:
                print(f"   📝 Not failure - POST-OTP page with fields: {list(post_otp_fields.keys())}")
                return False  # Not a failure, just needs more fields
            
            # Check if we have success indicators
            if not await self._strict_success_check(page, elapsed_time):
                print("   ❌ DEFINITE FAILURE: OTP field gone but no success indicators")
                return True
        
        return False

    async def _final_verification(self, page) -> bool:
        """Final verification yang lebih reasonable - tidak terlalu strict"""
        print("   🔍 Performing final verification...")
        
        # Wait a bit more for stability
        await asyncio.sleep(3)
        
        current_url = page.url.lower()
        current_title = (await page.title()).lower()
        
        print(f"   🔗 Final URL: {current_url}")
        print(f"   📄 Final title: {current_title}")
        
        # ========== CHECK FOR POST-OTP ADDITIONAL FIELDS PAGE ==========
        # Some flows: Email → Password → Birthday → OTP → NEW PAGE for Full Name + Username
        post_otp_fields = await self._detect_post_otp_fields(page)
        if post_otp_fields:
            print(f"   📝 POST-OTP PAGE: Additional fields required: {list(post_otp_fields.keys())}")
            
            # Fill the fields
            await self._fill_post_otp_fields(page, post_otp_fields)
            
            # Click continue/next
            await self._click_post_otp_continue(page)
            
            # Wait for next page
            await asyncio.sleep(4)
            
            # Re-check - might need to fill more fields or might be done
            current_url = page.url.lower()
            print(f"   🔗 After POST-OTP fields URL: {current_url}")
            
            # Check again for more fields (might be multi-step)
            more_fields = await self._detect_post_otp_fields(page)
            if more_fields:
                print(f"   📝 More POST-OTP fields: {list(more_fields.keys())}")
                await self._fill_post_otp_fields(page, more_fields)
                await self._click_post_otp_continue(page)
                await asyncio.sleep(4)
        
        # Re-fetch URL after potential post-OTP handling
        current_url = page.url.lower()
        
        # REAL-WORLD SUCCESS CRITERIA (berdasarkan pengalaman bisa login)
        success_indicators = [
            # 1. URL-based success - REAL Instagram pages
            any(url in current_url for url in [
                'instagram.com/', 
                'instagram.com/home',
                'instagram.com/feed',
                'instagram.com/direct/inbox',
                'instagram.com/explore',
                'instagram.com/accounts/edit'
            ]),
            
            # 2. Navigation elements yang HANYA ada saat logged in
            await page.query_selector('[data-testid="nav-profile"]') is not None,  # Profile icon
            await page.query_selector('[aria-label="Home"]') is not None,  # Home button
            await page.query_selector('nav[role="navigation"]') is not None,  # Main nav
            
            # 3. Content indicators
            'welcome to instagram' in (await page.content()).lower(),
            'get started' in (await page.content()).lower() and 'instagram' in current_title,
            
            # 4. NO OTP elements anymore
            await page.query_selector('input[placeholder*="Confirmation Code" i]') is None,
        ]
        
        print(f"   📊 Final verification indicators: {sum(success_indicators)}/{len(success_indicators)}")
        
        # JIKA 3 atau lebih indicators terpenuhi = SUCCESS
        # (lebih flexible dari sebelumnya)
        final_result = sum(success_indicators) >= 3
        
        if final_result:
            print("   🎉 FINAL VERIFICATION: OTP SUCCESS - Account should be loginable!")
            
            # Additional check: coba ambil username dari profile untuk konfirmasi
            try:
                profile_element = await page.query_selector('[data-testid="nav-profile"]')
                if profile_element:
                    print("   ✅ Profile navigation found - definitely logged in!")
            except:
                pass
            
            # Check for suspended even after success indicators
            if await self._is_account_suspended(page):
                print("   🚫 Account suspended after final verification!")
                self.status = 5
                return False
                
        else:
            print("   ❌ FINAL VERIFICATION: Not enough success indicators")
            
            # Check if account is suspended
            if await self._is_account_suspended(page):
                print("   🚫 Account is suspended!")
                self.status = 5
                await self._handle_suspended_account(page)
                return False
            
            # Debug info
            print(f"   🔍 Debug - URL contains 'instagram.com/': {'instagram.com/' in current_url}")
            print(f"   🔍 Debug - Has profile icon: {success_indicators[1]}")
            print(f"   🔍 Debug - Has home button: {success_indicators[2]}")
            print(f"   🔍 Debug - No OTP field: {success_indicators[4]}")
        
        return final_result

    def _return_data(self):
        """Return account data with status"""
        data = {
            'status': getattr(self, 'status', 4),
            'username': getattr(self, 'username', ''),
            'email': getattr(self, 'email_new', ''),
            'password': getattr(self, 'password', ''),
            'full_name': getattr(self, 'full_name', '')
        }
        
        status_map = {
            1: "✅ ACCOUNT CREATED & READY TO USE",
            2: "📱 OTP VERIFICATION REQUIRED", 
            3: "⚠️ OTP PROCESS FAILED - NEED MANUAL INTERVENTION",
            4: "❌ CREATION FAILED",
            5: "🚫 ACCOUNT SUSPENDED/DISABLED"
        }
        
        print("")
        print("📦 FINAL ACCOUNT DATA:")
        print("   👤 Username: %s", data['username'])
        print("   📧 Email: %s", data['email'])
        print("   🔐 Password: %s", "*" * len(data['password']))
        print("   👨‍💼 Full Name: %s", data['full_name'])
        print("   📊 Status: %s", status_map.get(data['status'], "UNKNOWN"))
        print("")
        
        return data

    async def get_otp_from_email(self, email: str) -> str:
        """Enhanced OTP retrieval with better waiting"""
        print("[OTP] 🔍 Retrieving OTP for: %s", email)
        
        if self.tmp == 1:
            print("[OTP] 📧 Using MailTm...")
            mail = MailTm()
            codec = mail.wait_for_email()
            if codec:
                print("[OTP] ✅ OTP from MailTm: %s", codec)
                return codec
            else:
                print("[OTP] ⏳ No OTP yet from MailTm...")
        
        elif self.tmp == 3:
            print("[OTP] 📧 Using Gmail...")
            codec = input("    Enter OTP code from Gmail: ").strip()
            if codec:
                print("[OTP] ✅ OTP from Gmail: %s", codec)
                return codec

            print("[OTP] ⏳ No OTP yet from Cmail...")
        
        elif self.tmp == 2:
            print("[OTP] 📧 Using Sepuluh...")
            codec = Sepuluh.get_code()
            if codec:
                print("[OTP] ✅ OTP from Sepuluh: %s", codec)
                return codec
            else:
                print("[OTP] ⏳ No OTP yet from Sepuluh...")
        
        # If no OTP obtained, prompt for manual entry
        print("[OTP] 🆘 Auto OTP retrieval failed")
        print("[OTP] 📱 Please check email: %s", email)
        otp_code = input("    Enter OTP code manually (or press Enter to skip): ").strip()
        return otp_code if otp_code else None

    async def close(self):
        """Close session"""
        try:
            await self.session.close_session()
            if self.chromium_started:
                await self.stop_chromium()
        except Exception:
            pass

    def update(self) -> Tuple[int, Optional[str], Optional[str], Optional[str]]:
        """Get account info"""
        return (self.status, self.username, self.password, self.email_new)

    @property
    def keep_browser_alive(self) -> bool:
        return self._keep_browser_alive

    @keep_browser_alive.setter
    def keep_browser_alive(self, value: bool):
        self._keep_browser_alive = bool(value)

class Cmail:
    def get_random(digit):
        list_mail = ["vintomaper.com","tovinit.com","mentonit.net"]
        lis = list("abcdefghijklmnopqrstuvwxyz0123456789")
        dig = [random.choice(lis) for _ in range(digit)]
        return "".join(dig), random.choice(list_mail)


# ============================================================================
# ENHANCED ACCOUNT (BONUS CLASS)
# ============================================================================

class EnhancedAccount(Account):
    """
    Enhanced Account dengan tambahan fitur:
    - Advanced fingerprint rotation
    - Behavioral analysis
    - Automatic proxy selection
    - Cookie persistence
    """
    
    def __init__(self, tmp=1, use_proxy=True, platform="chrome", 
                 use_chromium=False, suppress_no_code_log: bool = False, verbose: bool = True):
        super().__init__(tmp, use_proxy, platform, use_chromium, suppress_no_code_log, verbose)
        self.creation_analyzer = None

    async def init_session(self, profile_dir: Optional[str] = None):
        """Enhanced session initialization dengan advanced features"""
        await super().init_session(profile_dir)
        
        # Try to get optimal proxy
        try:
            if self.session.proxy_manager:
                optimal = await self.session.proxy_manager.get_optimal_proxy("US", 70)
                if optimal:
                    self.bound_proxy = optimal
                    if self.verbose:
                        print("[EnhancedAccount] Optimal proxy selected")
        except Exception:
            pass

    async def enhanced_create(self, pwd):
        """Enhanced creation dengan pre/post warmup"""
        try:
            await self._pre_creation_warmup()
            await super().create(pwd)
            await self._post_creation_cleanup()
        except Exception as e:
            logger.error("[EnhancedAccount] Error: %s", e)
            self.status = 4

    async def _pre_creation_warmup(self):
        """Pre-creation warmup dengan traffic shaping"""
        print("[EnhancedAccount] Starting pre-creation warmup...")
        
        warmup_endpoints = [
            "https://www.instagram.com/",
            "https://www.instagram.com/explore/",
            "https://www.instagram.com/accounts/login/",
        ]
        
        for endpoint in random.sample(warmup_endpoints, 2):
            try:
                if self.traffic_shaper:
                    await self.traffic_shaper.shape_traffic("navigation")
                
                headers = await self._build_fresh_headers()
                await self.session.get(endpoint, headers=headers)
                await asyncio.sleep(random.uniform(2.0, 5.0))
            except Exception:
                continue

    async def _post_creation_cleanup(self):
        """Post-creation cleanup"""
        if self.bound_proxy:
            try:
                await self.session.proxy_manager.cleanup_proxy(self.bound_proxy)
                self.bound_proxy = None
            except Exception:
                pass

    async def save_cookies_to_file(self, path: str):
        """Save cookies ke file"""
        try:
            c = await self.session.cookie_jar.to_dict()
            os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                json.dump(c, f, ensure_ascii=False, indent=2)
            print("[EnhancedAccount] Cookies saved to %s", path)
        except Exception as e:
            logger.warning("[EnhancedAccount] Failed to save cookies: %s", e)

    async def load_cookies_from_file(self, path: str):
        """Load cookies dari file"""
        try:
            if not os.path.exists(path):
                return
            with open(path, "r", encoding="utf-8") as f:
                payload = json.load(f)
            await self.session.cookie_jar.merge_from_dict(payload)
            print("[EnhancedAccount] Cookies loaded from %s", path)
        except Exception as e:
            logger.warning("[EnhancedAccount] Failed to load cookies: %s", e)


# ============================================================================
# COMPATIBILITY ALIASES
# ============================================================================

class Manual(Account):
    """Alias untuk Account class - untuk backward compatibility"""
    pass

# ============================================================================
# UI & MAIN
# ============================================================================

def get_ip():
    """Dapatkan IP publik"""
    try:
        response = requests.get('https://api.ipify.org', timeout=5)
        response.raise_for_status()
        return response.text
    except Exception:
        return "0.0.0.0"


def banner():
    os.system('cls' if os.name == 'nt' else 'clear')
    username = os.getenv("USERNAME") or "User"
    ip_addr = get_ip()
    
    print(f"""{reset}
     {biru}__________________  __
    /  _/ ____/ ____/ / / /{reset}{bg_kuning}{hitam}V{reset}{putih}.2.1
    {biru}/ // / __/ __/ / /_/ /{reset}{bg_kuning}{hitam}FIXED{reset}{hijau}
  {biru}_/ // /_/ / /___/ __  /{reset}{bg_kuning}{hitam}A{reset}{hijau}ccount
 {biru}/___/\____/_____/_/ /_/{reset}{bg_kuning}{hitam}I{reset}{hijau}nstagram
{bg_kuning}{hitam}::{reset} {bg_merah}{putih}Updated 2025-11-24 09:06:05{reset} {bg_kuning}{hitam}::{reset}
{merah}──────────────────────────────{reset}
{hijau} Username: {putih}{username}{reset}
{hijau} IP: {merah}{ip_addr}{reset}
{merah}──────────────────────────────{reset}""")


async def result_mail():
    """FIXED: Main execution dengan better error handling"""
    try:
        banner()
        print(f"{hijau}({merah}1{hijau}) {putih}Mail.tm")
        print(f"{hijau}({merah}2{hijau}) {putih}10minutemail.com")
        print(f"{hijau}({merah}3{hijau}) {putih}Gmail Alias")
        
        tmp = int(input(f"{hijau}Pilih Email: {reset}"))
        
        gmail = None
        if tmp == 3:
            sleep(1)
            banner()
            gmail = input(f"{hijau}(*) Set Gmail: {reset}")
        
        sleep(1)
        banner()
        pwd = input(f"{hijau}(*) Set Password: {reset}")
        print(f"{merah}──────────────────────────────{reset}\n")
        
        success_count = 0
        fail_count = 0
        
        while True:
            try:
                if tmp == 3 and gmail:
                    # Use Manual class untuk Gmail alias
                    santui = Account(tmp=tmp)
                    # Set gmail ke account instance
                    santui.gmail_base = gmail
                else:
                    santui = Account(tmp=tmp)
                
                await santui.init_session()
                result = await santui.create(pwd)
                
                if isinstance(result, dict):
                    status = result.get('status', 4)
                    username = result.get('username', '')
                    password = result.get('password', '')
                    email = result.get('email', '')
                else:
                    status, username, password, email = santui.update()
                
                if status == 1:
                    success_count += 1
                    with open("account.txt", "a", encoding="utf-8") as f:
                        f.write(f"{username}|{password}|{email}\n")
                    
                    print(f"\n{bg_hijau}{hitam}[SUCCESS #{success_count}]{reset}")
                    print(f"{hijau}Username: {cyan}{username}{reset}")
                    print(f"{hijau}Password: {cyan}{password}{reset}")
                    print(f"{hijau}Email: {cyan}{email}{reset}")
                    print(f"{merah}──────────────────────────────{reset}\n")
                    
                elif status == 4:
                    fail_count += 1
                    print(f"{bg_merah}{putih}[FAILED #{fail_count}]{reset}")
                    print(f"{merah}──────────────────────────────{reset}\n")
                else:
                    print(f"{bg_kuning}{hitam}[CHECKPOINT - NEED MANUAL VERIFICATION]{reset}")
                    print(f"{merah}──────────────────────────────{reset}\n")
                
                # Cleanup
                await santui.close()
                await asyncio.sleep(2)
                
                # Continue prompt
                # cont = input(f"{hijau}Lanjut membuat akun? (y/n): {reset}").lower()
                # if cont != 'y':
                #     break
                    
            except Exception as e:
                logger.error("[result_mail] Error: %s", e)
                fail_count += 1
                await asyncio.sleep(5)
        
        print(f"\n{bg_biru}{putih}[SUMMARY]{reset}")
        print(f"{hijau}Success: {success_count}{reset}")
        print(f"{merah}Failed: {fail_count}{reset}")
        print(f"{merah}──────────────────────────────{reset}\n")
                
    except KeyboardInterrupt:
        print(f"\n{merah}Program dihentikan oleh user.{reset}")
    except Exception as e:
        logger.error("[result_mail] Fatal error: %s", e)

def initialize_system():
    """✅ FIXED: System initialization dengan validation"""
    try:
        # Check required packages
        required_packages = ['aiohttp', 'requests', 'colorama', 'faker']
        missing_packages = []
        
        for package in required_packages:
            try:
                __import__(package)
            except ImportError:
                missing_packages.append(package)
        
        if missing_packages:
            print(f"{merah}Missing packages: {', '.join(missing_packages)}{reset}")
            print(f"{hijau}Install with: pip install {' '.join(missing_packages)}{reset}")
            return False
        
        # Check optional packages
        optional_packages = {
            'playwright': 'Playwright (for Chromium)',
            'httpx': 'HTTPX (for advanced HTTP)',
            'cryptography': 'Cryptography (for encryption)'
        }
        
        for package, description in optional_packages.items():
            try:
                __import__(package)
                print(f"{hijau}✅ {description} available{reset}")
            except ImportError:
                print(f"{kuning}⚠️ {description} not available{reset}")
        
        return True
        
    except Exception as e:
        logger.error("[initialize_system] Error: %s", e)
        return False


async def main():
    """Main entry point"""
    try:
        await result_mail()
    except KeyboardInterrupt:
        print(f"\n{merah}Program dihentikan.{reset}")
    except Exception as e:
        logger.error("[main] Fatal error: %s", e, exc_info=True)


if __name__ == "__main__":
    try:
        if not initialize_system():
            print(f"{merah}System initialization failed. Exiting.{reset}")
            exit(1)
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"\n{merah}Exit.{reset}")
    except Exception as e:
        print(f"{merah}Fatal error: {e}{reset}")
        logger.error("[__main__] Fatal error: %s", e, exc_info=True)