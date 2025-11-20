#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
import os
import re
import subprocess
from ipaddress import ip_address

import dns.resolver
import requests
from dotenv import load_dotenv
from telegram import (
    Update,
    ReplyKeyboardMarkup,
    KeyboardButton,
)
from telegram.ext import (
    ApplicationBuilder,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
)

# ============================================================
# Carga de variables de entorno y logging
# ============================================================

load_dotenv()

TELEGRAM_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
VT_API_KEY = os.getenv("VT_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
NVD_API_KEY = os.getenv("NVD_API_KEY")  # opcional, para NVD

logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger(__name__)


# ============================================================
# Utilidades
# ============================================================

def is_valid_ip(value: str) -> bool:
    """Valida si el string recibido corresponde a una IP válida."""
    try:
        ip_address(value)
        return True
    except ValueError:
        return False


DOMAIN_REGEX = re.compile(r"^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")


def shorten(text: str, max_chars: int = 3800) -> str:
    """Recorta texto largo para no superar el límite de Telegram."""
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + "\n\n[Salida truncada por longitud]"


def detect_hash_type(value: str) -> str:
    """Intenta identificar tipo de hash por longitud."""
    if re.fullmatch(r"[A-Fa-f0-9]{32}", value):
        return "MD5"
    if re.fullmatch(r"[A-Fa-f0-9]{40}", value):
        return "SHA-1"
    if re.fullmatch(r"[A-Fa-f0-9]{64}", value):
        return "SHA-256"
    return "desconocido"


def is_url(value: str) -> bool:
    """Heurística simple para saber si parece una URL."""
    if value.startswith("http://") or value.startswith("https://"):
        return True
    if "/" in value and "." in value:
        return True
    return False


# Patrones para pseudo detección de tecnologías
PATTERNS_TECH = {
    "WordPress": ["wp-content", "wp-includes", "woocommerce"],
    "Drupal": ["drupalSettings", "Drupal.settings"],
    "Joomla": ["content=\"Joomla!", "Joomla!"],
    "Shopify": ["cdn.shopify.com", "x-shopify-stage"],
    "PrestaShop": ["prestashop", "var prestashop"],
    "Magento": ["Mage.Cookies.path", "Magento"],
    "Laravel": ["laravel_session", "csrf-token\"", "X-Powered-By: PHP"],
    "React": ["react-dom", "data-reactroot", "React.createElement"],
    "Vue.js": ["vue.runtime", "Vue.component", "data-v-"],
    "Next.js": ["__NEXT_DATA__", "next-head"],
    "Angular": ["ng-version", "angular.min.js"],
    "Cloudflare": ["cloudflare", "__cf_bm"],
}


# ============================================================
# Teclado principal con botones
# ============================================================

def main_keyboard() -> ReplyKeyboardMarkup:
    keyboard = [
        [
            KeyboardButton("🕵️ OSINT IP"),
            KeyboardButton("🌐 OSINT Dominio"),
        ],
        [
            KeyboardButton("🚔 AbuseIP"),
            KeyboardButton("🧬 Hash info"),
        ],
        [
            KeyboardButton("🧱 Webtech"),
            KeyboardButton("📡 Nmap rápido"),
        ],
        [
            KeyboardButton("📄 CVE info"),
            KeyboardButton("🛡 Blue Team"),
        ],
        [
            KeyboardButton("📚 Rutas de estudio"),
            KeyboardButton("ℹ️ Ayuda"),
        ],
    ]
    return ReplyKeyboardMarkup(keyboard, resize_keyboard=True)


# ============================================================
# /start, /help y /menu
# ============================================================

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = (
        "👋 Bienvenido a *CyberScout* – Asistente de Ciberseguridad.\n\n"
        "Te ayudo con:\n"
        "• 🕵️ OSINT de IP y dominios\n"
        "• 🚔 Reputación de IP (AbuseIPDB)\n"
        "• 🧬 Reputación de hashes (VirusTotal)\n"
        "• 🧱 Tecnologías web, cabeceras y WHOIS\n"
        "• 📡 Escaneos rápidos con Nmap\n"
        "• 📄 Información de CVE\n"
        "• 🛡 Mini playbooks Blue Team y rutas de estudio\n\n"
        "Usá el teclado de abajo para no tener que escribir todos los comandos.\n"
        "O enviá /help para ver el detalle de cada comando."
    )
    await update.message.reply_markdown(
        text,
        reply_markup=main_keyboard(),
    )


async def help_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = (
        "ℹ️ *Comandos disponibles de CyberScout*\n\n"
        "🕵️ *OSINT y reputación*\n"
        "• `/osint_ip <ip>` – Geolocalización aproximada, ASN, proveedor\n"
        "• `/osint_domain <dominio>` – Registros A y NS básicos\n"
        "• `/abuseip <ip>` – Reputación en AbuseIPDB\n"
        "• `/hash_info <hash>` – Reputación de hash en VirusTotal\n"
        "• `/ioc_check <valor>` – Clasifica si es IP / dominio / URL / hash y sugiere comandos\n\n"
        "🧱 *Web y tecnologías*\n"
        "• `/webtech <url>` – Tecnologías probables del sitio\n"
        "• `/http_headers <url>` – Cabeceras HTTP de seguridad\n\n"
        "📡 *Infraestructura*\n"
        "• `/nmap_scan <host>` – Escaneo rápido con Nmap (puertos comunes)\n"
        "• `/nmap_cheatsheet` – Comandos típicos de Nmap\n"
        "• `/whois <dominio|ip>` – WHOIS básico\n\n"
        "📄 *Vulnerabilidades y Blue Team*\n"
        "• `/cve <CVE-ID>` – Resumen de CVE (NVD + CIRCL)\n"
        "• `/blue_team` – Mini playbooks defensivos\n"
        "• `/learning_path` – Rutas de estudio recomendadas\n\n"
        "También podés usar el menú con botones para ahorrar escritura."
    )
    await update.message.reply_markdown(text)


async def menu(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = (
        "📋 Menú principal de *CyberScout*\n\n"
        "Elegí una opción del teclado de abajo o usá /help para ver todos los comandos."
    )
    await update.message.reply_markdown(
        text,
        reply_markup=main_keyboard(),
    )


# ============================================================
# Handler para los botones del teclado
# ============================================================

async def handle_text_menu(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = (update.message.text or "").strip()

    if text == "🕵️ OSINT IP":
        await update.message.reply_text(
            "Mandá:\n`/osint_ip 8.8.8.8`\n\nReemplazá 8.8.8.8 por la IP que quieras analizar.",
            parse_mode="Markdown",
        )
    elif text == "🌐 OSINT Dominio":
        await update.message.reply_text(
            "Mandá:\n`/osint_domain ejemplo.com`\n\nReemplazá ejemplo.com por el dominio que quieras analizar.",
            parse_mode="Markdown",
        )
    elif text == "🚔 AbuseIP":
        await update.message.reply_text(
            "Mandá:\n`/abuseip 1.1.1.1`\n\nReemplazá 1.1.1.1 por la IP que quieras consultar en AbuseIPDB.",
            parse_mode="Markdown",
        )
    elif text == "🧬 Hash info":
        await update.message.reply_text(
            "Mandá:\n`/hash_info <hash>`\n\nPegá el hash MD5 / SHA1 / SHA256 que quieras consultar.",
            parse_mode="Markdown",
        )
    elif text == "🧱 Webtech":
        await update.message.reply_text(
            "Mandá:\n`/webtech https://ejemplo.com`\n\nReemplazá la URL por la que quieras analizar.",
            parse_mode="Markdown",
        )
    elif text == "📡 Nmap rápido":
        await update.message.reply_text(
            "Mandá:\n`/nmap_scan 192.168.0.10`\n\nReemplazá la IP/host por el objetivo autorizado que quieras escanear.",
            parse_mode="Markdown",
        )
    elif text == "📄 CVE info":
        await update.message.reply_text(
            "Mandá:\n`/cve CVE-2021-44228`\n\nReemplazá el ID de CVE por el que quieras consultar.",
            parse_mode="Markdown",
        )
    elif text == "🛡 Blue Team":
        await blue_team(update, context)
    elif text == "📚 Rutas de estudio":
        await learning_path(update, context)
    elif text == "ℹ️ Ayuda":
        await help_cmd(update, context)
    else:
        # Si no es uno de los botones, dejamos que otros handlers actúen
        return


# ============================================================
# OSINT: IP
# ============================================================

async def osint_ip(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text(
            "Uso: `/osint_ip <ip>`\nEjemplo: `/osint_ip 8.8.8.8`",
            parse_mode="Markdown",
        )
        return

    ip = context.args[0].strip()

    if not is_valid_ip(ip):
        await update.message.reply_text(
            "La IP indicada no es válida.\nEjemplo correcto: `/osint_ip 8.8.8.8`",
            parse_mode="Markdown",
        )
        return

    await update.message.reply_text("🔎 Consultando información básica de la IP, un momento...")

    try:
        url = f"https://ipinfo.io/{ip}/json"
        resp = requests.get(url, timeout=8)
        data = resp.json()

        country = data.get("country", "N/D")
        city = data.get("city", "N/D")
        org = data.get("org", "N/D")
        loc = data.get("loc", "N/D")

        text = (
            f"🕵️ *OSINT de IP {ip}*\n\n"
            f"🌍 País: `{country}`\n"
            f"🏙 Ciudad: `{city}`\n"
            f"🏢 Org / ASN: `{org}`\n"
            f"📍 Coordenadas aprox.: `{loc}`\n\n"
            "_Datos aproximados para uso OSINT y análisis de contexto._"
        )
        await update.message.reply_markdown(text)
    except Exception:
        logger.exception("Error en osint_ip")
        await update.message.reply_text("⚠️ Ocurrió un error obteniendo la información de la IP.")


# ============================================================
# OSINT: dominio
# ============================================================

async def osint_domain(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text(
            "Uso: `/osint_domain <dominio>`\nEjemplo: `/osint_domain example.com`",
            parse_mode="Markdown",
        )
        return

    domain = context.args[0].strip().lower()

    if not DOMAIN_REGEX.match(domain):
        await update.message.reply_text(
            "❌ Dominio no válido.\nEjemplo: `/osint_domain example.com`",
            parse_mode="Markdown",
        )
        return

    await update.message.reply_text("🔎 Resolviendo registros DNS del dominio...")

    resolver = dns.resolver.Resolver()

    try:
        answers_a = resolver.resolve(domain, "A")
        ips = [str(rdata) for rdata in answers_a]
    except Exception:
        ips = []

    try:
        answers_ns = resolver.resolve(domain, "NS")
        ns_records = [str(rdata.target).rstrip(".") for rdata in answers_ns]
    except Exception:
        ns_records = []

    text_lines = [f"🕵️ *OSINT de dominio* `{domain}`\n"]

    if ips:
        text_lines.append("📡 *Registros A (IPv4):*")
        for ip in ips:
            text_lines.append(f"• `{ip}`")
        text_lines.append("")
    else:
        text_lines.append("📡 No se encontraron registros A.")

    if ns_records:
        text_lines.append("🧩 *Servidores NS:*")
        for ns in ns_records:
            text_lines.append(f"• `{ns}`")
    else:
        text_lines.append("🧩 No se encontraron registros NS.")

    text_lines.append("\n_Usar solo en contextos legales y con fines de análisis._")

    await update.message.reply_markdown("\n".join(text_lines))


# ============================================================
# AbuseIPDB
# ============================================================

async def abuseip_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text(
            "Uso: `/abuseip <ip>`\nEjemplo: `/abuseip 1.1.1.1`",
            parse_mode="Markdown",
        )
        return

    if not ABUSEIPDB_API_KEY:
        await update.message.reply_text(
            "⚠️ No hay API key de AbuseIPDB configurada.\n"
            "Agregá `ABUSEIPDB_API_KEY` en tu archivo `.env` (plan gratuito disponible)."
        )
        return

    ip = context.args[0].strip()

    if not is_valid_ip(ip):
        await update.message.reply_text(
            "❌ IP no válida.\nEjemplo correcto: `/abuseip 1.1.1.1`",
            parse_mode="Markdown",
        )
        return

    await update.message.reply_text("🚔 Consultando reputación en AbuseIPDB...")

    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {
            "Key": ABUSEIPDB_API_KEY,
            "Accept": "application/json",
        }
        params = {
            "ipAddress": ip,
            "maxAgeInDays": "90",
            "verbose": "true",
        }

        resp = requests.get(url, headers=headers, params=params, timeout=10)

        if resp.status_code == 429:
            await update.message.reply_text("⚠️ Límite de consultas de AbuseIPDB alcanzado (rate limit).")
            return

        if resp.status_code != 200:
            logger.warning("AbuseIPDB status: %s, body: %s", resp.status_code, resp.text[:500])
            await update.message.reply_text("⚠️ No se pudo obtener información desde AbuseIPDB.")
            return

        data = resp.json().get("data", {})

        score = data.get("abuseConfidenceScore", "N/D")
        total_reports = data.get("totalReports", 0)
        last_reported = data.get("lastReportedAt", "N/D")
        is_whitelisted = data.get("isWhitelisted", False)
        country = data.get("countryCode", "N/D")
        usage_type = data.get("usageType", "N/D")
        isp = data.get("isp", "N/D")
        domain = data.get("domain", "N/D")

        text = (
            f"🚔 *AbuseIPDB – IP* `{ip}`\n\n"
            f"📊 *Abuse score:* `{score}` (0–100)\n"
            f"📑 Reportes totales: `{total_reports}`\n"
            f"🕒 Último reporte: `{last_reported}`\n\n"
            f"🌍 País: `{country}`\n"
            f"🏢 ISP: `{isp}`\n"
            f"🌐 Dominio asociado: `{domain}`\n"
            f"🏷️ Uso reportado: `{usage_type}`\n"
            f"🛡 Whitelisted: `{is_whitelisted}`\n\n"
            "_Interpretar el score siempre en contexto (hosting compartido, VPN, etc.)._"
        )
        await update.message.reply_markdown(text)
    except Exception:
        logger.exception("Error en AbuseIPDB")
        await update.message.reply_text("⚠️ Ocurrió un error consultando AbuseIPDB.")


# ============================================================
# Hash / VirusTotal
# ============================================================

async def hash_info(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("Uso: `/hash_info <hash>`", parse_mode="Markdown")
        return

    if not VT_API_KEY:
        await update.message.reply_text(
            "⚠️ No hay API key configurada para VirusTotal.\n"
            "Configurá `VT_API_KEY` en tu `.env` (plan gratuito)."
        )
        return

    file_hash = context.args[0].strip().lower()
    await update.message.reply_text("🧬 Consultando reputación del hash en VirusTotal...")

    try:
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {"x-apikey": VT_API_KEY}
        resp = requests.get(url, headers=headers, timeout=10)

        if resp.status_code == 404:
            await update.message.reply_text("ℹ️ Hash no encontrado en la base de VirusTotal.")
            return

        if resp.status_code != 200:
            logger.warning("VirusTotal status: %s, body: %s", resp.status_code, resp.text[:500])
            await update.message.reply_text("⚠️ No se pudo obtener información del hash.")
            return

        data = resp.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)

        hash_type = detect_hash_type(file_hash)

        text = (
            f"🧬 *Reputación de hash*\n\n"
            f"`{file_hash}`\n"
            f"Tipo estimado: *{hash_type}*\n\n"
            f"😈 Malicious: *{malicious}*\n"
            f"⚠️ Suspicious: *{suspicious}*\n"
            f"✅ Harmless: *{harmless}*\n"
            f"❓ Undetected: *{undetected}*\n\n"
            "_Analizá siempre las muestras en entornos aislados (sandbox / VM)._"
        )
        await update.message.reply_markdown(text)
    except Exception:
        logger.exception("Error en hash_info")
        await update.message.reply_text("⚠️ Ocurrió un error consultando la reputación del hash.")


# ============================================================
# Tecnologías web
# ============================================================

async def webtech(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text(
            "Uso: `/webtech <url>`\nEjemplo: `/webtech https://example.com`",
            parse_mode="Markdown",
        )
        return

    url = context.args[0].strip()
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url

    await update.message.reply_text("🧱 Analizando sitio y tecnologías probables...")

    try:
        headers_request = {
            "User-Agent": "Mozilla/5.0 (compatible; CyberScout/1.0)"
        }
        resp = requests.get(url, headers=headers_request, timeout=10)
        content = resp.text
        headers_resp = resp.headers

        detected = []

        server = headers_resp.get("Server")
        powered_by = headers_resp.get("X-Powered-By")
        if server:
            detected.append(f"🖥 Server: `{server}`")
        if powered_by:
            detected.append(f"⚙️ X-Powered-By: `{powered_by}`")

        set_cookie = headers_resp.get("Set-Cookie", "")
        cookie_hits = []
        for needle in ["PHPSESSID", "laravel_session", "ASP.NET_SessionId", "JSESSIONID"]:
            if needle.lower() in set_cookie.lower():
                cookie_hits.append(needle)
        if cookie_hits:
            detected.append(
                "🍪 Cookies de sesión detectadas: "
                + ", ".join(f"`{c}`" for c in cookie_hits)
            )

        content_lower = content.lower()
        tech_hits = []
        for tech, patterns in PATTERNS_TECH.items():
            for p in patterns:
                if p.lower() in content_lower:
                    tech_hits.append(tech)
                    break

        if tech_hits:
            tech_hits = sorted(set(tech_hits))
            detected.append("🔍 Tecnologías probables: " + ", ".join(f"*{t}*" for t in tech_hits))

        if not detected:
            detected.append(
                "No se detectaron tecnologías claras. El sitio puede ser muy simple u ofuscado."
            )

        text = "🧱 *Detección de tecnologías web*\n\n" + "\n".join(detected)
        text += "\n\n_Análisis heurístico y aproximado. Para más detalle, usar Wappalyzer, WhatWeb, etc._"

        await update.message.reply_markdown(text)
    except Exception:
        logger.exception("Error en webtech")
        await update.message.reply_text("⚠️ Ocurrió un error analizando el sitio.")


# ============================================================
# Cabeceras HTTP
# ============================================================

async def http_headers(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text(
            "Uso: `/http_headers <url>`\nEjemplo: `/http_headers https://example.com`",
            parse_mode="Markdown",
        )
        return

    url = context.args[0].strip()
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url

    await update.message.reply_text("📨 Obteniendo cabeceras HTTP de seguridad...")

    try:
        resp = requests.get(url, timeout=10, allow_redirects=True)
        headers_resp = resp.headers

        security_headers = [
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Referrer-Policy",
            "Permissions-Policy",
        ]

        lines = [f"📨 *Cabeceras de seguridad para* `{url}`\n"]

        for h in security_headers:
            value = headers_resp.get(h, "No presente")
            lines.append(f"• *{h}*: `{value}`")

        lines.append(
            "\nRevisá estas cabeceras contra buenas prácticas (OWASP, guías del vendor) "
            "para endurecer la configuración del sitio."
        )

        await update.message.reply_markdown("\n".join(lines))
    except Exception:
        logger.exception("Error en http_headers")
        await update.message.reply_text("⚠️ Ocurrió un error obteniendo las cabeceras HTTP.")


# ============================================================
# Nmap (escaneo rápido hardenizado)
# ============================================================

async def nmap_scan(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text(
            "Uso: `/nmap_scan <host>`\nEjemplo: `/nmap_scan 192.168.0.10`",
            parse_mode="Markdown",
        )
        return

    target = context.args[0].strip()

    # Validación básica para evitar cosas raras (aunque subprocess con lista ya es seguro)
    if len(target) > 100 or " " in target or ";" in target or "&" in target:
        await update.message.reply_text("❌ Objetivo no válido.")
        return

    await update.message.reply_text(
        "📡 Ejecutando escaneo Nmap rápido (puertos más comunes)...\n"
        "Usar solo contra objetivos autorizados."
    )

    try:
        # Escaneo más ligero y con límites claros
        cmd = [
            "nmap",
            "-T4",              # rápido
            "-F",               # fast scan (puertos más comunes)
            "--max-retries", "2",
            "--host-timeout", "25s",
            target,
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=35,   # timeout duro para el proceso
        )

        if result.returncode not in (0, 1):
            await update.message.reply_text("⚠️ Nmap devolvió un error al ejecutar el escaneo.")
            logger.error("Nmap error: %s", result.stderr)
            return

        output = shorten(result.stdout)
        if not output.strip():
            await update.message.reply_text("ℹ️ El escaneo no devolvió salida útil. Verificá el objetivo.")
            return

        text = "📡 *Resultado del escaneo Nmap (rápido)*\n\n```bash\n" + output + "\n```"
        await update.message.reply_markdown(text)
    except FileNotFoundError:
        await update.message.reply_text(
            "❌ Nmap no está instalado en el servidor.\n"
            "Instalá Nmap para usar este comando."
        )
    except subprocess.TimeoutExpired:
        await update.message.reply_text(
            "⚠️ El escaneo Nmap tardó demasiado y fue cancelado.\n"
            "Probá con un host interno o reducí el alcance del escaneo."
        )
    except Exception:
        logger.exception("Error en nmap_scan")
        await update.message.reply_text("⚠️ Ocurrió un error ejecutando Nmap.")


async def nmap_cheatsheet(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = (
        "📘 *Nmap Cheatsheet (uso ético)*\n\n"
        "Escaneo rápido puertos comunes:\n"
        "`nmap -sV -T4 <ip>`\n\n"
        "Escaneo completo de puertos:\n"
        "`nmap -p- -sV -T4 <ip>`\n\n"
        "Detección de sistema operativo:\n"
        "`nmap -O <ip>`\n\n"
        "Scripts básicos de vulnerabilidades:\n"
        "`nmap --script vuln <ip>`\n\n"
        "Recordá ejecutarlo solo en infraestructura propia o con autorización escrita."
    )
    await update.message.reply_markdown(text)


# ============================================================
# WHOIS
# ============================================================

async def whois_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("Uso: `/whois <dominio|ip>`", parse_mode="Markdown")
        return

    target = context.args[0].strip()

    await update.message.reply_text("📄 Ejecutando consulta WHOIS en el sistema...")

    try:
        cmd = ["whois", target]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=40,
        )

        if result.returncode != 0 and not result.stdout:
            await update.message.reply_text("⚠️ No se pudo obtener información WHOIS para el objetivo indicado.")
            logger.error("WHOIS error: %s", result.stderr)
            return

        output = shorten(result.stdout)
        text = "📄 *Resultado WHOIS (resumen)*\n\n```text\n" + output + "\n```"
        await update.message.reply_markdown(text)
    except FileNotFoundError:
        await update.message.reply_text(
            "❌ No se encontró la herramienta `whois` en el sistema.\n"
            "Instalá el paquete `whois` para usar este comando."
        )
    except subprocess.TimeoutExpired:
        await update.message.reply_text("⚠️ La consulta WHOIS fue cancelada por exceder el tiempo máximo.")
    except Exception:
        logger.exception("Error en whois_cmd")
        await update.message.reply_text("⚠️ Ocurrió un error ejecutando WHOIS.")


# ============================================================
# IOC check
# ============================================================

async def ioc_check(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("Uso: `/ioc_check <valor>`", parse_mode="Markdown")
        return

    value = context.args[0].strip()
    tipo = "desconocido"
    sugerencias = []

    if is_valid_ip(value):
        tipo = "IP"
        sugerencias = [
            f"/osint_ip {value}",
            f"/abuseip {value}",
        ]
    elif is_url(value):
        tipo = "URL"
        sugerencias = [
            f"/webtech {value}",
            f"/http_headers {value}",
        ]
    elif DOMAIN_REGEX.match(value.lower()):
        tipo = "Dominio"
        sugerencias = [
            f"/osint_domain {value}",
            f"/whois {value}",
        ]
    else:
        hash_type = detect_hash_type(value)
        if hash_type != "desconocido":
            tipo = f"Hash ({hash_type})"
            sugerencias = [
                f"/hash_info {value}",
            ]
        else:
            tipo = "Texto no clasificado (usuario, ruta, patrón, etc.)"

    lines = [
        "🧩 *Clasificación de IOC*\n",
        f"📌 Valor recibido: `{value}`",
        f"📂 Tipo estimado: *{tipo}*",
        "",
    ]

    if sugerencias:
        lines.append("📎 Comandos sugeridos para seguir el análisis:")
        for s in sugerencias:
            lines.append(f"• `{s}`")
    else:
        lines.append("No se encontraron sugerencias automatizadas para este tipo de dato.")

    await update.message.reply_markdown("\n".join(lines))


# ============================================================
# CVE (NVD + fallback CIRCL)
# ============================================================

async def cve_info(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text(
            "Uso: `/cve <CVE-ID>`\nEjemplo: `/cve CVE-2021-44228`",
            parse_mode="Markdown",
        )
        return

    cve_id = context.args[0].upper().strip()
    await update.message.reply_text("📄 Buscando información del CVE en la API pública de CIRCL...")

    try:
        circl_url = f"https://cve.circl.lu/api/cve/{cve_id}"
        resp = requests.get(circl_url, timeout=12)

        # Si la API no responde OK, avisamos
        if resp.status_code != 200:
            logger.warning("CIRCL status %s para %s, body: %s", resp.status_code, cve_id, resp.text[:300])
            await update.message.reply_text(
                "⚠️ No se pudo obtener información del CVE desde la API pública. "
                "Probá más tarde o validá el ID del CVE."
            )
            return

        data = resp.json()

        # Si el CVE no existe o la API no lo conoce
        if not data or "id" not in data:
            await update.message.reply_text(
                f"ℹ️ El CVE `{cve_id}` no fue encontrado en la base consultada.\n"
                "Puede que sea muy nuevo, esté mal escrito o aún no esté publicado."
            )
            return

        description = data.get("summary", "Sin descripción disponible.")
        cvss_score = data.get("cvss", "N/D")
        published = data.get("Published", "N/D")
        modified = data.get("Modified", "N/D")

        text = (
            f"📄 *{cve_id}*\n\n"
            f"📊 *CVSS (base score):* `{cvss_score}`\n"
            f"📅 Publicado: `{published}`\n"
            f"🕒 Última actualización: `{modified}`\n\n"
            f"📝 *Descripción resumida:*\n{description}\n\n"
            "Se recomienda validar esta información con la documentación oficial del proveedor, "
            "avisos de seguridad y tu propio contexto de infraestructura."
        )
        await update.message.reply_markdown(text)
    except Exception:
        logger.exception("Error consultando CIRCL para CVE %s", cve_id)
        await update.message.reply_text(
            "⚠️ Ocurrió un error obteniendo información del CVE desde la API pública.\n"
            "Verificá la conectividad de tu servidor a Internet o probá de nuevo más tarde."
        )

# ============================================================
# Blue Team
# ============================================================

async def blue_team(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = (
        "🛡 *Blue Team – Mini playbooks de referencia*\n\n"
        "1️⃣ Actividad sospechosa desde una IP externa:\n"
        "• Verificar reputación de la IP (AbuseIPDB, otras fuentes OSINT).\n"
        "• Correlacionar en firewall, proxy, WAF y EDR.\n"
        "• Identificar usuarios, hosts y servicios involucrados.\n"
        "• Aplicar bloqueos temporales según política.\n"
        "• Registrar todo en el gestor de incidentes.\n\n"
        "2️⃣ Archivo potencialmente malicioso:\n"
        "• Calcular hash y consultar reputación (VirusTotal, etc.).\n"
        "• Analizar en sandbox controlada.\n"
        "• Buscar el hash en EDR, SIEM e inventarios.\n"
        "• Actualizar reglas de detección si corresponde.\n\n"
        "3️⃣ Vulnerabilidad crítica en sistema expuesto:\n"
        "• Confirmar exposición y versión del servicio.\n"
        "• Validar si la vulnerabilidad es explotable en el contexto.\n"
        "• Coordinar patching / mitigaciones con infraestructura.\n"
        "• Aplicar reglas temporales en WAF o firewall si es necesario.\n"
        "• Documentar ventana de riesgo y acciones realizadas.\n\n"
        "Estos pasos son orientativos y deben adaptarse a los procesos formales de cada organización."
    )
    await update.message.reply_markdown(text)


# ============================================================
# Rutas de aprendizaje
# ============================================================

async def learning_path(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = (
        "📚 *Rutas de aprendizaje en ciberseguridad*\n\n"
        "🕵️ OSINT y superficie de ataque:\n"
        "• Redes y protocolos (TCP/IP, HTTP, DNS).\n"
        "• Búsqueda avanzada, metadatos, enumeración de dominios.\n"
        "• Herramientas: theHarvester, Amass, Shodan, Maltego.\n"
        "• Reporte claro y accionable.\n\n"
        "💻 Pentesting y hacking ético:\n"
        "• Sistemas orientados a seguridad (Kali Linux, Parrot).\n"
        "• Nmap, reconocimiento activo, enumeración de servicios.\n"
        "• OWASP Top 10, Burp Suite, fuzzing de parámetros.\n"
        "• Post-explotación básica y reporting profesional.\n\n"
        "🧬 Análisis de malware y respuesta a incidentes:\n"
        "• Funcionamiento interno de Windows y Linux.\n"
        "• Análisis estático (hashes, strings, YARA).\n"
        "• Análisis dinámico en sandbox, monitoreo de red y sistema.\n"
        "• Uso de EDR, SIEM e inteligencia de amenazas.\n\n"
        "Combiná estas rutas según tu rol objetivo (SOC, Red Team, DFIR, etc.)."
    )
    await update.message.reply_markdown(text)


# ============================================================
# main
# ============================================================

def main():
    if not TELEGRAM_TOKEN:
        raise RuntimeError("TELEGRAM_BOT_TOKEN no está definido en el archivo .env")

    app = ApplicationBuilder().token(TELEGRAM_TOKEN).build()

    # Comandos de control
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help_cmd))
    app.add_handler(CommandHandler("menu", menu))

    # OSINT y reputación
    app.add_handler(CommandHandler("osint_ip", osint_ip))
    app.add_handler(CommandHandler("osint_domain", osint_domain))
    app.add_handler(CommandHandler("abuseip", abuseip_cmd))
    app.add_handler(CommandHandler("hash_info", hash_info))
    app.add_handler(CommandHandler("ioc_check", ioc_check))

    # Web
    app.add_handler(CommandHandler("webtech", webtech))
    app.add_handler(CommandHandler("http_headers", http_headers))

    # Infra
    app.add_handler(CommandHandler("nmap_scan", nmap_scan))
    app.add_handler(CommandHandler("nmap_cheatsheet", nmap_cheatsheet))
    app.add_handler(CommandHandler("whois", whois_cmd))

    # CVE y Blue Team
    app.add_handler(CommandHandler("cve", cve_info))
    app.add_handler(CommandHandler("blue_team", blue_team))
    app.add_handler(CommandHandler("learning_path", learning_path))

    # Handler para texto plano (botones del teclado)
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text_menu))

    logger.info("CyberScout iniciado.")
    app.run_polling()


if __name__ == "__main__":
    main()