# backend.py - Telegram-ready hosting system
import os
import sys
import time
import json
import base64
import traceback
import hashlib
import random
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path

# ---------- imports (safe) ----------
try:
    from flask import (
        Flask, render_template, request, redirect, url_for, session,
        jsonify, send_file, flash, render_template_string
    )
    from werkzeug.security import generate_password_hash, check_password_hash
    from werkzeug.utils import secure_filename
except Exception as e:
    print("Missing packages. Install: pip install flask requests werkzeug")
    raise

import requests
import subprocess
import shutil
import ast
import socket
from telethon import TelegramClient
from telethon.tl.types import InputMessagesFilterDocument
from telethon.sessions import StringSession

# ========== CONFIG ==========
BASE_DOMAIN = os.environ.get("BASE_DOMAIN", "x.2026tr.xyz")
PORT = int(os.environ.get("PORT", 5000))
APP_ROOT = Path(__file__).parent.resolve()

# ========== TELEGRAM CONFIG ==========
API_ID = 24179304
API_HASH = "6fdbaf87f6fa54a1a8a51603bf38c2d1"
SESSION_STRING = "1ApWapzMBu00TcO02cRYREPfQ8ubOErEnIYktiYxvfa9JTCId4Yh7myle5Lw9i8T1LqkrVGLOYlQjTiPx1QrSTTxLPBbqtMGxkgYrojwYDWYS-Vjrm-9viL9wcbgsEh5QH-6PIht93hyaKsZXuDXlBO0SlpU2xhuqLAh_-0Qe7sCgWnCpBtszPJGFuvQVSKUz0Kt2Cj4OXDBQp8I4pvogCOlXO1Rj5QP4aSM6pKYxvg8uC9zPLBxdG__rZI7Mg3GmYaFOPHg32-k2co9YyP701pjpEXJHj_1bjbuEU2Q0Fr2yHKiYWEy-JyAz_xRHx06hAzmexHQvP2oZ7mKw1g4jIdbUSMmG4X0="
TELEGRAM_CHANNEL = "nabihostingdeposak"
TELEGRAM_SYNC_INTERVAL = 300  # 5 dakika

# ========== FLASK APP ==========
app = Flask(__name__, template_folder="templates", static_folder="static")
app.secret_key = "nabi_secure_key_2024_tr_826_baba"
app.config["UPLOAD_FOLDER"] = "user_files"
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB

# ========== TELEGRAM CLIENT ==========
telegram_client = None
client_lock = False

async def get_telegram_client():
    """Telegram client'ı al veya oluştur"""
    global telegram_client, client_lock
    
    if telegram_client and await telegram_client.is_connected():
        return telegram_client
    
    # Client oluşturma kilidi
    if client_lock:
        # Kilitliyse bekleyelim
        for _ in range(10):  # 10 deneme
            await asyncio.sleep(0.5)
            if telegram_client and await telegram_client.is_connected():
                return telegram_client
    
    client_lock = True
    try:
        if telegram_client:
            try:
                await telegram_client.disconnect()
            except:
                pass
        
        telegram_client = TelegramClient(
            StringSession(SESSION_STRING),
            API_ID,
            API_HASH
        )
        await telegram_client.start()
        print("Telegram client başlatıldı")
        return telegram_client
    except Exception as e:
        print(f"Telegram client hatası: {e}")
        return None
    finally:
        client_lock = False

# ========== DATABASE (SQLITE3) ==========
def get_db_connection():
    """SQLite3 database connection"""
    conn = sqlite3.connect('hosting.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_database():
    """Initialize database tables"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            email TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_admin BOOLEAN DEFAULT 0
        )
    ''')
    
    # Websites table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS websites (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            domain TEXT UNIQUE NOT NULL,
            site_name TEXT UNIQUE NOT NULL,
            php_enabled BOOLEAN DEFAULT 1,
            python_enabled BOOLEAN DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            status TEXT DEFAULT 'active',
            last_sync TIMESTAMP
        )
    ''')
    
    conn.commit()
    conn.close()

# ========== DATABASE HELPERS ==========
def get_user_by_id(user_id):
    """Get user by ID"""
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()
    return user

def get_user_by_username(username):
    """Get user by username"""
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    conn.close()
    return user

def create_user(username, password_hash, email):
    """Create new user"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        'INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)',
        (username, password_hash, email)
    )
    user_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return user_id

def get_user_websites(user_id):
    """Get all websites for a user"""
    conn = get_db_connection()
    websites = conn.execute(
        'SELECT * FROM websites WHERE user_id = ? ORDER BY created_at DESC',
        (user_id,)
    ).fetchall()
    conn.close()
    return websites

def get_website_by_site_name(site_name):
    """Get website by site_name"""
    conn = get_db_connection()
    website = conn.execute(
        'SELECT * FROM websites WHERE site_name = ? AND status = ?',
        (site_name, 'active')
    ).fetchone()
    conn.close()
    return website

def create_website(user_id, domain, site_name, php_enabled, python_enabled):
    """Create new website"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        '''INSERT INTO websites 
           (user_id, domain, site_name, php_enabled, python_enabled) 
           VALUES (?, ?, ?, ?, ?)''',
        (user_id, domain, site_name, php_enabled, python_enabled)
    )
    website_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return website_id

def update_website_sync_time(site_name):
    """Update website last sync time"""
    conn = get_db_connection()
    conn.execute(
        'UPDATE websites SET last_sync = CURRENT_TIMESTAMP WHERE site_name = ?',
        (site_name,)
    )
    conn.commit()
    conn.close()

def website_exists(site_name):
    """Check if website exists"""
    conn = get_db_connection()
    exists = conn.execute(
        'SELECT 1 FROM websites WHERE site_name = ?',
        (site_name,)
    ).fetchone() is not None
    conn.close()
    return exists

# ========== HELPERS ==========
def get_current_user():
    if "user_id" in session:
        return get_user_by_id(session["user_id"])
    return None

def safe_site_path(user, site_name):
    """Return public_html path and ensure directories exist."""
    base = Path(app.config["UPLOAD_FOLDER"]) / user["username"] / site_name / "public_html"
    base.mkdir(parents=True, exist_ok=True)
    return base

def run_php(file_path):
    try:
        res = subprocess.run(["php", file_path], capture_output=True, text=True, timeout=10)
        return res.stdout or res.stderr or ""
    except Exception as e:
        return f"PHP Error: {e}"

def run_python(file_path):
    try:
        res = subprocess.run(["python3", file_path], capture_output=True, text=True, timeout=10)
        return res.stdout or res.stderr or ""
    except Exception as e:
        return f"Python Error: {e}"

def extract_site_from_host(host):
    """Return first label if subdomain (site name), else None."""
    if not host:
        return None
    host_only = host.split(":", 1)[0]
    if host_only in (BASE_DOMAIN, "localhost", "127.0.0.1"):
        return None
    if "." in host_only:
        return host_only.split(".")[0]
    return None

# ========== TELEGRAM HELPERS ==========
import asyncio

async def search_user_files_from_telegram(username, site_name):
    """Telegram kanalından kullanıcının dosyalarını ara"""
    try:
        client = await get_telegram_client()
        if not client:
            return None
            
        entity = await client.get_entity(TELEGRAM_CHANNEL)
        
        search_terms = [
            f"{username}_{site_name}",
            f"{site_name} {username}",
            site_name,
            username
        ]
        
        for term in search_terms:
            try:
                messages = await client.get_messages(
                    entity,
                    search=term,
                    filter=InputMessagesFilterDocument,
                    limit=20
                )
                
                for message in messages:
                    if message.document and message.message:
                        # Mesajda kullanıcı ve site adı geçiyor mu kontrol et
                        msg_text = message.message.lower()
                        if username.lower() in msg_text and site_name.lower() in msg_text:
                            return message
            except Exception as e:
                print(f"Telegram search error for term '{term}': {e}")
                continue
        
        return None
    except Exception as e:
        print(f"Telegram search error: {e}")
        return None

async def download_telegram_file(message):
    """Telegram'dan dosya indir"""
    try:
        client = await get_telegram_client()
        if not client:
            return None
        
        # Dosya adını belirle
        file_name = f"telegram_{int(time.time())}_{message.id}.zip"
        if hasattr(message.document, 'attributes'):
            for attr in message.document.attributes:
                if hasattr(attr, 'file_name'):
                    file_name = attr.file_name
                    break
        
        # Dosyayı indir
        download_path = f"temp_{file_name}"
        await client.download_media(message, download_path)
        
        return download_path
    except Exception as e:
        print(f"Telegram download error: {e}")
        return None

def extract_zip_to_site(zip_path, target_base):
    """ZIP dosyasını site dizinine çıkar"""
    try:
        import zipfile
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            # Önce mevcut dosyaları temizle (index.html hariç)
            for item in target_base.iterdir():
                if item.is_file() and item.name != "index.html":
                    item.unlink()
                elif item.is_dir():
                    shutil.rmtree(item)
            
            # ZIP'i çıkar
            zip_ref.extractall(target_base)
        return True
    except Exception as e:
        print(f"ZIP extraction error: {e}")
        return False
    finally:
        # Temp dosyayı sil
        try:
            if os.path.exists(zip_path):
                os.remove(zip_path)
        except:
            pass

def is_recently_synced(site_base):
    """Site son zamanlarda sync edilmiş mi kontrol et"""
    marker = site_base / ".telegram_last_sync"
    if marker.exists():
        try:
            ts = float(marker.read_text())
            return (time.time() - ts) < TELEGRAM_SYNC_INTERVAL
        except Exception:
            return False
    return False

def mark_synced(site_base):
    """Sync zamanını kaydet"""
    marker = site_base / ".telegram_last_sync"
    try:
        marker.write_text(str(time.time()))
    except Exception:
        pass

async def sync_user_site_from_telegram(username, site_name):
    """Telegram'dan site dosyalarını senkronize et"""
    site_public = Path(app.config["UPLOAD_FOLDER"]) / username / site_name / "public_html"
    site_public.mkdir(parents=True, exist_ok=True)
    
    if is_recently_synced(site_public):
        return site_public.exists() and any(site_public.iterdir())
    
    try:
        # Telegram'dan dosya ara
        message = await search_user_files_from_telegram(username, site_name)
        
        if message and message.document:
            print(f"Telegram'dan dosya bulundu: {username}/{site_name}")
            # Dosyayı indir
            zip_path = await download_telegram_file(message)
            
            if zip_path and os.path.exists(zip_path):
                print(f"ZIP indirildi: {zip_path}")
                # ZIP'i çıkar
                if extract_zip_to_site(zip_path, site_public):
                    mark_synced(site_public)
                    update_website_sync_time(site_name)
                    print(f"Telegram'dan site yüklendi: {username}/{site_name}")
                    return True
                else:
                    print(f"ZIP çıkarma hatası: {zip_path}")
            else:
                print(f"ZIP indirilemedi: {username}/{site_name}")
        
        # Telegram'da dosya yoksa, mevcut dosyaları kontrol et
        if site_public.exists() and any(site_public.iterdir()):
            mark_synced(site_public)
            return True
            
        print(f"Telegram'da dosya bulunamadı: {username}/{site_name}")
        return False
    except Exception as e:
        print(f"Telegram sync error for {username}/{site_name}: {e}")
        traceback.print_exc()
        return False

def sync_user_site_sync(username, site_name):
    """Sync fonksiyonunu senkron olarak çalıştır"""
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        result = loop.run_until_complete(sync_user_site_from_telegram(username, site_name))
        loop.close()
        return result
    except Exception as e:
        print(f"Sync error: {e}")
        return False

# ========== AST helper for ENTRY_FILE ==========
def read_entry_file_from_backend(site_base: Path):
    """backend.py dosyasından ENTRY_FILE'ı oku"""
    backend_path = site_base / "backend.py"
    if not backend_path.exists():
        return None
    try:
        src = backend_path.read_text(encoding="utf-8")
        tree = ast.parse(src, filename=str(backend_path))
        for node in tree.body:
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id == "ENTRY_FILE":
                        value = node.value
                        if isinstance(value, ast.Constant) and isinstance(value.value, str):
                            return os.path.basename(value.value)
                        elif isinstance(value, ast.Str):
                            return os.path.basename(value.s)
    except Exception:
        pass
    return None

# ========== HOST DISPATCHER ==========
@app.before_request
def host_dispatcher():
    panel_prefixes = (
        "/login", "/logout", "/register", "/dashboard",
        "/websites", "/create-site", "/file-manager",
        "/api", "/save-file", "/create-file", "/delete-file",
        "/upload-file", "/toggle-site", "/delete-site", "/settings", 
        "/static", "/admin", "/editor"
    )
    
    # Check if request is for panel
    for p in panel_prefixes:
        if request.path.startswith(p):
            return None

    site_name = extract_site_from_host(request.host)
    if not site_name:
        return None

    website = get_website_by_site_name(site_name)
    if not website:
        return "Site not found", 404
    
    user = get_user_by_id(website["user_id"])
    if not user:
        return "User missing", 404

    site_public = safe_site_path(user, site_name)
    
    # Telegram'dan sync et
    synced = sync_user_site_sync(user["username"], site_name)
    
    # Eğer sync başarısız olduysa ve dizin boşsa, default dosya oluştur
    if not synced and (not site_public.exists() or not any(site_public.iterdir())):
        # Default index.html oluştur
        default_html = f"""<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{site_name}</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            text-align: center;
            padding: 50px;
        }}
        .container {{
            max-width: 800px;
            margin: 0 auto;
            background: rgba(255, 255, 255, 0.1);
            padding: 40px;
            border-radius: 20px;
            backdrop-filter: blur(10px);
        }}
        h1 {{ font-size: 3em; margin-bottom: 20px; }}
        .loading {{
            margin: 30px 0;
            font-size: 1.2em;
        }}
        .info {{
            background: rgba(0,0,0,0.2);
            padding: 20px;
            border-radius: 10px;
            margin-top: 30px;
            text-align: left;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🚀 {site_name}</h1>
        <p>Site adresiniz: <strong>{site_name}.{BASE_DOMAIN}</strong></p>
        
        <div class="loading">
            <p>⏳ Telegram'dan dosyalar yükleniyor...</p>
            <p>Bu işlem birkaç saniye sürebilir.</p>
            <p>Sayfa otomatik olarak yenilenecektir.</p>
        </div>
        
        <div class="info">
            <h3>📝 Site Sahibi:</h3>
            <p>Site sahibi henüz dosyalarını yüklemedi veya</p>
            <p>Telegram kanalında dosya bulunamadı.</p>
            <p><strong>Telegram kanalı:</strong> @nabihostingdeposak</p>
        </div>
        
        <script>
            // 10 saniye sonra yenile
            setTimeout(function() {{
                location.reload();
            }}, 10000);
        </script>
    </div>
</body>
</html>"""
        (site_public / "index.html").write_text(default_html, encoding="utf-8")

    rel_path = request.path.lstrip('/')
    if rel_path == "" or rel_path.endswith("/"):
        # Dosya listesini al
        html_files = []
        backend_exists = False
        if site_public.exists():
            for item in site_public.iterdir():
                if item.is_file():
                    if item.name.endswith('.html'):
                        html_files.append(item.name)
                    elif item.name == 'backend.py':
                        backend_exists = True
        
        # Dosya yoksa yükleme ekranı göster
        if len(html_files) == 0:
            loading_html = f"""<!doctype html>
<html><head><meta charset="utf-8"><title>Site yükleniyor...</title>
<meta http-equiv="refresh" content="10">
<style>
    body {{
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        display: flex;
        align-items: center;
        justify-content: center;
        height: 100vh;
        margin: 0;
        text-align: center;
    }}
    .container {{
        max-width: 600px;
        padding: 40px;
        background: rgba(255, 255, 255, 0.1);
        backdrop-filter: blur(10px);
        border-radius: 20px;
        box-shadow: 0 20px 40px rgba(0, 0, 0, 0.2);
    }}
    .loader {{
        border: 5px solid #f3f3f3;
        border-top: 5px solid #3498db;
        border-radius: 50%;
        width: 50px;
        height: 50px;
        animation: spin 2s linear infinite;
        margin: 0 auto 20px;
    }}
    @keyframes spin {{
        0% {{ transform: rotate(0deg); }}
        100% {{ transform: rotate(360deg); }}
    }}
    h1 {{
        margin-bottom: 20px;
        font-size: 2.5em;
    }}
    p {{
        margin-bottom: 10px;
        line-height: 1.6;
    }}
    .note {{
        font-size: 0.9em;
        opacity: 0.8;
        margin-top: 30px;
        padding-top: 20px;
        border-top: 1px solid rgba(255, 255, 255, 0.2);
    }}
</style>
</head>
<body>
  <div class="container">
    <div class="loader"></div>
    <h1>🚀 Site Yükleniyor</h1>
    <p>Telegram kanalından dosyalarınız çekiliyor...</p>
    <p>Bu işlem birkaç dakika sürebilir.</p>
    <p>Lütfen bekleyin, sayfa otomatik olarak yenilenecektir.</p>
    <div class="note">
      <p>📌 Not: Site sahibi dosyalarını Telegram kanalına yüklemelidir.</p>
      <p>📌 Kanal: @nabihostingdeposak</p>
    </div>
  </div>
</body></html>"""
            return loading_html, 200
        
        # Birden fazla HTML dosyası varsa backend.py kontrol et
        elif len(html_files) > 1:
            entry_file = read_entry_file_from_backend(site_public)
            if entry_file and (site_public / entry_file).exists():
                rel_path = entry_file
            else:
                # backend.py zorunlu - kullanıcıya uyarı göster
                files_list = "<br>".join(f"• {file}" for file in html_files)
                warning_html = f"""<!doctype html>
<html><head><meta charset="utf-8"><title>backend.py Gerekli</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
    body {{
        font-family: Arial, sans-serif;
        background: #f0f0f0;
        padding: 20px;
        line-height: 1.6;
    }}
    .warning-box {{
        background: white;
        padding: 30px;
        border-radius: 10px;
        box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        max-width: 800px;
        margin: 40px auto;
    }}
    h1 {{ color: #e74c3c; }}
    .code {{
        background: #2c3e50;
        color: #ecf0f1;
        padding: 15px;
        border-radius: 5px;
        font-family: monospace;
        margin: 20px 0;
        overflow-x: auto;
    }}
    .files-list {{
        background: #f8f9fa;
        padding: 15px;
        border-radius: 5px;
        margin: 20px 0;
    }}
</style>
</head>
<body>
    <div class="warning-box">
        <h1>⚠️ backend.py Dosyası Gerekli</h1>
        <p>Sitenizde birden fazla HTML dosyası bulunuyor. Hangi dosyanın ana sayfa olacağını belirtmek için <strong>backend.py</strong> dosyası oluşturmalısınız.</p>
        
        <div class="code">
# backend.py dosyası içeriği:<br>
ENTRY_FILE = "index.html"  # Ana sayfa olacak dosya adı
        </div>
        
        <p>Mevcut HTML dosyalarınız:</p>
        <div class="files-list">
            {files_list}
        </div>
        
        <p><strong>Nasıl yapılır:</strong></p>
        <ol>
            <li>Site editörüne giriş yapın</li>
            <li>"Yeni Dosya" butonuna tıklayın</li>
            <li>Dosya adı olarak "backend.py" yazın</li>
            <li>İçeriğe yukarıdaki kodu yapıştırın</li>
            <li>Kaydedin ve siteyi yenileyin</li>
        </ol>
        
        <p><em>Not: backend.py sadece ENTRY_FILE sabitini okumak için kullanılır, çalıştırılmaz.</em></p>
    </div>
</body></html>"""
                return warning_html, 400
        
        # Sadece 1 HTML dosyası varsa onu göster
        else:
            rel_path = html_files[0]

    file_path = site_public / rel_path
    if not file_path.exists():
        return "File not found", 404

    if str(file_path).endswith(".php") and website["php_enabled"]:
        return run_php(str(file_path))
    if str(file_path).endswith(".py") and website["python_enabled"]:
        return run_python(str(file_path))
    try:
        return send_file(str(file_path))
    except Exception:
        return "File access error", 500

# ========== PANEL ROUTES ==========
@app.route("/")
def index():
    if get_current_user():
        return redirect("/dashboard")
    return render_template("index.html", base_domain=BASE_DOMAIN)

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")
        email = request.form.get("email", "").strip()
        
        if not username or not password:
            flash("Kullanıcı adı ve şifre gerekli", "danger")
            return redirect("/register")
        if password != confirm:
            flash("Şifreler eşleşmiyor", "danger")
            return redirect("/register")
        if get_user_by_username(username):
            flash("Kullanıcı zaten var", "danger")
            return redirect("/register")
        
        hashed = generate_password_hash(password)
        user_id = create_user(username, hashed, email)
        
        # Kullanıcı klasörünü oluştur
        (Path(app.config["UPLOAD_FOLDER"]) / username).mkdir(parents=True, exist_ok=True)
        
        flash("Kayıt başarılı. Giriş yapabilirsiniz.", "success")
        return redirect("/login")
    
    return render_template("register.html", base_domain=BASE_DOMAIN)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = get_user_by_username(username)
        
        if user and check_password_hash(user["password_hash"], password):
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            flash("Giriş başarılı", "success")
            return redirect("/dashboard")
        
        flash("Kullanıcı veya şifre hatalı", "danger")
        return redirect("/login")
    
    return render_template("login.html", base_domain=BASE_DOMAIN)

@app.route("/logout")
def logout():
    session.clear()
    flash("Çıkış yapıldı", "info")
    return redirect("/")

@app.route("/dashboard")
def dashboard():
    user = get_current_user()
    if not user:
        return redirect("/login")
    
    websites = get_user_websites(user["id"])
    return render_template("dashboard.html", 
                         username=user["username"], 
                         websites=websites, 
                         base_domain=BASE_DOMAIN)

@app.route("/websites")
def websites():
    user = get_current_user()
    if not user:
        return redirect("/login")
    
    websites = get_user_websites(user["id"])
    return render_template("websites.html", 
                         username=user["username"], 
                         websites=websites, 
                         base_domain=BASE_DOMAIN)

@app.route("/create-site", methods=["GET", "POST"])
def create_site():
    user = get_current_user()
    if not user:
        return redirect("/login")
    
    if request.method == "POST":
        site_name = request.form.get("site_name", "").lower().strip()
        site_name = ''.join(c for c in site_name if c.isalnum() or c in '-_')
        
        if not site_name:
            flash("Site adı gerekli", "danger")
            return redirect("/create-site")
        
        if website_exists(site_name):
            flash("Site adı kullanımda", "danger")
            return redirect("/create-site")
        
        domain = f"{site_name}.{BASE_DOMAIN}"
        php_enabled = 1 if request.form.get("php_enabled") else 0
        python_enabled = 1 if request.form.get("python_enabled") else 0
        
        website_id = create_website(user["id"], domain, site_name, php_enabled, python_enabled)
        site_path = Path(app.config["UPLOAD_FOLDER"]) / user["username"] / site_name / "public_html"
        site_path.mkdir(parents=True, exist_ok=True)
        
        # Default HTML dosyası oluştur
        default_html = f"""<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{site_name} - Yeni Site</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            text-align: center;
            padding: 50px;
        }}
        .container {{
            max-width: 800px;
            margin: 0 auto;
            background: rgba(255, 255, 255, 0.1);
            padding: 40px;
            border-radius: 20px;
            backdrop-filter: blur(10px);
        }}
        h1 {{
            font-size: 3em;
            margin-bottom: 20px;
        }}
        .steps {{
            text-align: left;
            margin: 30px 0;
            background: rgba(0,0,0,0.2);
            padding: 20px;
            border-radius: 10px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🎉 {site_name} Yayında!</h1>
        <p>Site adresiniz: <strong>{domain}</strong></p>
        
        <div class="steps">
            <h3>📝 Yapmanız Gerekenler:</h3>
            <ol>
                <li>Site Editörüne gidin</li>
                <li>HTML/CSS/JavaScript kodlarınızı yazın</li>
                <li>Kodlarınızı kaydedin</li>
                <li>Telegram kanalına dosyanız otomatik gönderilecek</li>
                <li>Site adresinizi ziyaret edin: <a href="http://{domain}" style="color:#fff;">{domain}</a></li>
            </ol>
        </div>
        
        <p><em>Not: İlk erişimde site dosyaları Telegram'dan çekilecektir.</em></p>
    </div>
</body>
</html>"""
        (site_path / "index.html").write_text(default_html, encoding="utf-8")
        
        flash(f"Site oluşturuldu: {domain}", "success")
        return redirect("/dashboard")
    
    return render_template("create_site.html", base_domain=BASE_DOMAIN)

@app.route("/editor/<site_name>")
def site_editor(site_name):
    """Site editörü"""
    user = get_current_user()
    if not user:
        return redirect("/login")
    
    website = get_website_by_site_name(site_name)
    if not website or website["user_id"] != user["id"]:
        flash("Site bulunamadı veya erişim izniniz yok", "danger")
        return redirect("/dashboard")
    
    return render_template("editor.html", 
                         site_name=site_name,
                         domain=f"{site_name}.{BASE_DOMAIN}",
                         base_domain=BASE_DOMAIN)

# ========== API ROUTES ==========
@app.route("/api/get-files/<site_name>")
def get_files_list(site_name):
    """Site dosyalarını listele"""
    user = get_current_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    
    website = get_website_by_site_name(site_name)
    if not website or website["user_id"] != user["id"]:
        return jsonify({"error": "Access denied"}), 403
    
    site_path = safe_site_path(user, site_name)
    
    files = []
    if site_path.exists():
        for item in site_path.iterdir():
            if item.is_file():
                files.append({
                    'name': item.name,
                    'size': item.stat().st_size,
                    'modified': datetime.fromtimestamp(item.stat().st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
                    'ext': item.suffix.lower()
                })
    
    return jsonify({"files": files})

@app.route("/api/get-file/<site_name>/<path:filename>")
def get_file_content(site_name, filename):
    """Dosya içeriğini getir"""
    user = get_current_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    
    website = get_website_by_site_name(site_name)
    if not website or website["user_id"] != user["id"]:
        return jsonify({"error": "Access denied"}), 403
    
    site_path = safe_site_path(user, site_name)
    file_path = site_path / filename
    
    if not file_path.exists():
        return jsonify({"error": "File not found"}), 404
    
    try:
        content = file_path.read_text(encoding='utf-8')
        return jsonify({"content": content})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/save-file/<site_name>/<path:filename>", methods=["POST"])
def save_file(site_name, filename):
    """Dosya kaydet"""
    user = get_current_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    
    website = get_website_by_site_name(site_name)
    if not website or website["user_id"] != user["id"]:
        return jsonify({"error": "Access denied"}), 403
    
    content = request.json.get("content", "")
    site_path = safe_site_path(user, site_name)
    file_path = site_path / filename
    
    try:
        # Dosyayı kaydet
        file_path.write_text(content, encoding='utf-8')
        
        # Telegram'a gönder (async olarak)
        thread = threading.Thread(target=send_to_telegram, 
                                args=(user["username"], site_name, site_path))
        thread.start()
        
        return jsonify({"success": True, 
                       "message": "Dosya kaydedildi ve Telegram'a gönderiliyor..."})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/create-file/<site_name>", methods=["POST"])
def create_file(site_name):
    """Yeni dosya oluştur"""
    user = get_current_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    
    website = get_website_by_site_name(site_name)
    if not website or website["user_id"] != user["id"]:
        return jsonify({"error": "Access denied"}), 403
    
    filename = request.json.get("filename", "").strip()
    if not filename:
        return jsonify({"error": "Dosya adı gerekli"}), 400
    
    site_path = safe_site_path(user, site_name)
    file_path = site_path / filename
    
    if file_path.exists():
        return jsonify({"error": "Dosya zaten var"}), 400
    
    try:
        # Default içerik
        if filename.endswith('.html'):
            content = f"""<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{filename}</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f0f0f0;
        }}
        .container {{
            max-width: 800px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        h1 {{ color: #333; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Merhaba Dünya!</h1>
        <p>Bu {filename} dosyasının içeriğidir.</p>
        <p>Kodlarınızı buraya yazabilirsiniz.</p>
    </div>
</body>
</html>"""
        elif filename.endswith('.css'):
            content = """/* CSS dosyanız */
body {
    font-family: Arial, sans-serif;
    margin: 0;
    padding: 0;
    background-color: #f8f9fa;
}

.container {
    max-width: 1200px;
    margin: 0 auto;
    padding: 20px;
}

.header {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    color: white;
    padding: 40px 20px;
    text-align: center;
}

.button {
    background-color: #4CAF50;
    color: white;
    padding: 10px 20px;
    border: none;
    border-radius: 5px;
    cursor: pointer;
}

.button:hover {
    background-color: #45a049;
}"""
        elif filename.endswith('.js'):
            content = """// JavaScript dosyanız

console.log('Merhaba! JavaScript dosyanız çalışıyor.');

// Örnek fonksiyon
function showAlert(message) {
    alert(message);
}

// DOM yüklendiğinde çalışacak kod
document.addEventListener('DOMContentLoaded', function() {
    console.log('Sayfa yüklendi!');
    
    // Örnek: Tüm butonlara tıklama olayı ekle
    const buttons = document.querySelectorAll('.button');
    buttons.forEach(button => {
        button.addEventListener('click', function() {
            alert('Butona tıklandı!');
        });
    });
});"""
        elif filename == 'backend.py':
            content = """# backend.py - Ana sayfa belirleme dosyası
# Bu dosya sadece ENTRY_FILE sabitini okumak için kullanılır
# Sunucuda çalıştırılmaz

ENTRY_FILE = "index.html"  # Ana sayfa olacak dosya adı
"""
        else:
            content = f"# {filename}\n\nBu dosyanın içeriği."
        
        file_path.write_text(content, encoding='utf-8')
        return jsonify({"success": True, "message": "Dosya oluşturuldu"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/delete-file/<site_name>/<path:filename>", methods=["DELETE"])
def delete_file(site_name, filename):
    """Dosya sil"""
    user = get_current_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    
    website = get_website_by_site_name(site_name)
    if not website or website["user_id"] != user["id"]:
        return jsonify({"error": "Access denied"}), 403
    
    site_path = safe_site_path(user, site_name)
    file_path = site_path / filename
    
    if not file_path.exists():
        return jsonify({"error": "Dosya bulunamadı"}), 404
    
    try:
        file_path.unlink()
        return jsonify({"success": True, "message": "Dosya silindi"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/delete-site/<site_name>", methods=["DELETE"])
def delete_site_api(site_name):
    """Site sil"""
    user = get_current_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    
    website = get_website_by_site_name(site_name)
    if not website or website["user_id"] != user["id"]:
        return jsonify({"error": "Access denied"}), 403
    
    try:
        # Database'den sil
        conn = get_db_connection()
        conn.execute('DELETE FROM websites WHERE site_name = ? AND user_id = ?', 
                    (site_name, user["id"]))
        conn.commit()
        conn.close()
        
        # Dosyaları sil
        site_dir = Path(app.config["UPLOAD_FOLDER"]) / user["username"] / site_name
        if site_dir.exists():
            shutil.rmtree(site_dir)
        
        return jsonify({"success": True, "message": "Site silindi"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ========== TELEGRAM SEND FUNCTIONS ==========
import threading
import zipfile

def send_to_telegram(username, site_name, site_path):
    """Site dosyalarını Telegram kanalına gönder"""
    try:
        import asyncio
        
        # ZIP dosyası oluştur
        zip_filename = f"temp_{username}_{site_name}_{int(time.time())}.zip"
        zip_path = Path(zip_filename)
        
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for root, dirs, files in os.walk(site_path):
                for file in files:
                    file_path = Path(root) / file
                    arcname = file_path.relative_to(site_path)
                    zipf.write(file_path, arcname)
        
        # Async fonksiyonu çalıştır
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(send_telegram_file(username, site_name, zip_path))
        loop.close()
        
    except Exception as e:
        print(f"Telegram gönderme hatası: {e}")
    finally:
        # Temp dosyayı sil
        try:
            if zip_path.exists():
                zip_path.unlink()
        except:
            pass

async def send_telegram_file(username, site_name, zip_path):
    """Telegram'a dosya gönder"""
    try:
        client = await get_telegram_client()
        if not client:
            print("Telegram client bulunamadı")
            return
        
        entity = await client.get_entity(TELEGRAM_CHANNEL)
        
        caption = f"""
📁 Site Güncellendi
👤 Kullanıcı: {username}
🌐 Site: {site_name}
🔗 Link: {site_name}.{BASE_DOMAIN}
⏰ Zaman: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Dosya otomatik olarak gönderilmiştir.
"""
        
        await client.send_file(
            entity,
            file=zip_path,
            caption=caption
        )
        print(f"Telegram'a gönderildi: {username}/{site_name}")
        
    except Exception as e:
        print(f"Telegram gönderme hatası: {e}")

# ========== ADMIN ==========
@app.route("/admin/create-admin")
def create_admin():
    conn = get_db_connection()
    admin_exists = conn.execute('SELECT 1 FROM users WHERE username = ?', ("admin",)).fetchone()
    if not admin_exists:
        hashed = generate_password_hash("admin123")
        conn.execute(
            'INSERT INTO users (username, password_hash, email, is_admin) VALUES (?, ?, ?, ?)',
            ("admin", hashed, "admin@local", 1)
        )
        conn.commit()
        conn.close()
        return "Admin created: admin / admin123"
    conn.close()
    return "Admin exists"

# ========== INIT ==========
def init_app():
    init_database()
    Path(app.config["UPLOAD_FOLDER"]).mkdir(parents=True, exist_ok=True)
    print("="*40)
    print("NABI HOSTING STARTING")
    print(f"DOMAIN: {BASE_DOMAIN}")
    print(f"TELEGRAM CHANNEL: {TELEGRAM_CHANNEL}")
    print("Storage: Telegram Channel")
    print("Database: SQLite3")
    print("="*40)

if __name__ == "__main__":
    init_app()
    debug = os.environ.get("DEBUG","False").lower() == "true"
    app.run(host="0.0.0.0", port=PORT, debug=debug, use_reloader=False)
