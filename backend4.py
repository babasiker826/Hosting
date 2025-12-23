# backend.py - NABI HOSTING (Telegram Depolama ile)
import os
import sys
import time
import json
import sqlite3
import zipfile
import threading
import asyncio
from datetime import datetime
from pathlib import Path

from flask import (
    Flask, render_template, request, redirect, url_for, session,
    jsonify, send_file, flash, render_template_string, make_response
)
from werkzeug.security import generate_password_hash, check_password_hash

import requests
import subprocess
import shutil

# ========== CONFIG ==========
BASE_DOMAIN = os.environ.get("BASE_DOMAIN", "x.2026tr.xyz")
PORT = int(os.environ.get("PORT", 5000))
DEBUG_MODE = os.environ.get("DEBUG", "False").lower() == "true"

# ========== TELEGRAM CONFIG ==========
API_ID = 24179304
API_HASH = "6fdbaf87f6fa54a1a8a51603bf38c2d1"
SESSION_STRING = "1ApWapzMBu00TcO02cRYREPfQ8ubOErEnIYktiYxvfa9JTCId4Yh7myle5Lw9i8T1LqkrVGLOYlQjTiPx1QrSTTxLPBbqtMGxkgYrojwYDWYS-Vjrm-9viL9wcbgsEh5QH-6PIht93hyaKsZXuDXlBO0SlpU2xhuqLAh_-0Qe7sCgWnCpBtszPJGFuvQVSKUz0Kt2Cj4OXDBQp8I4pvogCOlXO1Rj5QP4aSM6pKYxvg8uC9zPLBxdG__rZI7Mg3GmYaFOPHg32-k2co9YyP701pjpEXJHj_1bjbuEU2Q0Fr2yHKiYWEy-JyAz_xRHx06hAzmexHQvP2oZ7mKw1g4jIdbUSMmG4X0="
TELEGRAM_CHANNEL = "nabihostingdeposak"
TELEGRAM_SYNC_INTERVAL = 300  # 5 dakika

# ========== FLASK APP ==========
app = Flask(__name__, template_folder="templates", static_folder="static")
app.secret_key = os.environ.get("SECRET_KEY", "nabi_hosting_secure_key_2024")
app.config["UPLOAD_FOLDER"] = "user_files"
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB

# ========== TELEGRAM CLIENT ==========
TELEGRAM_AVAILABLE = False
telegram_client = None

try:
    from telethon import TelegramClient
    from telethon.sessions import StringSession
    from telethon.tl.types import InputMessagesFilterDocument
    
    TELEGRAM_AVAILABLE = True
    print("✅ Telethon yüklendi - Telegram özellikleri aktif")
    
    # Async client başlatma
    async def init_telegram():
        global telegram_client
        try:
            telegram_client = TelegramClient(
                StringSession(SESSION_STRING),
                API_ID,
                API_HASH
            )
            await telegram_client.start()
            print("✅ Telegram client başlatıldı")
            return telegram_client
        except Exception as e:
            print(f"❌ Telegram client başlatılamadı: {e}")
            return None
    
    # Client'ı async olarak başlat
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(init_telegram())
    loop.close()
    
except ImportError as e:
    print(f"⚠️ Telethon yüklenemedi: {e}")
    print("⚠️ Telegram özellikleri devre dışı - lokal depolama kullanılacak")

# ========== DATABASE ==========
def get_db():
    conn = sqlite3.connect('hosting.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cursor = conn.cursor()
    
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
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS websites (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            domain TEXT UNIQUE NOT NULL,
            site_name TEXT UNIQUE NOT NULL,
            status TEXT DEFAULT 'active',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_sync TIMESTAMP
        )
    ''')
    
    conn.commit()
    conn.close()
    print("✅ Database initialized")

# ========== DATABASE HELPERS ==========
def get_current_user():
    if "user_id" in session:
        conn = get_db()
        user = conn.execute('SELECT * FROM users WHERE id = ?', (session["user_id"],)).fetchone()
        conn.close()
        return user
    return None

def get_user_by_username(username):
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    conn.close()
    return user

def create_user(username, password, email=""):
    hashed = generate_password_hash(password)
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute('INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)',
                      (username, hashed, email))
        user_id = cursor.lastrowid
        conn.commit()
        return user_id
    finally:
        conn.close()

def get_website_by_name(site_name):
    conn = get_db()
    website = conn.execute(
        'SELECT * FROM websites WHERE site_name = ? AND status = ?',
        (site_name, 'active')
    ).fetchone()
    conn.close()
    return website

def get_user_websites(user_id):
    conn = get_db()
    websites = conn.execute(
        'SELECT * FROM websites WHERE user_id = ? ORDER BY created_at DESC',
        (user_id,)
    ).fetchall()
    conn.close()
    return websites

def create_website(user_id, site_name):
    domain = f"{site_name}.{BASE_DOMAIN}"
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute(
            'INSERT INTO websites (user_id, domain, site_name) VALUES (?, ?, ?)',
            (user_id, domain, site_name)
        )
        website_id = cursor.lastrowid
        conn.commit()
        
        # Kullanıcı klasörünü oluştur
        user_dir = Path(app.config["UPLOAD_FOLDER"]) / str(user_id) / site_name / "public_html"
        user_dir.mkdir(parents=True, exist_ok=True)
        
        # Default index.html oluştur
        default_html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>{site_name} - NABI Hosting</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            background: linear-gradient(135deg, #667eea, #764ba2);
            color: white;
            text-align: center;
            padding: 50px;
            margin: 0;
        }}
        .container {{
            background: rgba(255,255,255,0.1);
            backdrop-filter: blur(10px);
            padding: 40px;
            border-radius: 20px;
            display: inline-block;
            margin-top: 50px;
        }}
        h1 {{ font-size: 3em; margin: 0; }}
        .btn {{
            display: inline-block;
            background: white;
            color: #667eea;
            padding: 12px 24px;
            margin: 10px;
            border-radius: 50px;
            text-decoration: none;
            font-weight: bold;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🚀 {site_name}</h1>
        <p>Site yayında: <strong>{domain}</strong></p>
        <p>Site sahibi henüz içerik eklememiş.</p>
        <div style="margin-top: 30px;">
            <a href="https://{BASE_DOMAIN}/editor/{site_name}" class="btn">✏️ Siteyi Düzenle</a>
            <a href="https://{BASE_DOMAIN}/dashboard" class="btn">📊 Kontrol Paneli</a>
        </div>
        <p style="margin-top: 30px; font-size: 0.9em; opacity: 0.8;">
            📢 Dosyalar Telegram kanalında saklanır: @nabihostingdeposak
        </p>
    </div>
</body>
</html>"""
        
        (user_dir / "index.html").write_text(default_html, encoding='utf-8')
        
        # Telegram'a gönder
        if TELEGRAM_AVAILABLE:
            thread = threading.Thread(target=send_to_telegram, 
                                    args=(user_id, site_name, user_dir))
            thread.start()
        
        return website_id
    finally:
        conn.close()

# ========== TELEGRAM FUNCTIONS ==========
async def search_telegram_files(username, site_name):
    """Telegram'dan kullanıcı dosyalarını ara"""
    if not TELEGRAM_AVAILABLE or not telegram_client:
        return None
    
    try:
        entity = await telegram_client.get_entity(TELEGRAM_CHANNEL)
        
        # Arama terimleri
        search_terms = [
            f"{username} {site_name}",
            f"{site_name}.zip",
            f"{username}_{site_name}"
        ]
        
        for term in search_terms:
            try:
                messages = await telegram_client.get_messages(
                    entity,
                    search=term,
                    filter=InputMessagesFilterDocument,
                    limit=10
                )
                
                for msg in messages:
                    if msg.document and msg.message:
                        msg_text = msg.message.lower()
                        if username.lower() in msg_text and site_name.lower() in msg_text:
                            return msg
            except:
                continue
        
        return None
    except Exception as e:
        print(f"❌ Telegram search error: {e}")
        return None

async def download_from_telegram(message):
    """Telegram'dan dosya indir"""
    if not TELEGRAM_AVAILABLE or not telegram_client:
        return None
    
    try:
        # Geçici dosya adı
        file_name = f"telegram_download_{int(time.time())}.zip"
        
        # Dosyayı indir
        await telegram_client.download_media(message, file_name)
        
        if os.path.exists(file_name):
            return file_name
        return None
    except Exception as e:
        print(f"❌ Telegram download error: {e}")
        return None

def sync_site_from_telegram(user_id, username, site_name):
    """Telegram'dan site dosyalarını senkronize et"""
    site_dir = Path(app.config["UPLOAD_FOLDER"]) / str(user_id) / site_name / "public_html"
    site_dir.mkdir(parents=True, exist_ok=True)
    
    # Sync marker kontrolü
    sync_marker = site_dir / ".last_sync"
    if sync_marker.exists():
        try:
            last_sync = float(sync_marker.read_text())
            if time.time() - last_sync < TELEGRAM_SYNC_INTERVAL:
                print(f"✅ {site_name} zaten sync edilmiş")
                return True
        except:
            pass
    
    if not TELEGRAM_AVAILABLE:
        print(f"⚠️ Telegram yok, lokal dosyalar kullanılıyor: {site_name}")
        return True
    
    try:
        # Async fonksiyonu çalıştır
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        # Telegram'dan dosya ara
        message = loop.run_until_complete(search_telegram_files(username, site_name))
        
        if message and message.document:
            print(f"📥 Telegram'dan dosya bulundu: {site_name}")
            
            # Dosyayı indir
            zip_path = loop.run_until_complete(download_from_telegram(message))
            
            if zip_path and os.path.exists(zip_path):
                # Eski dosyaları temizle
                for item in site_dir.iterdir():
                    if item.is_file():
                        item.unlink()
                    elif item.is_dir():
                        shutil.rmtree(item)
                
                # ZIP'i çıkar
                with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                    zip_ref.extractall(site_dir)
                
                # Sync zamanını kaydet
                sync_marker.write_text(str(time.time()))
                
                # Database'de sync zamanını güncelle
                conn = get_db()
                conn.execute(
                    'UPDATE websites SET last_sync = CURRENT_TIMESTAMP WHERE site_name = ?',
                    (site_name,)
                )
                conn.commit()
                conn.close()
                
                # Temp dosyayı sil
                os.remove(zip_path)
                
                print(f"✅ {site_name} Telegram'dan sync edildi")
                return True
        
        print(f"ℹ️ Telegram'da dosya bulunamadı: {site_name}")
        return False
        
    except Exception as e:
        print(f"❌ Sync error for {site_name}: {e}")
        return False
    finally:
        if 'loop' in locals():
            loop.close()

def send_to_telegram(user_id, site_name, site_dir):
    """Site dosyalarını Telegram'a gönder"""
    if not TELEGRAM_AVAILABLE:
        return
    
    try:
        # ZIP oluştur
        zip_name = f"{user_id}_{site_name}_{int(time.time())}.zip"
        
        with zipfile.ZipFile(zip_name, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for root, dirs, files in os.walk(site_dir):
                for file in files:
                    file_path = Path(root) / file
                    arcname = file_path.relative_to(site_dir)
                    zipf.write(file_path, arcname)
        
        # Async olarak gönder
        async def send_async():
            try:
                if not telegram_client:
                    await init_telegram()
                
                entity = await telegram_client.get_entity(TELEGRAM_CHANNEL)
                
                caption = f"""
📁 Site Güncellendi
👤 User ID: {user_id}
🌐 Site: {site_name}
🔗 Link: {site_name}.{BASE_DOMAIN}
⏰ Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
                """
                
                await telegram_client.send_file(
                    entity,
                    file=zip_name,
                    caption=caption
                )
                print(f"✅ Telegram'a gönderildi: {site_name}")
            except Exception as e:
                print(f"❌ Telegram send error: {e}")
        
        # Gönderimi başlat
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(send_async())
        loop.close()
        
        # Temp ZIP'i sil
        if os.path.exists(zip_name):
            os.remove(zip_name)
            
    except Exception as e:
        print(f"❌ Telegram send error: {e}")

# ========== HOST DISPATCHER ==========
@app.before_request
def host_dispatcher():
    host = request.host.lower().split(':')[0]
    path = request.path
    
    print(f"🌐 HOST: {host} | PATH: {path}")
    
    # Panel routes
    panel_paths = ['/login', '/logout', '/register', '/dashboard',
                   '/websites', '/create-site', '/editor', '/api',
                   '/static', '/admin', '/favicon.ico']
    
    for panel_path in panel_paths:
        if path.startswith(panel_path):
            print(f"📊 Panel route: {path}")
            return None
    
    # Subdomain kontrolü
    if host.endswith(BASE_DOMAIN):
        # Site adını çıkar: nabi.x.2026tr.xyz -> nabi
        site_name = host.replace(f'.{BASE_DOMAIN}', '')
        
        print(f"🔍 Subdomain detected: {site_name}")
        
        # Ana domain ise dashboard göster
        if site_name in ['www', ''] or site_name == BASE_DOMAIN.replace('.', ''):
            return redirect(f'https://{BASE_DOMAIN}/dashboard')
        
        # Database'de site var mı?
        website = get_website_by_name(site_name)
        if not website:
            return f"""
            <html><body style="font-family:Arial;padding:50px;text-align:center">
            <h1>❌ Site Bulunamadı</h1>
            <p><strong>{site_name}.{BASE_DOMAIN}</strong> adında bir site yok.</p>
            <p>Kontrol panelinden site oluşturun.</p>
            <a href="https://{BASE_DOMAIN}/dashboard">Kontrol Paneli</a>
            </body></html>""", 404
        
        # Kullanıcıyı al
        user_id = website['user_id']
        conn = get_db()
        user = conn.execute('SELECT username FROM users WHERE id = ?', (user_id,)).fetchone()
        conn.close()
        
        if not user:
            return "Kullanıcı bulunamadı", 404
        
        username = user['username']
        
        # TELEGRAM'dan dosyaları sync et
        print(f"🔄 {site_name} için Telegram sync başlatılıyor...")
        sync_result = sync_site_from_telegram(user_id, username, site_name)
        
        if not sync_result:
            print(f"⚠️ {site_name} sync başarısız, lokal dosyalar kullanılıyor")
        
        # Site dizini
        site_dir = Path(app.config["UPLOAD_FOLDER"]) / str(user_id) / site_name / "public_html"
        
        # Dosya servis et
        rel_path = path.lstrip('/')
        if not rel_path:
            rel_path = "index.html"
        
        file_path = site_dir / rel_path
        
        if file_path.exists() and file_path.is_file():
            print(f"📁 Serving: {file_path}")
            return send_file(str(file_path))
        
        # Dosya yoksa loading sayfası göster
        loading_html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>{site_name} - Yükleniyor</title>
    <meta http-equiv="refresh" content="5">
    <style>
        body {{
            font-family: Arial, sans-serif;
            background: linear-gradient(135deg, #667eea, #764ba2);
            color: white;
            text-align: center;
            padding: 50px;
        }}
        .loader {{
            border: 5px solid #f3f3f3;
            border-top: 5px solid #3498db;
            border-radius: 50%;
            width: 50px;
            height: 50px;
            animation: spin 2s linear infinite;
            margin: 20px auto;
        }}
        @keyframes spin {{
            0% {{ transform: rotate(0deg); }}
            100% {{ transform: rotate(360deg); }}
        }}
    </style>
</head>
<body>
    <div class="loader"></div>
    <h1>🚀 Site Yükleniyor</h1>
    <p>Telegram'dan dosyalar çekiliyor: {site_name}.{BASE_DOMAIN}</p>
    <p>Bu işlem birkaç saniye sürebilir...</p>
    <p><small>Sayfa otomatik yenilenecek</small></p>
</body>
</html>"""
        return loading_html, 200
    
    # Unknown host
    return "Geçersiz domain", 400

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
        email = request.form.get("email", "")
        
        if not username or not password:
            flash("Kullanıcı adı ve şifre gerekli", "danger")
            return redirect("/register")
        
        if get_user_by_username(username):
            flash("Bu kullanıcı adı zaten var", "danger")
            return redirect("/register")
        
        user_id = create_user(username, password, email)
        session["user_id"] = user_id
        session["username"] = username
        
        flash("Kayıt başarılı! Hoş geldiniz.", "success")
        return redirect("/dashboard")
    
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
            flash("Giriş başarılı!", "success")
            return redirect("/dashboard")
        
        flash("Kullanıcı adı veya şifre hatalı", "danger")
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
        
        # Site adı kontrolü
        conn = get_db()
        existing = conn.execute('SELECT 1 FROM websites WHERE site_name = ?', (site_name,)).fetchone()
        conn.close()
        
        if existing:
            flash("Bu site adı zaten kullanımda", "danger")
            return redirect("/create-site")
        
        # Site oluştur
        site_id = create_website(user["id"], site_name)
        
        flash(f"Site oluşturuldu: {site_name}.{BASE_DOMAIN}", "success")
        return redirect("/dashboard")
    
    return render_template("create_site.html", base_domain=BASE_DOMAIN)

@app.route("/editor/<site_name>")
def site_editor(site_name):
    user = get_current_user()
    if not user:
        return redirect("/login")
    
    website = get_website_by_name(site_name)
    if not website or website["user_id"] != user["id"]:
        flash("Bu siteye erişim izniniz yok", "danger")
        return redirect("/dashboard")
    
    return render_template("editor.html",
                         site_name=site_name,
                         domain=f"{site_name}.{BASE_DOMAIN}",
                         base_domain=BASE_DOMAIN)

# ========== API ROUTES ==========
@app.route("/api/save-file/<site_name>/<filename>", methods=["POST"])
def api_save_file(site_name, filename):
    user = get_current_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    
    website = get_website_by_name(site_name)
    if not website or website["user_id"] != user["id"]:
        return jsonify({"error": "Access denied"}), 403
    
    content = request.json.get("content", "")
    
    # Dosyayı kaydet
    site_dir = Path(app.config["UPLOAD_FOLDER"]) / str(user["id"]) / site_name / "public_html"
    site_dir.mkdir(parents=True, exist_ok=True)
    
    file_path = site_dir / filename
    file_path.write_text(content, encoding='utf-8')
    
    # Telegram'a gönder
    if TELEGRAM_AVAILABLE:
        thread = threading.Thread(target=send_to_telegram,
                                args=(user["id"], site_name, site_dir))
        thread.start()
        telegram_msg = " ve Telegram'a gönderildi"
    else:
        telegram_msg = ""
    
    return jsonify({
        "success": True,
        "message": f"Dosya kaydedildi{telegram_msg}"
    })

# ========== INIT ==========
def init_app():
    init_db()
    Path(app.config["UPLOAD_FOLDER"]).mkdir(parents=True, exist_ok=True)
    
    print("="*50)
    print("🚀 NABI HOSTING BAŞLATILIYOR")
    print(f"🌐 Domain: {BASE_DOMAIN}")
    print(f"📱 Telegram: {'AKTİF' if TELEGRAM_AVAILABLE else 'PASİF'}")
    print(f"💾 Depolama: {'Telegram + Lokal' if TELEGRAM_AVAILABLE else 'Sadece Lokal'}")
    print("="*50)

if __name__ == "__main__":
    init_app()
    app.run(host="0.0.0.0", port=PORT, debug=DEBUG_MODE)
