# backend.py - FREEHOST v3.0 (Custom TLD Support)
import os
import sys
import time
import json
import sqlite3
import zipfile
import threading
import asyncio
import re
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

BASE_DOMAIN = os.environ.get("BASE_DOMAIN", "x.2026tr.xyz")
PORT = int(os.environ.get("PORT", 5000))
DEBUG_MODE = os.environ.get("DEBUG", "False").lower() == "true"

API_ID = 24179304
API_HASH = "6fdbaf87f6fa54a1a8a51603bf38c2d1"
SESSION_STRING = "1ApWapzMBu00TcO02cRYREPfQ8ubOErEnIYktiYxvfa9JTCId4Yh7myle5Lw9i8T1LqkrVGLOYlQjTiPx1QrSTTxLPBbqtMGxkgYrojwYDWYS-Vjrm-9viL9wcbgsEh5QH-6PIht93hyaKsZXuDXlBO0SlpU2xhuqLAh_-0Qe7sCgWnCpBtszPJGFuvQVSKUz0Kt2Cj4OXDBQp8I4pvogCOlXO1Rj5QP4aSM6pKYxvg8uC9zPLBxdG__rZI7Mg3GmYaFOPHg32-k2co9YyP701pjpEXJHj_1bjbuEU2Q0Fr2yHKiYWEy-JyAz_xRHx06hAzmexHQvP2oZ7mKw1g4jIdbUSMmG4X0="
TELEGRAM_CHANNEL = "nabihostingdeposak"
TELEGRAM_SYNC_INTERVAL = 300

app = Flask(__name__, template_folder="templates", static_folder="static")
app.secret_key = os.environ.get("SECRET_KEY", "freehost_secure_key_2024")
app.config["UPLOAD_FOLDER"] = "user_files"
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024

TELEGRAM_AVAILABLE = False
telegram_client = None

try:
    from telethon import TelegramClient
    from telethon.sessions import StringSession
    from telethon.tl.types import InputMessagesFilterDocument
    
    TELEGRAM_AVAILABLE = True
    print("✅ Cloud sync aktif")
    
    async def init_telegram():
        global telegram_client
        try:
            telegram_client = TelegramClient(
                StringSession(SESSION_STRING),
                API_ID,
                API_HASH
            )
            await telegram_client.start()
            print("✅ Cloud baglantisi baslatildi")
            return telegram_client
        except Exception as e:
            print(f"❌ Cloud baglantisi baslatilamadi: {e}")
            return None
    
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(init_telegram())
    loop.close()
    
except ImportError as e:
    print(f"⚠️ Cloud modulu yuklenemedi: {e}")
    print("⚠️ Cloud ozellikleri devre disi - lokal depolama kullanilacak")

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
            site_name TEXT UNIQUE NOT NULL,
            tld TEXT NOT NULL DEFAULT '.com',
            full_path TEXT UNIQUE NOT NULL,
            status TEXT DEFAULT 'active',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_sync TIMESTAMP
        )
    ''')
    
    conn.commit()
    conn.close()
    print("✅ Database hazir")

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

def get_website_by_path(full_path):
    conn = get_db()
    website = conn.execute(
        'SELECT * FROM websites WHERE full_path = ? AND status = ?',
        (full_path, 'active')
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

def create_website(user_id, site_name, tld):
    site_name = re.sub(r'[^a-zA-Z0-9\-_]', '', site_name.lower())
    tld = tld.lower()
    
    valid_tlds = ['.com', '.net', '.org', '.xyz', '.info', '.site', '.online']
    if tld not in valid_tlds:
        tld = '.com'
    
    full_path = f"{site_name}{tld}"
    
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute(
            'INSERT INTO websites (user_id, site_name, tld, full_path) VALUES (?, ?, ?, ?)',
            (user_id, site_name, tld, full_path)
        )
        website_id = cursor.lastrowid
        conn.commit()
        
        site_dir = Path(app.config["UPLOAD_FOLDER"]) / full_path / "public_html"
        site_dir.mkdir(parents=True, exist_ok=True)
        
        default_html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>{full_path} - FreeHost</title>
    <style>
        body {{
            background: black;
            color: white;
            font-family: monospace;
            margin: 0;
            padding: 0;
            height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            text-align: center;
        }}
        .container {{
            border: 1px solid #333;
            padding: 40px;
            border-radius: 0;
            max-width: 600px;
        }}
        .url {{
            color: #0f0;
            font-family: monospace;
            margin: 20px 0;
            padding: 10px;
            background: #111;
            border: 1px solid #333;
        }}
        a {{
            color: #0f0;
            text-decoration: none;
            border: 1px solid #333;
            padding: 8px 16px;
            margin: 5px;
        }}
        a:hover {{
            background: #222;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>FREEHOST</h1>
        <div class="url">{BASE_DOMAIN}/{full_path}</div>
        <p>Site sahibi henuz icerik eklememis.</p>
        <div>
            <a href="https://{BASE_DOMAIN}/editor/{full_path}">Siteyi Duzenle</a>
            <a href="https://{BASE_DOMAIN}/dashboard">Kontrol Paneli</a>
        </div>
    </div>
</body>
</html>"""
        
        (site_dir / "index.html").write_text(default_html, encoding='utf-8')
        
        if TELEGRAM_AVAILABLE:
            thread = threading.Thread(target=send_to_telegram, 
                                    args=(user_id, full_path, site_dir))
            thread.start()
        
        return website_id
    finally:
        conn.close()

async def search_telegram_files(user_id, full_path):
    if not TELEGRAM_AVAILABLE or not telegram_client:
        return None
    
    try:
        entity = await telegram_client.get_entity(TELEGRAM_CHANNEL)
        
        search_terms = [
            f"User ID: {user_id} Site: {full_path}",
            f"{full_path}.zip",
            f"{user_id}_{full_path}"
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
                        if str(user_id) in msg_text and full_path.lower() in msg_text:
                            return msg
            except:
                continue
        
        return None
    except Exception as e:
        print(f"❌ Cloud arama hatasi: {e}")
        return None

async def download_from_telegram(message):
    if not TELEGRAM_AVAILABLE or not telegram_client:
        return None
    
    try:
        file_name = f"cloud_download_{int(time.time())}.zip"
        await telegram_client.download_media(message, file_name)
        
        if os.path.exists(file_name):
            return file_name
        return None
    except Exception as e:
        print(f"❌ Cloud indirme hatasi: {e}")
        return None

def sync_site_from_telegram(user_id, full_path):
    site_dir = Path(app.config["UPLOAD_FOLDER"]) / full_path / "public_html"
    site_dir.mkdir(parents=True, exist_ok=True)
    
    sync_marker = site_dir / ".last_sync"
    if sync_marker.exists():
        try:
            last_sync = float(sync_marker.read_text())
            if time.time() - last_sync < TELEGRAM_SYNC_INTERVAL:
                print(f"✅ {full_path} zaten senkronize")
                return True
        except:
            pass
    
    if not TELEGRAM_AVAILABLE:
        print(f"⚠️ Cloud yok, lokal dosyalar kullaniliyor: {full_path}")
        return True
    
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        message = loop.run_until_complete(search_telegram_files(user_id, full_path))
        
        if message and message.document:
            print(f"📥 Cloud'dan dosya bulundu: {full_path}")
            
            zip_path = loop.run_until_complete(download_from_telegram(message))
            
            if zip_path and os.path.exists(zip_path):
                for item in site_dir.iterdir():
                    if item.is_file():
                        item.unlink()
                    elif item.is_dir():
                        shutil.rmtree(item)
                
                with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                    zip_ref.extractall(site_dir)
                
                sync_marker.write_text(str(time.time()))
                
                conn = get_db()
                conn.execute(
                    'UPDATE websites SET last_sync = CURRENT_TIMESTAMP WHERE full_path = ?',
                    (full_path,)
                )
                conn.commit()
                conn.close()
                
                os.remove(zip_path)
                print(f"✅ {full_path} Cloud'dan senkronize edildi")
                return True
        
        print(f"ℹ️ Cloud'da dosya bulunamadi: {full_path}")
        return False
        
    except Exception as e:
        print(f"❌ Senkronizasyon hatasi {full_path}: {e}")
        return False
    finally:
        if 'loop' in locals():
            loop.close()

def send_to_telegram(user_id, full_path, site_dir):
    if not TELEGRAM_AVAILABLE:
        return
    
    try:
        zip_name = f"{user_id}_{full_path}_{int(time.time())}.zip"
        
        with zipfile.ZipFile(zip_name, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for root, dirs, files in os.walk(site_dir):
                for file in files:
                    file_path = Path(root) / file
                    arcname = file_path.relative_to(site_dir)
                    zipf.write(file_path, arcname)
        
        async def send_async():
            try:
                if not telegram_client:
                    await init_telegram()
                
                entity = await telegram_client.get_entity(TELEGRAM_CHANNEL)
                
                caption = f"""
📁 Site Guncellendi
👤 User ID: {user_id}
🌐 Site: {full_path}
🔗 Link: {BASE_DOMAIN}/{full_path}
⏰ Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
                """
                
                await telegram_client.send_file(
                    entity,
                    file=zip_name,
                    caption=caption
                )
                print(f"✅ Cloud'a gonderildi: {full_path}")
            except Exception as e:
                print(f"❌ Cloud gonderim hatasi: {e}")
        
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(send_async())
        loop.close()
        
        if os.path.exists(zip_name):
            os.remove(zip_name)
            
    except Exception as e:
        print(f"❌ Cloud gonderim hatasi: {e}")

@app.before_request
def host_dispatcher():
    host = request.host.lower().split(':')[0]
    path = request.path
    
    print(f"🌐 HOST: {host} | PATH: {path}")
    
    panel_paths = ['/login', '/logout', '/register', '/dashboard',
                   '/websites', '/create-site', '/editor', '/api',
                   '/static', '/admin', '/favicon.ico']
    
    for panel_path in panel_paths:
        if path.startswith(panel_path):
            print(f"📊 Panel route: {path}")
            return None
    
    if host == BASE_DOMAIN or host == f"www.{BASE_DOMAIN}":
        if path == '/':
            return None
        
        if path.startswith('/'):
            site_path = path[1:]
            
            import re
            tld_pattern = r'^[a-zA-Z0-9\-_]+\.(com|net|org|xyz|info|site|online)$'
            
            if re.match(tld_pattern, site_path):
                print(f"🔍 Site path detected: {site_path}")
                
                website = get_website_by_path(site_path)
                if not website:
                    return render_template('404.html', 
                                         site_path=site_path, 
                                         base_domain=BASE_DOMAIN), 404
                
                user_id = website['user_id']
                
                print(f"🔄 {site_path} icin senkronizasyon baslatiliyor...")
                sync_result = sync_site_from_telegram(user_id, site_path)
                
                if not sync_result:
                    print(f"⚠️ {site_path} senkronizasyon basarisiz, lokal dosyalar kullaniliyor")
                
                site_dir = Path(app.config["UPLOAD_FOLDER"]) / site_path / "public_html"
                
                remaining_path = path[len('/' + site_path):]
                if not remaining_path:
                    remaining_path = "/index.html"
                elif remaining_path == "/":
                    remaining_path = "/index.html"
                
                file_path = site_dir / remaining_path.lstrip('/')
                
                if file_path.exists() and file_path.is_file():
                    print(f"📁 Serving: {file_path}")
                    return send_file(str(file_path))
                
                return render_template('loading.html',
                                     site_path=site_path,
                                     base_domain=BASE_DOMAIN), 200
    
    return "Gecersiz istek", 400

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
            flash("Kullanici adi ve sifre gerekli", "danger")
            return redirect("/register")
        
        if get_user_by_username(username):
            flash("Bu kullanici adi zaten var", "danger")
            return redirect("/register")
        
        user_id = create_user(username, password, email)
        session["user_id"] = user_id
        session["username"] = username
        
        flash("Kayit basarili! Hos geldiniz.", "success")
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
            flash("Giris basarili!", "success")
            return redirect("/dashboard")
        
        flash("Kullanici adi veya sifre hatali", "danger")
        return redirect("/login")
    
    return render_template("login.html", base_domain=BASE_DOMAIN)

@app.route("/logout")
def logout():
    session.clear()
    flash("Cikis yapildi", "info")
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
        site_name = request.form.get("site_name", "").strip()
        tld = request.form.get("tld", ".com")
        
        if not site_name:
            flash("Site adi gerekli", "danger")
            return redirect("/create-site")
        
        full_path = f"{site_name}{tld}"
        conn = get_db()
        existing = conn.execute('SELECT 1 FROM websites WHERE full_path = ?', (full_path,)).fetchone()
        conn.close()
        
        if existing:
            flash("Bu site adi zaten kullanımda", "danger")
            return redirect("/create-site")
        
        site_id = create_website(user["id"], site_name, tld)
        
        flash(f"Site olusturuldu: {BASE_DOMAIN}/{full_path}", "success")
        return redirect("/dashboard")
    
    return render_template("create_site.html", base_domain=BASE_DOMAIN)

@app.route("/editor/<full_path>")
def site_editor(full_path):
    user = get_current_user()
    if not user:
        return redirect("/login")
    
    website = get_website_by_path(full_path)
    if not website or website["user_id"] != user["id"]:
        flash("Bu siteye erisim izniniz yok", "danger")
        return redirect("/dashboard")
    
    return render_template("editor.html",
                         site_name=full_path,
                         domain=f"{BASE_DOMAIN}/{full_path}",
                         base_domain=BASE_DOMAIN)

@app.route("/api/save-file/<full_path>/<filename>", methods=["POST"])
def api_save_file(full_path, filename):
    user = get_current_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    
    website = get_website_by_path(full_path)
    if not website or website["user_id"] != user["id"]:
        return jsonify({"error": "Access denied"}), 403
    
    content = request.json.get("content", "")
    
    site_dir = Path(app.config["UPLOAD_FOLDER"]) / full_path / "public_html"
    site_dir.mkdir(parents=True, exist_ok=True)
    
    file_path = site_dir / filename
    file_path.write_text(content, encoding='utf-8')
    
    if TELEGRAM_AVAILABLE:
        thread = threading.Thread(target=send_to_telegram,
                                args=(user["id"], full_path, site_dir))
        thread.start()
        cloud_msg = " ve cloud'a gonderildi"
    else:
        cloud_msg = ""
    
    return jsonify({
        "success": True,
        "message": f"Dosya kaydedildi{cloud_msg}"
    })

@app.route("/api/get-files/<full_path>")
def api_get_files(full_path):
    user = get_current_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    
    website = get_website_by_path(full_path)
    if not website or website["user_id"] != user["id"]:
        return jsonify({"error": "Access denied"}), 403
    
    site_dir = Path(app.config["UPLOAD_FOLDER"]) / full_path / "public_html"
    
    files = []
    if site_dir.exists():
        for item in site_dir.iterdir():
            if item.is_file():
                files.append({
                    'name': item.name,
                    'size': item.stat().st_size,
                    'modified': datetime.fromtimestamp(item.stat().st_mtime).strftime('%Y-%m-%d %H:%M:%S')
                })
    
    return jsonify({"files": files})

@app.route("/api/get-file/<full_path>/<filename>")
def api_get_file(full_path, filename):
    user = get_current_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    
    website = get_website_by_path(full_path)
    if not website or website["user_id"] != user["id"]:
        return jsonify({"error": "Access denied"}), 403
    
    site_dir = Path(app.config["UPLOAD_FOLDER"]) / full_path / "public_html"
    file_path = site_dir / filename
    
    if not file_path.exists():
        return jsonify({"error": "File not found"}), 404
    
    try:
        content = file_path.read_text(encoding='utf-8')
        return jsonify({"content": content})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/admin/create-admin")
def create_admin():
    conn = get_db()
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

def init_app():
    init_db()
    Path(app.config["UPLOAD_FOLDER"]).mkdir(parents=True, exist_ok=True)
    
    print("="*50)
    print("🚀 FREEHOST v3.0 BASLATILIYOR")
    print(f"🌐 Domain: {BASE_DOMAIN}")
    print(f"📁 Path Format: {BASE_DOMAIN}/[site][.tld]")
    print(f"📱 Cloud Sync: {'AKTIF' if TELEGRAM_AVAILABLE else 'PASIF'}")
    print("="*50)

if __name__ == "__main__":
    init_app()
    app.run(host="0.0.0.0", port=PORT, debug=DEBUG_MODE)
