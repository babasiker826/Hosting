import os
import sys
import time
import json
import sqlite3
import zipfile
import threading
import asyncio
import re
import secrets
from datetime import datetime, timedelta
from pathlib import Path
from functools import wraps
from concurrent.futures import ThreadPoolExecutor

from flask import (
    Flask, render_template, request, redirect, url_for, session,
    jsonify, send_file, flash, render_template_string, make_response,
    send_from_directory
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

import requests
import subprocess
import shutil
from urllib.parse import urlparse

# ==================== KONFİGÜRASYON ====================
BASE_DOMAIN = os.environ.get("BASE_DOMAIN", "x.2026tr.xyz")
PORT = int(os.environ.get("PORT", 5000))
DEBUG_MODE = os.environ.get("DEBUG", "False").lower() == "true"
MAX_UPLOAD_SIZE = 100 * 1024 * 1024  # 100MB
SESSION_LIFETIME = timedelta(hours=24)

# Telegram API Configuration
API_ID = 24179304
API_HASH = "6fdbaf87f6fa54a1a8a51603bf38c2d1"
SESSION_STRING = "1ApWapzMBu00TcO02cRYREPfQ8ubOErEnIYktiYxvfa9JTCId4Yh7myle5Lw9i8T1LqkrVGLOYlQjTiPx1QrSTTxLPBbqtMGxkgYrojwYDWYS-Vjrm-9viL9wcbgsEh5QH-6PIht93hyaKsZXuDXlBO0SlpU2xhuqLAh_-0Qe7sCgWnCpBtszPJGFuvQVSKUz0Kt2Cj4OXDBQp8I4pvogCOlXO1Rj5QP4aSM6pKYxvg8uC9zPLBxdG__rZI7Mg3GmYaFOPHg32-k2co9YyP701pjpEXJHj_1bjbuEU2Q0Fr2yHKiYWEy-JyAz_xRHx06hAzmexHQvP2oZ7mKw1g4jIdbUSMmG4X0="
TELEGRAM_CHANNEL = "nabihostingdeposak"
TELEGRAM_SYNC_INTERVAL = 300  # 5 dakika

# ==================== FLASK UYGULAMASI ====================
app = Flask(__name__, 
           template_folder="templates", 
           static_folder="static",
           static_url_path="/static")

app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))
app.config["UPLOAD_FOLDER"] = "user_files"
app.config['MAX_CONTENT_LENGTH'] = MAX_UPLOAD_SIZE
app.config['PERMANENT_SESSION_LIFETIME'] = SESSION_LIFETIME
app.config['SESSION_COOKIE_SECURE'] = not DEBUG_MODE
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# ==================== TELEGRAM CLIENT ====================
TELEGRAM_AVAILABLE = False
telegram_client = None
executor = ThreadPoolExecutor(max_workers=10)

try:
    from telethon import TelegramClient
    from telethon.sessions import StringSession
    from telethon.tl.types import InputMessagesFilterDocument
    
    TELEGRAM_AVAILABLE = True
    print("✅ Cloud Sync Aktif")
    
    async def init_telegram():
        global telegram_client
        try:
            telegram_client = TelegramClient(
                StringSession(SESSION_STRING),
                API_ID,
                API_HASH
            )
            await telegram_client.start()
            print("✅ Cloud Bağlantısı Başlatıldı")
            return telegram_client
        except Exception as e:
            print(f"❌ Cloud Bağlantısı Başlatılamadı: {e}")
            return None
    
    # Async initialization
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(init_telegram())
    loop.close()
    
except ImportError as e:
    print(f"⚠️ Cloud Modülü Yüklenemedi: {e}")
    print("⚠️ Cloud Özellikleri Devre Dışı - Lokal Depolama Kullanılacak")

# ==================== DATABASE FUNCTIONS ====================
def get_db():
    """Database bağlantısı oluştur"""
    conn = sqlite3.connect('hosting.db', timeout=10)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Database tablolarını oluştur"""
    conn = get_db()
    cursor = conn.cursor()
    
    # Kullanıcılar tablosu
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            email TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP,
            is_active BOOLEAN DEFAULT 1,
            is_admin BOOLEAN DEFAULT 0,
            storage_quota INTEGER DEFAULT 10737418240, -- 10GB
            used_storage INTEGER DEFAULT 0
        )
    ''')
    
    # Siteler tablosu
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS websites (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            site_name TEXT NOT NULL,
            tld TEXT NOT NULL DEFAULT '.com',
            full_path TEXT UNIQUE NOT NULL,
            status TEXT DEFAULT 'active',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_modified TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_sync TIMESTAMP,
            file_count INTEGER DEFAULT 0,
            total_size INTEGER DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )
    ''')
    
    # API Anahtarları tablosu
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS api_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            api_key TEXT UNIQUE NOT NULL,
            name TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_used TIMESTAMP,
            is_active BOOLEAN DEFAULT 1,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )
    ''')
    
    # İndeksler
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_websites_full_path ON websites(full_path)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_websites_user_id ON websites(user_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)')
    
    conn.commit()
    conn.close()
    print("✅ Database Hazır")

# ==================== AUTH DECORATORS ====================
def login_required(f):
    """Login gerektiren endpoint'ler için decorator"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            if request.is_json:
                return jsonify({'error': 'Unauthorized'}), 401
            flash('Bu sayfaya erişmek için giriş yapmalısınız', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Admin yetkisi gerektiren endpoint'ler için decorator"""
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        user = get_current_user()
        if not user or not user['is_admin']:
            flash('Bu işlem için admin yetkisi gerekiyor', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# ==================== USER FUNCTIONS ====================
def get_current_user():
    """Mevcut kullanıcıyı getir"""
    if 'user_id' in session:
        conn = get_db()
        user = conn.execute(
            'SELECT * FROM users WHERE id = ? AND is_active = 1',
            (session['user_id'],)
        ).fetchone()
        conn.close()
        return user
    return None

def get_user_by_username(username):
    """Kullanıcı adına göre kullanıcı getir"""
    conn = get_db()
    user = conn.execute(
        'SELECT * FROM users WHERE username = ?',
        (username,)
    ).fetchone()
    conn.close()
    return user

def create_user(username, password, email=""):
    """Yeni kullanıcı oluştur"""
    # Kullanıcı adı kontrolü
    if not re.match(r'^[a-zA-Z0-9_]{3,30}$', username):
        raise ValueError('Kullanıcı adı sadece harf, rakam ve alt çizgi içerebilir (3-30 karakter)')
    
    # Şifre kontrolü
    if len(password) < 6:
        raise ValueError('Şifre en az 6 karakter olmalı')
    
    hashed = generate_password_hash(password)
    conn = get_db()
    cursor = conn.cursor()
    
    try:
        cursor.execute(
            'INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)',
            (username, hashed, email)
        )
        user_id = cursor.lastrowid
        
        # API anahtarı oluştur
        api_key = secrets.token_urlsafe(32)
        cursor.execute(
            'INSERT INTO api_keys (user_id, api_key, name) VALUES (?, ?, ?)',
            (user_id, api_key, 'Default API Key')
        )
        
        conn.commit()
        return user_id
    except sqlite3.IntegrityError:
        raise ValueError('Bu kullanıcı adı zaten kullanılıyor')
    finally:
        conn.close()

def update_user_login(user_id):
    """Kullanıcının son giriş zamanını güncelle"""
    conn = get_db()
    conn.execute(
        'UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?',
        (user_id,)
    )
    conn.commit()
    conn.close()

# ==================== WEBSITE FUNCTIONS ====================
def get_website_by_path(full_path):
    """Site yoluna göre site bilgilerini getir"""
    conn = get_db()
    website = conn.execute(
        '''SELECT websites.*, users.username 
           FROM websites 
           JOIN users ON websites.user_id = users.id 
           WHERE websites.full_path = ? AND websites.status = ?''',
        (full_path, 'active')
    ).fetchone()
    conn.close()
    return website

def get_user_websites(user_id):
    """Kullanıcının tüm sitelerini getir"""
    conn = get_db()
    websites = conn.execute(
        '''SELECT *, 
           (SELECT COUNT(*) FROM websites w2 WHERE w2.user_id = ?) as total_sites
           FROM websites 
           WHERE user_id = ? 
           ORDER BY created_at DESC''',
        (user_id, user_id)
    ).fetchall()
    conn.close()
    
    # Dosya boyutlarını hesapla
    for website in websites:
        site_dir = Path(app.config["UPLOAD_FOLDER"]) / website['full_path'] / "public_html"
        if site_dir.exists():
            total_size = sum(f.stat().st_size for f in site_dir.rglob('*') if f.is_file())
            file_count = sum(1 for _ in site_dir.rglob('*') if _.is_file())
            website['size'] = total_size
            website['file_count'] = file_count
        else:
            website['size'] = 0
            website['file_count'] = 0
    
    return websites

def create_website(user_id, site_name, tld='.com'):
    """Yeni site oluştur"""
    # Site adı temizleme
    site_name = re.sub(r'[^a-zA-Z0-9\-_]', '', site_name.lower())
    if not site_name:
        raise ValueError('Geçerli bir site adı girin')
    
    # TLD kontrolü
    valid_tlds = ['.com', '.net', '.org', '.xyz', '.info', '.site', '.online', '.dev']
    tld = tld.lower()
    if tld not in valid_tlds:
        tld = '.com'
    
    full_path = f"{site_name}{tld}"
    
    # Site adı kontrolü
    if len(full_path) > 100:
        raise ValueError('Site adı çok uzun')
    
    conn = get_db()
    cursor = conn.cursor()
    
    try:
        # Mevcut site kontrolü
        existing = conn.execute(
            'SELECT 1 FROM websites WHERE full_path = ?',
            (full_path,)
        ).fetchone()
        
        if existing:
            raise ValueError('Bu site adı zaten kullanılıyor')
        
        # Site oluştur
        cursor.execute(
            '''INSERT INTO websites 
               (user_id, site_name, tld, full_path, created_at, last_modified) 
               VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)''',
            (user_id, site_name, tld, full_path)
        )
        website_id = cursor.lastrowid
        
        # Klasör yapısını oluştur
        site_dir = Path(app.config["UPLOAD_FOLDER"]) / full_path / "public_html"
        site_dir.mkdir(parents=True, exist_ok=True)
        
        # Varsayılan index.html oluştur
        create_default_index(full_path, site_dir)
        
        conn.commit()
        return website_id
        
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        conn.close()

def delete_website(user_id, full_path):
    """Siteyi sil"""
    conn = get_db()
    cursor = conn.cursor()
    
    try:
        # Site kontrolü
        website = conn.execute(
            'SELECT * FROM websites WHERE full_path = ? AND user_id = ?',
            (full_path, user_id)
        ).fetchone()
        
        if not website:
            return False, 'Site bulunamadı veya erişim izniniz yok'
        
        # Siteyi database'den sil
        cursor.execute(
            'DELETE FROM websites WHERE full_path = ? AND user_id = ?',
            (full_path, user_id)
        )
        
        # Dosyaları sil
        site_dir = Path(app.config["UPLOAD_FOLDER"]) / full_path
        if site_dir.exists():
            shutil.rmtree(site_dir)
        
        conn.commit()
        return True, 'Site başarıyla silindi'
        
    except Exception as e:
        conn.rollback()
        return False, f'Silme hatası: {str(e)}'
    finally:
        conn.close()

def calculate_site_size(full_path):
    """Site dosya boyutunu hesapla"""
    site_dir = Path(app.config["UPLOAD_FOLDER"]) / full_path / "public_html"
    if not site_dir.exists():
        return 0
    
    total_size = 0
    try:
        for file_path in site_dir.rglob('*'):
            if file_path.is_file():
                total_size += file_path.stat().st_size
    except:
        pass
    
    return total_size

# ==================== FILE OPERATIONS ====================
def create_default_index(full_path, site_dir):
    """Varsayılan index.html dosyası oluştur"""
    index_content = f'''<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{full_path} - FreeHost Pro</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        body {{
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
            font-family: 'Inter', system-ui, sans-serif;
            color: white;
            min-height: 100vh;
            margin: 0;
            padding: 0;
        }}
        .container {{
            max-width: 800px;
            margin: 0 auto;
            padding: 40px 20px;
            text-align: center;
        }}
        .logo {{
            font-size: 48px;
            font-weight: bold;
            margin-bottom: 20px;
            background: linear-gradient(135deg, #3b82f6, #8b5cf6);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}
        .url {{
            background: rgba(255, 255, 255, 0.1);
            padding: 15px;
            border-radius: 12px;
            margin: 30px 0;
            font-family: 'JetBrains Mono', monospace;
            border: 1px solid rgba(255, 255, 255, 0.2);
        }}
        .btn {{
            display: inline-block;
            padding: 12px 24px;
            margin: 10px;
            border-radius: 8px;
            text-decoration: none;
            font-weight: 600;
            transition: all 0.3s;
        }}
        .btn-primary {{
            background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%);
        }}
        .btn-secondary {{
            background: rgba(255, 255, 255, 0.1);
            border: 1px solid rgba(255, 255, 255, 0.2);
        }}
        .btn:hover {{
            transform: translateY(-2px);
            box-shadow: 0 10px 20px rgba(0, 0, 0, 0.2);
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">FreeHost Pro</div>
        <h1 class="text-3xl font-bold mb-4">Siteniz Hazır!</h1>
        <div class="url text-lg">
            https://{BASE_DOMAIN}/{full_path}
        </div>
        <p class="text-gray-300 mb-8">
            Bu site FreeHost Pro ile oluşturuldu. Site sahibi henüz içerik eklememiş.
        </p>
        <div>
            <a href="https://{BASE_DOMAIN}/editor/{full_path}" class="btn btn-primary">
                Siteyi Düzenle
            </a>
            <a href="https://{BASE_DOMAIN}/dashboard" class="btn btn-secondary">
                Kontrol Paneli
            </a>
        </div>
    </div>
</body>
</html>'''
    
    (site_dir / "index.html").write_text(index_content, encoding='utf-8')

# ==================== TELEGRAM SYNC FUNCTIONS ====================
async def search_telegram_files(user_id, full_path):
    """Telegram'da site dosyalarını ara"""
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
        print(f"❌ Cloud Arama Hatası: {e}")
        return None

async def download_from_telegram(message):
    """Telegram'dan dosya indir"""
    if not TELEGRAM_AVAILABLE or not telegram_client:
        return None
    
    try:
        file_name = f"cloud_download_{int(time.time())}.zip"
        await telegram_client.download_media(message, file_name)
        
        if os.path.exists(file_name):
            return file_name
        return None
    except Exception as e:
        print(f"❌ Cloud İndirme Hatası: {e}")
        return None

def sync_site_from_telegram(user_id, full_path):
    """Siteyi Telegram'dan senkronize et"""
    site_dir = Path(app.config["UPLOAD_FOLDER"]) / full_path / "public_html"
    site_dir.mkdir(parents=True, exist_ok=True)
    
    # Son senkronizasyon kontrolü
    sync_marker = site_dir / ".last_sync"
    if sync_marker.exists():
        try:
            last_sync = float(sync_marker.read_text())
            if time.time() - last_sync < TELEGRAM_SYNC_INTERVAL:
                return True
        except:
            pass
    
    if not TELEGRAM_AVAILABLE:
        return True
    
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        message = loop.run_until_complete(search_telegram_files(user_id, full_path))
        
        if message and message.document:
            print(f"📥 Cloud'dan Dosya Bulundu: {full_path}")
            
            zip_path = loop.run_until_complete(download_from_telegram(message))
            
            if zip_path and os.path.exists(zip_path):
                # Mevcut dosyaları temizle
                for item in site_dir.iterdir():
                    if item.name != ".last_sync":
                        if item.is_file():
                            item.unlink()
                        elif item.is_dir():
                            shutil.rmtree(item)
                
                # ZIP dosyasını çıkar
                with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                    zip_ref.extractall(site_dir)
                
                # Senkronizasyon zamanını kaydet
                sync_marker.write_text(str(time.time()))
                
                # Database'i güncelle
                conn = get_db()
                conn.execute(
                    'UPDATE websites SET last_sync = CURRENT_TIMESTAMP WHERE full_path = ?',
                    (full_path,)
                )
                conn.commit()
                conn.close()
                
                os.remove(zip_path)
                return True
        
        return False
        
    except Exception as e:
        print(f"❌ Senkronizasyon Hatası {full_path}: {e}")
        return False
    finally:
        if 'loop' in locals():
            loop.close()

def send_to_telegram(user_id, full_path, site_dir):
    """Siteyi Telegram'a yükle"""
    if not TELEGRAM_AVAILABLE:
        return
    
    try:
        zip_name = f"{user_id}_{full_path}_{int(time.time())}.zip"
        
        # ZIP oluştur
        with zipfile.ZipFile(zip_name, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for root, dirs, files in os.walk(site_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, site_dir)
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
🌐 Site: {full_path}
🔗 Link: {BASE_DOMAIN}/{full_path}
⏰ Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
                """
                
                await telegram_client.send_file(
                    entity,
                    file=zip_name,
                    caption=caption
                )
                print(f"✅ Cloud'a Gönderildi: {full_path}")
            except Exception as e:
                print(f"❌ Cloud Gönderim Hatası: {e}")
        
        # Thread'de çalıştır
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(send_async())
        loop.close()
        
        # Temizlik
        if os.path.exists(zip_name):
            os.remove(zip_name)
            
    except Exception as e:
        print(f"❌ Cloud Gönderim Hatası: {e}")

# ==================== ROUTES ====================
@app.before_request
def before_request():
    """Her istekten önce çalışacak fonksiyon"""
    # Session timeout kontrolü
    if 'user_id' in session:
        session.permanent = True
    
    # Host-based routing için
    host = request.host.split(':')[0]
    
    # Panel yollarını kontrol et
    panel_paths = ['/login', '/logout', '/register', '/dashboard',
                   '/create-site', '/editor', '/api', '/static',
                   '/admin', '/favicon.ico', '/']
    
    path = request.path
    for panel_path in panel_paths:
        if path.startswith(panel_path):
            return None
    
    # Site hosting için
    if host == BASE_DOMAIN or host == f"www.{BASE_DOMAIN}":
        if path == '/':
            return None
        
        if path.startswith('/'):
            site_path = path[1:]  # Baştaki /'yi kaldır
            
            # TLD pattern kontrolü
            tld_pattern = r'^[a-zA-Z0-9\-_]+\.(com|net|org|xyz|info|site|online|dev)$'
            
            if re.match(tld_pattern, site_path):
                website = get_website_by_path(site_path)
                if not website:
                    return render_template('404.html', 
                                         site_path=site_path, 
                                         base_domain=BASE_DOMAIN), 404
                
                # Senkronizasyon
                executor.submit(sync_site_from_telegram, website['user_id'], site_path)
                
                site_dir = Path(app.config["UPLOAD_FOLDER"]) / site_path / "public_html"
                
                # Dosya servisi
                remaining_path = path[len('/' + site_path):]
                if not remaining_path or remaining_path == '/':
                    remaining_path = '/index.html'
                
                file_path = site_dir / remaining_path.lstrip('/')
                
                if file_path.exists() and file_path.is_file():
                    return send_file(str(file_path))
                
                return render_template('loading.html',
                                     site_path=site_path,
                                     base_domain=BASE_DOMAIN), 200
    
    return "Geçersiz İstek", 400

@app.route("/")
def index():
    """Ana sayfa"""
    user = get_current_user()
    if user:
        return redirect(url_for('dashboard'))
    return render_template("index.html", base_domain=BASE_DOMAIN)

@app.route("/register", methods=["GET", "POST"])
def register():
    """Kayıt sayfası"""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        email = request.form.get("email", "")
        confirm_password = request.form.get("confirm_password", "")
        
        # Validasyon
        if not username or not password:
            flash("Kullanıcı adı ve şifre gerekli", "danger")
            return redirect(url_for('register'))
        
        if password != confirm_password:
            flash("Şifreler eşleşmiyor", "danger")
            return redirect(url_for('register'))
        
        try:
            user_id = create_user(username, password, email)
            session["user_id"] = user_id
            session["username"] = username
            
            update_user_login(user_id)
            flash("Kayıt başarılı! Hoş geldiniz.", "success")
            return redirect(url_for('dashboard'))
            
        except ValueError as e:
            flash(str(e), "danger")
            return redirect(url_for('register'))
        except Exception as e:
            flash(f"Kayıt sırasında hata oluştu: {str(e)}", "danger")
            return redirect(url_for('register'))
    
    return render_template("register.html", base_domain=BASE_DOMAIN)

@app.route("/login", methods=["GET", "POST"])
def login():
    """Giriş sayfası"""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        remember = request.form.get("remember", False)
        
        user = get_user_by_username(username)
        if user and check_password_hash(user["password_hash"], password):
            if not user['is_active']:
                flash("Hesabınız askıya alınmış", "danger")
                return redirect(url_for('login'))
            
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            
            if remember:
                session.permanent = True
            
            update_user_login(user["id"])
            flash("Giriş başarılı!", "success")
            return redirect(url_for('dashboard'))
        
        flash("Kullanıcı adı veya şifre hatalı", "danger")
        return redirect(url_for('login'))
    
    return render_template("login.html", base_domain=BASE_DOMAIN)

@app.route("/logout")
def logout():
    """Çıkış yap"""
    session.clear()
    flash("Çıkış yapıldı", "info")
    return redirect(url_for('index'))

@app.route("/dashboard")
@login_required
def dashboard():
    """Kontrol paneli"""
    user = get_current_user()
    websites = get_user_websites(user['id'])
    
    # Storage hesaplama
    total_size = sum(website.get('size', 0) for website in websites)
    storage_quota = user.get('storage_quota', 10737418240)  # 10GB default
    storage_percent = (total_size / storage_quota * 100) if storage_quota > 0 else 0
    
    return render_template("dashboard.html",
                         username=user["username"],
                         websites=websites,
                         base_domain=BASE_DOMAIN,
                         total_size=total_size,
                         storage_quota=storage_quota,
                         storage_percent=storage_percent)

@app.route("/create-site", methods=["GET", "POST"])
@login_required
def create_site():
    """Site oluşturma sayfası"""
    user = get_current_user()
    
    if request.method == "POST":
        site_name = request.form.get("site_name", "").strip()
        tld = request.form.get("tld", ".com")
        
        if not site_name:
            flash("Site adı gerekli", "danger")
            return redirect(url_for('create_site'))
        
        try:
            create_website(user['id'], site_name, tld)
            full_path = f"{re.sub(r'[^a-zA-Z0-9\-_]', '', site_name.lower())}{tld}"
            
            flash(f"Site oluşturuldu: {BASE_DOMAIN}/{full_path}", "success")
            return redirect(url_for('dashboard'))
            
        except ValueError as e:
            flash(str(e), "danger")
            return redirect(url_for('create_site'))
        except Exception as e:
            flash(f"Site oluşturma hatası: {str(e)}", "danger")
            return redirect(url_for('create_site'))
    
    return render_template("create_site.html", base_domain=BASE_DOMAIN)

@app.route("/editor/<full_path>")
@login_required
def site_editor(full_path):
    """Site editörü"""
    user = get_current_user()
    website = get_website_by_path(full_path)
    
    if not website or website['user_id'] != user['id']:
        flash("Bu siteye erişim izniniz yok", "danger")
        return redirect(url_for('dashboard'))
    
    return render_template("editor.html",
                         site_name=full_path,
                         domain=f"{BASE_DOMAIN}/{full_path}",
                         base_domain=BASE_DOMAIN)

# ==================== API ENDPOINTS ====================
@app.route("/api/save-file/<full_path>/<filename>", methods=["POST"])
@login_required
def api_save_file(full_path, filename):
    """Dosya kaydet"""
    user = get_current_user()
    
    website = get_website_by_path(full_path)
    if not website or website['user_id'] != user['id']:
        return jsonify({"error": "Access denied"}), 403
    
    # Dosya adı güvenliği
    filename = secure_filename(filename)
    if not filename:
        return jsonify({"error": "Invalid filename"}), 400
    
    content = request.json.get("content", "")
    
    site_dir = Path(app.config["UPLOAD_FOLDER"]) / full_path / "public_html"
    site_dir.mkdir(parents=True, exist_ok=True)
    
    file_path = site_dir / filename
    
    try:
        # Dosyayı kaydet
        file_path.write_text(content, encoding='utf-8')
        
        # Boyut kontrolü
        file_size = len(content.encode('utf-8'))
        
        # Database'i güncelle
        conn = get_db()
        conn.execute(
            '''UPDATE websites 
               SET last_modified = CURRENT_TIMESTAMP,
                   file_count = (SELECT COUNT(*) FROM (SELECT 1 FROM websites WHERE full_path = ?) as w),
                   total_size = ? 
               WHERE full_path = ?''',
            (full_path, calculate_site_size(full_path), full_path)
        )
        conn.commit()
        conn.close()
        
        # Cloud senkronizasyonu
        if TELEGRAM_AVAILABLE:
            executor.submit(send_to_telegram, user['id'], full_path, site_dir)
        
        return jsonify({
            "success": True,
            "message": "Dosya kaydedildi",
            "size": file_size,
            "cloud_sync": TELEGRAM_AVAILABLE
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/get-files/<full_path>")
@login_required
def api_get_files(full_path):
    """Dosya listesi getir"""
    user = get_current_user()
    
    website = get_website_by_path(full_path)
    if not website or website['user_id'] != user['id']:
        return jsonify({"error": "Access denied"}), 403
    
    site_dir = Path(app.config["UPLOAD_FOLDER"]) / full_path / "public_html"
    
    files = []
    if site_dir.exists():
        try:
            for item in site_dir.iterdir():
                if item.is_file():
                    stat = item.stat()
                    files.append({
                        'name': item.name,
                        'size': stat.st_size,
                        'modified': datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
                        'extension': item.suffix.lower()
                    })
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    
    return jsonify({"files": sorted(files, key=lambda x: x['name'])})

@app.route("/api/get-file/<full_path>/<filename>")
@login_required
def api_get_file(full_path, filename):
    """Dosya içeriğini getir"""
    user = get_current_user()
    
    website = get_website_by_path(full_path)
    if not website or website['user_id'] != user['id']:
        return jsonify({"error": "Access denied"}), 403
    
    site_dir = Path(app.config["UPLOAD_FOLDER"]) / full_path / "public_html"
    file_path = site_dir / secure_filename(filename)
    
    if not file_path.exists():
        return jsonify({"error": "File not found"}), 404
    
    try:
        content = file_path.read_text(encoding='utf-8')
        return jsonify({
            "content": content,
            "size": len(content),
            "modified": datetime.fromtimestamp(file_path.stat().st_mtime).isoformat()
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/delete-file/<full_path>/<filename>", methods=["DELETE"])
@login_required
def api_delete_file(full_path, filename):
    """Dosya sil"""
    user = get_current_user()
    
    website = get_website_by_path(full_path)
    if not website or website['user_id'] != user['id']:
        return jsonify({"error": "Access denied"}), 403
    
    site_dir = Path(app.config["UPLOAD_FOLDER"]) / full_path / "public_html"
    file_path = site_dir / secure_filename(filename)
    
    if not file_path.exists():
        return jsonify({"error": "File not found"}), 404
    
    try:
        # Dosyayı sil
        file_path.unlink()
        
        # Database'i güncelle
        conn = get_db()
        conn.execute(
            '''UPDATE websites 
               SET last_modified = CURRENT_TIMESTAMP,
                   file_count = (SELECT COUNT(*) FROM (SELECT 1 FROM websites WHERE full_path = ?) as w),
                   total_size = ? 
               WHERE full_path = ?''',
            (full_path, calculate_site_size(full_path), full_path)
        )
        conn.commit()
        conn.close()
        
        # Cloud senkronizasyonu
        if TELEGRAM_AVAILABLE:
            executor.submit(send_to_telegram, user['id'], full_path, site_dir)
        
        return jsonify({
            "success": True,
            "message": "Dosya silindi"
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/delete-site/<full_path>", methods=["DELETE"])
@login_required
def api_delete_site(full_path):
    """Site sil"""
    user = get_current_user()
    
    success, message = delete_website(user['id'], full_path)
    
    if success:
        return jsonify({
            "success": True,
            "message": message
        })
    else:
        return jsonify({
            "success": False,
            "error": message
        }), 400

@app.route("/api/upload-file/<full_path>", methods=["POST"])
@login_required
def api_upload_file(full_path):
    """Dosya yükle"""
    user = get_current_user()
    
    website = get_website_by_path(full_path)
    if not website or website['user_id'] != user['id']:
        return jsonify({"error": "Access denied"}), 403
    
    if 'file' not in request.files:
        return jsonify({"error": "No file provided"}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No file selected"}), 400
    
    filename = secure_filename(file.filename)
    site_dir = Path(app.config["UPLOAD_FOLDER"]) / full_path / "public_html"
    site_dir.mkdir(parents=True, exist_ok=True)
    
    file_path = site_dir / filename
    
    try:
        file.save(file_path)
        
        # Cloud senkronizasyonu
        if TELEGRAM_AVAILABLE:
            executor.submit(send_to_telegram, user['id'], full_path, site_dir)
        
        return jsonify({
            "success": True,
            "message": "File uploaded",
            "filename": filename,
            "size": file_path.stat().st_size
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/create-folder/<full_path>", methods=["POST"])
@login_required
def api_create_folder(full_path):
    """Klasör oluştur"""
    user = get_current_user()
    
    website = get_website_by_path(full_path)
    if not website or website['user_id'] != user['id']:
        return jsonify({"error": "Access denied"}), 403
    
    folder_name = request.json.get("folder_name", "").strip()
    if not folder_name:
        return jsonify({"error": "Folder name required"}), 400
    
    # Güvenli klasör adı
    folder_name = re.sub(r'[^\w\-\.]', '', folder_name)
    
    site_dir = Path(app.config["UPLOAD_FOLDER"]) / full_path / "public_html"
    folder_path = site_dir / folder_name
    
    try:
        folder_path.mkdir(exist_ok=True)
        
        # Cloud senkronizasyonu
        if TELEGRAM_AVAILABLE:
            executor.submit(send_to_telegram, user['id'], full_path, site_dir)
        
        return jsonify({
            "success": True,
            "message": "Folder created"
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/rename-file/<full_path>", methods=["POST"])
@login_required
def api_rename_file(full_path):
    """Dosya/klasör adını değiştir"""
    user = get_current_user()
    
    website = get_website_by_path(full_path)
    if not website or website['user_id'] != user['id']:
        return jsonify({"error": "Access denied"}), 403
    
    old_name = request.json.get("old_name", "")
    new_name = request.json.get("new_name", "")
    
    if not old_name or not new_name:
        return jsonify({"error": "Both names required"}), 400
    
    old_name = secure_filename(old_name)
    new_name = secure_filename(new_name)
    
    site_dir = Path(app.config["UPLOAD_FOLDER"]) / full_path / "public_html"
    old_path = site_dir / old_name
    new_path = site_dir / new_name
    
    if not old_path.exists():
        return jsonify({"error": "Source not found"}), 404
    
    if new_path.exists():
        return jsonify({"error": "Destination already exists"}), 400
    
    try:
        old_path.rename(new_path)
        
        # Cloud senkronizasyonu
        if TELEGRAM_AVAILABLE:
            executor.submit(send_to_telegram, user['id'], full_path, site_dir)
        
        return jsonify({
            "success": True,
            "message": "Renamed successfully"
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ==================== ADMIN ROUTES ====================
@app.route("/admin")
@admin_required
def admin_panel():
    """Admin paneli"""
    conn = get_db()
    stats = conn.execute('''
        SELECT 
            (SELECT COUNT(*) FROM users) as total_users,
            (SELECT COUNT(*) FROM websites) as total_sites,
            (SELECT COUNT(*) FROM websites WHERE status = 'active') as active_sites,
            (SELECT SUM(total_size) FROM websites) as total_storage
    ''').fetchone()
    
    recent_users = conn.execute(
        'SELECT * FROM users ORDER BY created_at DESC LIMIT 10'
    ).fetchall()
    
    recent_sites = conn.execute('''
        SELECT websites.*, users.username 
        FROM websites 
        JOIN users ON websites.user_id = users.id 
        ORDER BY websites.created_at DESC 
        LIMIT 10
    ''').fetchall()
    
    conn.close()
    
    return render_template("admin.html",
                         stats=stats,
                         recent_users=recent_users,
                         recent_sites=recent_sites,
                         base_domain=BASE_DOMAIN)

# ==================== ERROR HANDLERS ====================
@app.errorhandler(404)
def page_not_found(e):
    """404 hata sayfası"""
    return render_template('404.html', base_domain=BASE_DOMAIN), 404

@app.errorhandler(500)
def internal_server_error(e):
    """500 hata sayfası"""
    return render_template('500.html', base_domain=BASE_DOMAIN), 500

@app.errorhandler(413)
def request_entity_too_large(e):
    """413 hata (dosya çok büyük)"""
    return jsonify({"error": "File too large"}), 413

# ==================== INITIALIZATION ====================
def init_app():
    """Uygulamayı başlat"""
    init_db()
    
    # Upload klasörünü oluştur
    Path(app.config["UPLOAD_FOLDER"]).mkdir(parents=True, exist_ok=True)
    
    # Static klasörünü oluştur
    Path("static").mkdir(exist_ok=True)
    
    # Logo
    print("="*50)
    print("🚀 FREEHOST PRO v4.0 BAŞLATILIYOR")
    print(f"🌐 Domain: {BASE_DOMAIN}")
    print(f"📁 Site Formatı: {BASE_DOMAIN}/[site][.tld]")
    print(f"📱 Cloud Sync: {'✅ AKTİF' if TELEGRAM_AVAILABLE else '⚠️ PASİF'}")
    print(f"🔐 Session Key: {len(app.secret_key)} karakter")
    print("="*50)

# ==================== MAIN ENTRY POINT ====================
if __name__ == "__main__":
    init_app()
    app.run(
        host="0.0.0.0",
        port=PORT,
        debug=DEBUG_MODE,
        threaded=True
)
