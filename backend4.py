# backend.py - FREEHOST PRO v4.0 (ÇALIŞAN VERSİYON)
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

from flask import (
    Flask, render_template, request, redirect, url_for, session,
    jsonify, send_file, flash
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# ==================== KONFİGÜRASYON ====================
BASE_DOMAIN = os.environ.get("BASE_DOMAIN", "x.2026tr.xyz")
PORT = int(os.environ.get("PORT", 5000))
DEBUG_MODE = os.environ.get("DEBUG", "True").lower() == "true"

# ==================== FLASK UYGULAMASI ====================
app = Flask(__name__, template_folder="templates", static_folder="static")
app.secret_key = os.environ.get("SECRET_KEY", "freehost_super_secret_key_2024")
app.config["UPLOAD_FOLDER"] = "user_files"
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB

# ==================== DATABASE FUNCTIONS ====================
def get_db():
    conn = sqlite3.connect('hosting.db', timeout=10)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
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
            is_admin BOOLEAN DEFAULT 0
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
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    conn.commit()
    conn.close()
    print("✅ Database hazır")

# ==================== AUTH DECORATORS ====================
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Bu sayfaya erişmek için giriş yapmalısınız', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# ==================== USER FUNCTIONS ====================
def get_current_user():
    if 'user_id' in session:
        conn = get_db()
        user = conn.execute(
            'SELECT * FROM users WHERE id = ?',
            (session['user_id'],)
        ).fetchone()
        conn.close()
        return user
    return None

def get_user_by_username(username):
    conn = get_db()
    user = conn.execute(
        'SELECT * FROM users WHERE username = ?',
        (username,)
    ).fetchone()
    conn.close()
    return user

def create_user(username, password, email=""):
    # Basit validasyon
    if len(username) < 3 or len(username) > 30:
        raise ValueError('Kullanıcı adı 3-30 karakter arasında olmalı')
    
    if len(password) < 4:
        raise ValueError('Şifre en az 4 karakter olmalı')
    
    hashed = generate_password_hash(password)
    conn = get_db()
    cursor = conn.cursor()
    
    try:
        cursor.execute(
            'INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)',
            (username, hashed, email)
        )
        user_id = cursor.lastrowid
        conn.commit()
        return user_id
    except sqlite3.IntegrityError:
        raise ValueError('Bu kullanıcı adı zaten kullanılıyor')
    finally:
        conn.close()

# ==================== WEBSITE FUNCTIONS ====================
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
    
    # Websites listesini dict'e çevir
    websites_list = []
    for website in websites:
        website_dict = dict(website)
        
        # Site boyutunu hesapla
        site_dir = Path(app.config["UPLOAD_FOLDER"]) / website_dict['full_path'] / "public_html"
        if site_dir.exists():
            total_size = 0
            file_count = 0
            try:
                for file_path in site_dir.rglob('*'):
                    if file_path.is_file():
                        total_size += file_path.stat().st_size
                        file_count += 1
            except:
                pass
            
            website_dict['size'] = total_size
            website_dict['file_count'] = file_count
        else:
            website_dict['size'] = 0
            website_dict['file_count'] = 0
        
        websites_list.append(website_dict)
    
    return websites_list

def create_website(user_id, site_name, tld='.com'):
    # Site adı temizleme
    site_name = re.sub(r'[^a-zA-Z0-9\-_]', '', site_name.lower())
    if not site_name:
        raise ValueError('Geçerli bir site adı girin')
    
    # TLD kontrolü
    valid_tlds = ['.com', '.net', '.org', '.xyz', '.info', '.site', '.online']
    tld = tld.lower()
    if tld not in valid_tlds:
        tld = '.com'
    
    full_path = f"{site_name}{tld}"
    
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
            'INSERT INTO websites (user_id, site_name, tld, full_path) VALUES (?, ?, ?, ?)',
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
        import shutil
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

# ==================== FILE OPERATIONS ====================
def create_default_index(full_path, site_dir):
    """Varsayılan index.html dosyası oluştur"""
    index_content = f'''<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
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
        <p>Site sahibi henüz içerik eklememiş.</p>
        <div>
            <a href="https://{BASE_DOMAIN}/editor/{full_path}">Siteyi Düzenle</a>
            <a href="https://{BASE_DOMAIN}/dashboard">Kontrol Paneli</a>
        </div>
    </div>
</body>
</html>'''
    
    (site_dir / "index.html").write_text(index_content, encoding='utf-8')

# ==================== ROUTES ====================
@app.before_request
def before_request():
    """Host-based routing"""
    host = request.host.split(':')[0]
    path = request.path
    
    # Panel yollarını kontrol et
    panel_paths = ['/login', '/logout', '/register', '/dashboard',
                   '/create-site', '/editor', '/api', '/static',
                   '/favicon.ico', '/']
    
    if any(path.startswith(p) for p in panel_paths):
        return None
    
    # Site hosting için
    if host == BASE_DOMAIN or host == f"www.{BASE_DOMAIN}":
        if path == '/':
            return None
        
        if path.startswith('/'):
            site_path = path[1:]
            
            # TLD pattern kontrolü
            tld_pattern = r'^[a-zA-Z0-9\-_]+\.(com|net|org|xyz|info|site|online)$'
            
            if re.match(tld_pattern, site_path):
                website = get_website_by_path(site_path)
                if not website:
                    return "Site bulunamadı", 404
                
                site_dir = Path(app.config["UPLOAD_FOLDER"]) / site_path / "public_html"
                
                # Dosya servisi
                remaining_path = path[len('/' + site_path):]
                if not remaining_path or remaining_path == '/':
                    remaining_path = '/index.html'
                
                file_path = site_dir / remaining_path.lstrip('/')
                
                if file_path.exists() and file_path.is_file():
                    return send_file(str(file_path))
                
                return "Dosya bulunamadı", 404
    
    return None

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
        
        # Validasyon
        if not username or not password:
            flash("Kullanıcı adı ve şifre gerekli", "danger")
            return redirect(url_for('register'))
        
        try:
            user_id = create_user(username, password, email)
            session["user_id"] = user_id
            session["username"] = username
            
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
        
        user = get_user_by_username(username)
        if user and check_password_hash(user["password_hash"], password):
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            
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
    if not user:
        return redirect(url_for('login'))
    
    websites = get_user_websites(user['id'])
    
    # Storage hesaplama
    total_size = 0
    for site in websites:
        total_size += site.get('size', 0)
    
    # MB cinsine çevir
    total_size_mb = total_size / (1024 * 1024)
    
    return render_template("dashboard.html",
                         username=user["username"],
                         websites=websites,
                         base_domain=BASE_DOMAIN,
                         total_size=total_size_mb)

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
    
    content = request.json.get("content", "")
    
    site_dir = Path(app.config["UPLOAD_FOLDER"]) / full_path / "public_html"
    site_dir.mkdir(parents=True, exist_ok=True)
    
    file_path = site_dir / filename
    
    try:
        file_path.write_text(content, encoding='utf-8')
        return jsonify({
            "success": True,
            "message": "Dosya kaydedildi"
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
        for item in site_dir.iterdir():
            if item.is_file():
                stat = item.stat()
                files.append({
                    'name': item.name,
                    'size': stat.st_size,
                    'modified': datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
                })
    
    return jsonify({"files": files})

@app.route("/api/get-file/<full_path>/<filename>")
@login_required
def api_get_file(full_path, filename):
    """Dosya içeriğini getir"""
    user = get_current_user()
    
    website = get_website_by_path(full_path)
    if not website or website['user_id'] != user['id']:
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

@app.route("/api/delete-file/<full_path>/<filename>", methods=["DELETE"])
@login_required
def api_delete_file(full_path, filename):
    """Dosya sil"""
    user = get_current_user()
    
    website = get_website_by_path(full_path)
    if not website or website['user_id'] != user['id']:
        return jsonify({"error": "Access denied"}), 403
    
    site_dir = Path(app.config["UPLOAD_FOLDER"]) / full_path / "public_html"
    file_path = site_dir / filename
    
    if not file_path.exists():
        return jsonify({"error": "File not found"}), 404
    
    try:
        file_path.unlink()
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

# ==================== ERROR HANDLERS ====================
@app.errorhandler(404)
def page_not_found(e):
    """404 hata sayfası"""
    return render_template('404.html', base_domain=BASE_DOMAIN), 404

@app.errorhandler(500)
def internal_server_error(e):
    """500 hata sayfası"""
    print(f"500 HATASI: {str(e)}")
    return render_template('500.html', error=str(e), base_domain=BASE_DOMAIN), 500

# ==================== INITIALIZATION ====================
def init_app():
    """Uygulamayı başlat"""
    init_db()
    
    # Upload klasörünü oluştur
    Path(app.config["UPLOAD_FOLDER"]).mkdir(parents=True, exist_ok=True)
    
    # Logo
    print("="*50)
    print("🚀 FREEHOST PRO BAŞLATILIYOR")
    print(f"🌐 Domain: {BASE_DOMAIN}")
    print(f"📁 Site Formatı: {BASE_DOMAIN}/[site][.tld]")
    print(f"🔧 Debug: {DEBUG_MODE}")
    print("="*50)

# ==================== TEMP ADMIN CREATION ====================
@app.route("/create-admin")
def create_admin():
    """Admin kullanıcısı oluştur (sadece geliştirme için)"""
    if not DEBUG_MODE:
        return "Sadece debug modunda erişilebilir", 403
    
    try:
        user_id = create_user("admin", "admin123", "admin@freehost.com")
        
        conn = get_db()
        conn.execute(
            'UPDATE users SET is_admin = 1 WHERE id = ?',
            (user_id,)
        )
        conn.commit()
        conn.close()
        
        return "Admin kullanıcısı oluşturuldu: admin / admin123"
    except Exception as e:
        return f"Hata: {str(e)}"

# ==================== MAIN ENTRY POINT ====================
if __name__ == "__main__":
    init_app()
    app.run(
        host="0.0.0.0",
        port=PORT,
        debug=DEBUG_MODE
  )
