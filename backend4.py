# backend.py - DÜZELTİLMİŞ VERSİYON
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
    
    websites_list = []
    for website in websites:
        website_dict = dict(website)
        
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
    site_name = re.sub(r'[^a-zA-Z0-9\-_]', '', site_name.lower())
    if not site_name:
        raise ValueError('Geçerli bir site adı girin')
    
    valid_tlds = ['.com', '.net', '.org', '.xyz', '.info', '.site', '.online']
    tld = tld.lower()
    if tld not in valid_tlds:
        tld = '.com'
    
    full_path = f"{site_name}{tld}"
    
    conn = get_db()
    cursor = conn.cursor()
    
    try:
        existing = conn.execute(
            'SELECT 1 FROM websites WHERE full_path = ?',
            (full_path,)
        ).fetchone()
        
        if existing:
            raise ValueError('Bu site adı zaten kullanılıyor')
        
        cursor.execute(
            'INSERT INTO websites (user_id, site_name, tld, full_path) VALUES (?, ?, ?, ?)',
            (user_id, site_name, tld, full_path)
        )
        website_id = cursor.lastrowid
        
        site_dir = Path(app.config["UPLOAD_FOLDER"]) / full_path / "public_html"
        site_dir.mkdir(parents=True, exist_ok=True)
        
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
        website = conn.execute(
            'SELECT * FROM websites WHERE full_path = ? AND user_id = ?',
            (full_path, user_id)
        ).fetchone()
        
        if not website:
            return False, 'Site bulunamadı veya erişim izniniz yok'
        
        cursor.execute(
            'DELETE FROM websites WHERE full_path = ? AND user_id = ?',
            (full_path, user_id)
        )
        
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
    index_content = f'''<!DOCTYPE html>
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
def host_dispatcher():
    """SITE HOSTING DÜZELTMESİ - BU KISIM ÇOK ÖNEMLİ"""
    host = request.host.lower().split(':')[0]
    path = request.path
    
    # DEBUG: Gelen isteği logla
    if DEBUG_MODE:
        print(f"🌐 HOST: {host} | PATH: {path}")
    
    # Panel yollarını kontrol et
    panel_paths = ['/login', '/logout', '/register', '/dashboard',
                   '/websites', '/create-site', '/editor', '/api',
                   '/static', '/admin', '/favicon.ico', '/']
    
    for panel_path in panel_paths:
        if path.startswith(panel_path):
            if DEBUG_MODE:
                print(f"📊 Panel route: {path}")
            return None
    
    # Site hosting için
    if host == BASE_DOMAIN or host == f"www.{BASE_DOMAIN}":
        if path == '/':
            return None
        
        if path.startswith('/'):
            site_path = path[1:]  # Baştaki /'yi kaldır
            
            # DEBUG
            if DEBUG_MODE:
                print(f"🔍 Site path: {site_path}")
            
            # TLD pattern kontrolü - DAHA ESNEK
            tld_pattern = r'^[a-zA-Z0-9\-_]+(\.[a-zA-Z]{2,})$'
            
            if re.match(tld_pattern, site_path):
                website = get_website_by_path(site_path)
                if not website:
                    return render_template('404.html', 
                                         site_path=site_path, 
                                         base_domain=BASE_DOMAIN), 404
                
                site_dir = Path(app.config["UPLOAD_FOLDER"]) / site_path / "public_html"
                
                # Dosya servisi
                remaining_path = path[len('/' + site_path):]
                if not remaining_path or remaining_path == '/':
                    remaining_path = "/index.html"
                elif not remaining_path.startswith('/'):
                    remaining_path = '/' + remaining_path
                
                file_path = site_dir / remaining_path.lstrip('/')
                
                if DEBUG_MODE:
                    print(f"📁 Looking for: {file_path}")
                
                if file_path.exists() and file_path.is_file():
                    if DEBUG_MODE:
                        print(f"✅ Serving: {file_path}")
                    return send_file(str(file_path))
                else:
                    if DEBUG_MODE:
                        print(f"❌ File not found: {file_path}")
                    return "Dosya bulunamadı", 404
    
    return None

@app.route("/")
def index():
    user = get_current_user()
    if user:
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
            flash("Giris basarili!", "success")
            return redirect("/dashboard")
        
        flash("Kullanıcı adı veya şifre hatali", "danger")
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

# ==================== API ENDPOINTS ====================
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
    
    return jsonify({
        "success": True,
        "message": f"Dosya kaydedildi"
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

@app.route("/api/delete-file/<full_path>/<filename>", methods=["DELETE"])
def api_delete_file(full_path, filename):
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
        file_path.unlink()
        return jsonify({"success": True, "message": "Dosya silindi"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/delete-site/<full_path>", methods=["DELETE"])
def api_delete_site(full_path):
    user = get_current_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    
    success, message = delete_website(user["id"], full_path)
    
    if success:
        return jsonify({"success": True, "message": message})
    else:
        return jsonify({"success": False, "error": message}), 400

# ==================== EDITOR.JS DÜZELTMESİ ====================
@app.route("/static/editor.js")
def editor_js():
    """Düzeltilmiş editor.js dosyası"""
    js_content = '''
    const siteName = "{{ site_name }}";
    let currentFile = "";

    async function loadFiles() {
        try {
            const res = await fetch(`/api/get-files/${siteName}`);
            if (!res.ok) throw new Error('Dosyalar yüklenemedi');
            
            const data = await res.json();
            
            const fileList = document.getElementById('file-list');
            const fileSelect = document.getElementById('file-select');
            
            fileList.innerHTML = "";
            fileSelect.innerHTML = '<option value="">Dosya seç</option>';
            
            if (data.files && data.files.length === 0) {
                fileList.innerHTML = '<div class="text-gray-600 p-2">Dosya yok</div>';
                return;
            }
            
            data.files.forEach(file => {
                const fileItem = document.createElement('div');
                fileItem.className = "p-2 hover:bg-gray-900 cursor-pointer rounded";
                fileItem.textContent = file.name;
                fileItem.onclick = () => loadFileContent(file.name);
                fileList.appendChild(fileItem);
                
                const option = document.createElement('option');
                option.value = file.name;
                option.textContent = file.name;
                fileSelect.appendChild(option);
            });
            
            if (data.files && data.files.length > 0) {
                loadFileContent(data.files[0].name);
            }
        } catch (error) {
            console.error('Dosya yükleme hatası:', error);
            document.getElementById('file-list').innerHTML = 
                '<div class="text-red-500 p-2">Dosyalar yüklenemedi</div>';
        }
    }
    
    document.getElementById('file-select').addEventListener('change', function(e) {
        if (e.target.value) {
            loadFileContent(e.target.value);
        }
    });
    
    async function loadFileContent(filename) {
        try {
            currentFile = filename;
            document.getElementById('file-select').value = filename;
            
            const res = await fetch(`/api/get-file/${siteName}/${filename}`);
            if (!res.ok) throw new Error('Dosya yüklenemedi');
            
            const data = await res.json();
            
            if (data.content) {
                document.getElementById('editor').value = data.content;
                updateCharCount();
            }
        } catch (error) {
            console.error('Dosya içeriği yükleme hatası:', error);
            alert('Dosya yüklenemedi: ' + error.message);
        }
    }
    
    async function saveFile() {
        if (!currentFile) {
            alert("Önce bir dosya seçin");
            return;
        }
        
        const content = document.getElementById('editor').value;
        
        try {
            const res = await fetch(`/api/save-file/${siteName}/${currentFile}`, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({content: content})
            });
            
            const data = await res.json();
            
            if (data.success) {
                showStatus(data.message, 'success');
            } else {
                showStatus(data.error || 'Kaydetme hatası', 'error');
            }
        } catch (error) {
            console.error('Kaydetme hatası:', error);
            showStatus('Kaydetme başarısız', 'error');
        }
    }
    
    function newFile() {
        const filename = prompt("Yeni dosya adı (örn: index.html):");
        if (filename) {
            currentFile = filename;
            document.getElementById('editor').value = "";
            
            // Hemen kaydet
            saveFile();
            
            // 1 saniye sonra dosyaları yenile
            setTimeout(() => {
                loadFiles();
                showStatus('Dosya oluşturuldu', 'success');
            }, 1000);
        }
    }
    
    async function deleteCurrentFile() {
        if (!currentFile) {
            alert("Silinecek dosya seçin");
            return;
        }
        
        if (!confirm(`${currentFile} dosyasını silmek istiyor musunuz?`)) {
            return;
        }
        
        try {
            const res = await fetch(`/api/delete-file/${siteName}/${currentFile}`, {
                method: 'DELETE'
            });
            
            const data = await res.json();
            
            if (data.success) {
                showStatus(data.message, 'success');
                document.getElementById('editor').value = "";
                currentFile = "";
                loadFiles();
            } else {
                showStatus(data.error || 'Silme hatası', 'error');
            }
        } catch (error) {
            console.error('Silme hatası:', error);
            showStatus('Silme başarısız', 'error');
        }
    }
    
    function updateCharCount() {
        const text = document.getElementById('editor').value;
        document.getElementById('char-count').textContent = text.length + " karakter";
    }
    
    function showStatus(message, type) {
        const statusEl = document.getElementById('save-status');
        statusEl.textContent = message;
        statusEl.className = 'text-sm ' + (type === 'success' ? 'text-green-500' : 'text-red-500');
        
        setTimeout(() => {
            statusEl.textContent = "";
        }, 3000);
    }
    
    document.getElementById('editor').addEventListener('input', updateCharCount);
    
    // Ctrl+S ile kaydet
    document.addEventListener('keydown', function(e) {
        if ((e.ctrlKey || e.metaKey) && e.key === 's') {
            e.preventDefault();
            saveFile();
        }
    });
    
    window.onload = function() {
        loadFiles();
        updateCharCount();
        
        // Editor'e focusla
        document.getElementById('editor').focus();
    };
    '''
    
    response = make_response(js_content)
    response.headers['Content-Type'] = 'application/javascript'
    return response

# ==================== ERROR HANDLERS ====================
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html', base_domain=BASE_DOMAIN), 404

@app.errorhandler(500)
def internal_server_error(e):
    print(f"❌ 500 HATASI: {str(e)}")
    import traceback
    traceback.print_exc()
    return render_template('500.html', error=str(e), base_domain=BASE_DOMAIN), 500

# ==================== INITIALIZATION ====================
def init_app():
    init_db()
    Path(app.config["UPLOAD_FOLDER"]).mkdir(parents=True, exist_ok=True)
    
    print("="*50)
    print("🚀 FREEHOST PRO ÇALIŞIYOR")
    print(f"🌐 Domain: {BASE_DOMAIN}")
    print(f"📁 Site Formatı: {BASE_DOMAIN}/[site][.tld]")
    print(f"🔧 Debug: {DEBUG_MODE}")
    print("="*50)

# ==================== FIX TEMPLATE CONTEXT ====================
@app.context_processor
def inject_vars():
    return dict(base_domain=BASE_DOMAIN)

# ==================== MAIN ENTRY POINT ====================
if __name__ == "__main__":
    init_app()
    app.run(
        host="0.0.0.0",
        port=PORT,
        debug=DEBUG_MODE
)
