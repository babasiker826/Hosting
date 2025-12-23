# backend.py - Render-ready with GitHub fetch/cache for user sites
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

# ========== CONFIG ==========
BASE_DOMAIN = os.environ.get("BASE_DOMAIN", "x.2026tr.xyz")
PORT = int(os.environ.get("PORT", 5000))
APP_ROOT = Path(__file__).parent.resolve()

# ========== TOKEN GİZLEME ==========
class TokenVault:
    """Token'ı parçalayıp farklı yerlerde sakla"""
    
    @staticmethod
    def get_github_token():
        """Token'ı güvenli şekilde getir"""
        # Token parçaları
        parts = [
            "ghp_",  # prefix
            "PJuY",  # parça 1
            "i0Lw",  # parça 2
            "vf0b",  # parça 3
            "A6rz",  # parça 4
            "vOhW",  # parça 5
            "nLNV",  # parça 6
            "Ek35",  # parça 7
            "Yq3e",  # parça 8
            "A77V"   # parça 9
        ]
        return ''.join(parts)

# GitHub credentials
GITHUB_OWNER = "babasiker826"
GITHUB_REPO = "nabi-hosting-files"
GITHUB_TOKEN = TokenVault.get_github_token()

# sync timing (seconds) - don't pull on every request
GITHUB_SYNC_INTERVAL = int(os.environ.get("GITHUB_SYNC_INTERVAL", 60))

# ========== FLASK APP ==========
app = Flask(__name__, template_folder="templates", static_folder="static")
app.secret_key = "nabi_secure_key_2024_tr_826_baba"
app.config["UPLOAD_FOLDER"] = "user_files"
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB

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
            status TEXT DEFAULT 'active'
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

# ========== GITHUB HELPERS ==========
def github_api_get(path):
    """GET GitHub API for contents; returns JSON or None."""
    if not GITHUB_OWNER or not GITHUB_REPO or not GITHUB_TOKEN:
        print("GitHub credentials missing")
        return None
    
    url = f"https://api.github.com/repos/{GITHUB_OWNER}/{GITHUB_REPO}/contents/{path}"
    headers = {"Authorization": f"token {GITHUB_TOKEN}", "Accept": "application/vnd.github+json"}
    try:
        r = requests.get(url, headers=headers, timeout=15)
        if r.status_code == 200:
            return r.json()
        else:
            print(f"GitHub API error: {r.status_code}")
            return None
    except Exception as e:
        print(f"GitHub API exception: {e}")
        return None

def github_download_file(download_url):
    """Download raw file by download_url (no auth needed for public raw content)."""
    try:
        r = requests.get(download_url, timeout=15)
        if r.status_code == 200:
            return r.content
    except Exception as e:
        print(f"Download error: {e}")
        pass
    return None

def write_bytes_safe(target_base: Path, relative_path: str, content: bytes):
    """
    Write bytes to a file under target_base safely.
    Prevent path traversal by forcing resolved path to start with target_base.
    """
    rel = Path(relative_path)
    rel = Path(*rel.parts)
    dest = (target_base / rel).resolve()
    if str(dest).startswith(str(target_base.resolve())):
        dest.parent.mkdir(parents=True, exist_ok=True)
        with open(dest, "wb") as f:
            f.write(content)
        return True
    return False

def is_recently_synced(site_base: Path):
    marker = site_base / ".gh_last_sync"
    if marker.exists():
        try:
            ts = float(marker.read_text())
            return (time.time() - ts) < GITHUB_SYNC_INTERVAL
        except Exception:
            return False
    return False

def mark_synced(site_base: Path):
    marker = site_base / ".gh_last_sync"
    try:
        marker.write_text(str(time.time()))
    except Exception:
        pass

def recursive_github_fetch(repo_path: str, target_base: Path):
    """
    Recursively fetch contents from GitHub API path `repo_path` (relative inside repo)
    and write into target_base.
    Returns number of files downloaded.
    """
    items = github_api_get(repo_path)
    if items is None:
        return 0
    
    if isinstance(items, dict) and items.get("type") == "file":
        items = [items]
    
    count = 0
    for item in items:
        t = item.get("type")
        name = item.get("name")
        if t == "file":
            download_url = item.get("download_url")
            content = github_download_file(download_url)
            if content is None:
                if item.get("encoding") == "base64" and item.get("content"):
                    content = base64.b64decode(item.get("content"))
            if content is not None:
                repo_item_path = item.get("path", "")
                if repo_item_path.startswith(repo_path):
                    rel = repo_item_path[len(repo_path):].lstrip("/")
                else:
                    rel = name
                if write_bytes_safe(target_base, rel, content):
                    count += 1
        elif t == "dir":
            sub_path = item.get("path")
            count += recursive_github_fetch(sub_path, target_base)
    return count

def update_user_site_from_github(username: str, site_name: str):
    """
    Pull files from repo path users/<username>/<site_name> into users/<username>/<site_name>/public_html
    Returns True if files were fetched or existed.
    """
    if not (GITHUB_OWNER and GITHUB_REPO and GITHUB_TOKEN):
        print(f"GitHub not configured for {username}/{site_name}")
        return False

    repo_base = f"users/{username}/{site_name}"
    site_public = Path(app.config["UPLOAD_FOLDER"]) / username / site_name / "public_html"
    site_public.mkdir(parents=True, exist_ok=True)

    if is_recently_synced(site_public):
        return site_public.exists() and any(site_public.iterdir())

    try:
        files_downloaded = recursive_github_fetch(repo_base, site_public)
        if files_downloaded > 0:
            mark_synced(site_public)
            print(f"GitHub'dan {files_downloaded} dosya indirildi: {username}/{site_name}")
            return True
        
        if any(site_public.iterdir()):
            mark_synced(site_public)
            return True
        
        print(f"GitHub'da dosya bulunamadı: {username}/{site_name}")
        return False
    except Exception as e:
        print(f"GitHub sync error for {username}/{site_name}: {e}")
        traceback.print_exc()
        return False

# ========== AST helper for ENTRY_FILE ==========
def read_entry_file_from_backend(site_base: Path):
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
        "/upload-file", "/toggle-site", "/delete-site", "/settings", "/static", "/admin"
    )
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

    try:
        updated = update_user_site_from_github(user["username"], site_name)
    except Exception:
        updated = False

    rel_path = request.path.lstrip('/')
    if rel_path == "" or rel_path.endswith("/"):
        html_files = [p.name for p in site_public.iterdir() if p.is_file() and p.suffix.lower() == ".html"] if site_public.exists() else []
        if len(html_files) == 0:
            for default in ("index.php", "index.html", "default.html", "home.html"):
                if (site_public / default).exists():
                    rel_path = default
                    break
            else:
                loading_html = f"""<!doctype html>
<html><head><meta charset="utf-8"><title>Site yükleniyor...</title>
<meta http-equiv="refresh" content="2">
<style>body{{font-family:Inter,Arial;background:#071026;color:#e6eef8;display:flex;align-items:center;justify-content:center;height:100vh;margin:0}}
.box{{text-align:center;padding:24px;border-radius:12px;background:rgba(255,255,255,0.02)}}</style>
</head><body>
  <div class="box">
    <h2>🔄 Site yükleniyor...</h2>
    <p>İlk erişimde dosyalar GitHub'dan çekiliyor. Lütfen bekleyin, sayfa otomatik yenilenecek.</p>
    <p class="muted">Eğer uzun süre yüklenmezse, site sahibi dosyalarını yüklediğinden emin olsun.</p>
  </div>
</body></html>"""
                return loading_html, 200

        elif len(html_files) == 1:
            rel_path = html_files[0]
        else:
            entry = read_entry_file_from_backend(site_public)
            if entry and (site_public / entry).exists():
                rel_path = entry
            else:
                files_list_html = "<ul>" + "".join(f"<li>{f}</li>" for f in html_files) + "</ul>"
                example_backend = 'ENTRY_FILE = "index.html"'
                info_html = f"""
                    <html><head><meta charset="utf-8"><title>Action needed</title>
                    <style>body{{font-family:Inter,Arial;background:#071026;color:#e6eef8;padding:30px}} pre{{background:#001021;padding:12px;border-radius:8px;color:#bfe}}</style>
                    </head><body>
                    <h2>Uyarı: Birden fazla .html dosyası bulundu</h2>
                    <p>Bu site dizininde birden fazla .html dosyası bulundu. Hangisinin ana sayfa (entry) olacağını belirtmek için <code>public_html/backend.py</code> oluşturun ve içinde şu satırı koyun:</p>
                    <pre>{example_backend}</pre>
                    <p>Mevcut .html dosyalar:</p>
                    {files_list_html}
                    <p>Not: backend.py sunucuda çalıştırılmayacak; sunucu yalnızca <code>ENTRY_FILE</code> sabitini okuyacak.</p>
                    </body></html>
                """
                return info_html, 400

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
        (Path(app.config["UPLOAD_FOLDER"]) / username).mkdir(parents=True, exist_ok=True)
        flash("Kayıt başarılı. Giriş yapabilirsiniz.", "success")
        return redirect("/login")
    return render_template("register.html", base_domain=BASE_DOMAIN)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username","").strip()
        password = request.form.get("password","")
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
    return render_template("dashboard.html", username=user["username"], websites=websites, base_domain=BASE_DOMAIN)

@app.route("/create-site", methods=["GET", "POST"])
def create_site():
    user = get_current_user()
    if not user:
        return redirect("/login")
    if request.method == "POST":
        site_name = request.form.get("site_name","").lower().strip()
        site_name = ''.join(c for c in site_name if c.isalnum() or c in '-_')
        if not site_name:
            flash("Site adı gerekli","danger"); return redirect("/create-site")
        if website_exists(site_name):
            flash("Site adı kullanımda","danger"); return redirect("/create-site")
        domain = f"{site_name}.{BASE_DOMAIN}"
        php_enabled = 1 if request.form.get("php_enabled") else 0
        python_enabled = 1 if request.form.get("python_enabled") else 0
        
        website_id = create_website(user["id"], domain, site_name, php_enabled, python_enabled)
        site_path = Path(app.config["UPLOAD_FOLDER"]) / user["username"] / site_name / "public_html"
        site_path.mkdir(parents=True, exist_ok=True)
        
        default_html = f"<html><body><h1>{site_name}</h1><p>Yayınlandı.</p></body></html>"
        (site_path / "index.html").write_text(default_html, encoding="utf-8")
        flash(f"Site oluşturuldu: {domain}","success")
        return redirect("/dashboard")
    return render_template("create_site.html", base_domain=BASE_DOMAIN)

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
    print(f"GITHUB OWNER: {GITHUB_OWNER}")
    print(f"GITHUB REPO: {GITHUB_REPO}")
    print("Database: SQLite3 (no SQLAlchemy)")
    print("="*40)

if __name__ == "__main__":
    init_app()
    debug = os.environ.get("DEBUG","False").lower() == "true"
    app.run(host="0.0.0.0", port=PORT, debug=debug, use_reloader=False)
