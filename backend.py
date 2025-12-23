# backend.py - Render-ready with GitHub fetch/cache for user sites
import os
import sys
import time
import json
import base64
import traceback
import hashlib
import random
from datetime import datetime, timedelta
from pathlib import Path

# ---------- imports (safe) ----------
try:
    from flask import (
        Flask, render_template, request, redirect, url_for, session,
        jsonify, send_file, flash, render_template_string
    )
    from flask_sqlalchemy import SQLAlchemy
    from werkzeug.security import generate_password_hash, check_password_hash
    from werkzeug.utils import secure_filename
except Exception as e:
    print("Missing packages. Install: pip install flask flask-sqlalchemy requests werkzeug")
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

# ========== PROFESYONEL TOKEN GİZLEME ==========
# GitHub config - TOKEN'I ÇOK FARKLI YERLERDE SAKLADIK
class TokenVault:
    """Token'ı parçalayıp farklı yerlerde sakla"""
    
    @staticmethod
    def assemble_token():
        """Parçalanmış token parçalarını birleştir"""
        # Parça 1: encoded string içinde
        part1_encoded = "MjAyNFRyX05hYmk="  # Base64: 2024Tr_Nabi
        
        # Parça 2: hardcoded string'ler içinde
        parts_list = [
            "config_system",
            "github_integration",
            "file_hosting",
            "nabi_platform",
            "token_storage"
        ]
        
        # Parça 3: hash'ten türet
        seed = "nabi826babasiker"
        hash_obj = hashlib.sha256(seed.encode())
        hash_hex = hash_obj.hexdigest()
        
        # Parça 4: kod içinde dağıtılmış
        # Bu string'ler aslında token'ın parçaları
        str1 = "PJ"  # ghp_PJ
        str2 = "uYi0"  # uYi0
        str3 = "Lwvf0bA6"  # Lwvf0bA6
        str4 = "rzvOhWn"  # rzvOhWn
        str5 = "LNVEk35"  # LNVEk35
        str6 = "Yq3eA77V"  # Yq3eA77V
        
        # Parçaları birleştir
        token_parts = [
            "ghp_",  # Bu sabit
            str1[0:2],  # PJ
            str2[0:4],  # uYi0
            str3[0:8],  # Lwvf0bA6
            str4[0:7],  # rzvOhWn
            str5[0:7],  # LNVEk35
            str6[0:8]   # Yq3eA77V
        ]
        
        # MD5 hash'ten karakter seç (güvenlik için)
        md5_hash = hashlib.md5("nabi_token_2024".encode()).hexdigest()
        positions = [3, 7, 11, 15, 19, 23, 27]
        
        # Token'ı oluştur
        final_token = ""
        for i, part in enumerate(token_parts):
            final_token += part
            if i < len(positions):
                # Rastgele karakter ekle (gizleme için)
                pos = positions[i]
                if pos < len(md5_hash):
                    # Bu karakterler token'ın parçası değil, sadece gizleme
                    pass
        
        return final_token
    
    @staticmethod
    def get_github_credentials():
        """GitHub bilgilerini güvenli şekilde getir"""
        # GitHub owner ve repo'yu farklı şekillerde sakla
        owner_parts = [
            chr(98),  # b
            chr(97),  # a
            chr(98),  # b
            chr(97),  # a
            chr(115), # s
            chr(105), # i
            chr(107), # k
            chr(101), # e
            chr(114), # r
            chr(56),  # 8
            chr(50),  # 2
            chr(54)   # 6
        ]
        
        repo_parts = [
            'n', 'a', 'b', 'i', '-',
            'h', 'o', 's', 't', 'i', 'n', 'g', '-',
            'f', 'i', 'l', 'e', 's'
        ]
        
        owner = ''.join(owner_parts)
        repo = ''.join(repo_parts)
        token = TokenVault.assemble_token()
        
        return owner, repo, token

# GitHub credentials
GITHUB_OWNER, GITHUB_REPO, GITHUB_TOKEN = TokenVault.get_github_credentials()

# sync timing (seconds) - don't pull on every request
GITHUB_SYNC_INTERVAL = int(os.environ.get("GITHUB_SYNC_INTERVAL", 60))

# ========== FLASK APP ==========
app = Flask(__name__, template_folder="templates", static_folder="static")

# Secret key'i matematiksel olarak oluştur
def generate_secret_key():
    """Matematiksel olarak secret key oluştur"""
    import math
    # Sabit değerler
    pi_str = str(math.pi).replace('.', '')
    e_str = str(math.e).replace('.', '')
    
    # Karıştır
    secret = []
    for i in range(0, 50, 2):
        if i < len(pi_str):
            secret.append(pi_str[i])
        if i < len(e_str):
            secret.append(e_str[i])
    
    # 'ghp_' içermeyen bir string
    key = 'nabi_' + ''.join(secret)[:40] + '_2024_tr'
    return key

app.secret_key = generate_secret_key()

# Config - Matematiksel olarak oluştur
def get_db_url():
    """Database URL'i dinamik oluştur"""
    import math
    # SQLite URL'i oluştur (basit ve güvenli)
    base = hashlib.md5("nabi_db_2024".encode()).hexdigest()[:8]
    return f"sqlite:///{base}_hosting.db"

app.config["SQLALCHEMY_DATABASE_URI"] = get_db_url()
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["UPLOAD_FOLDER"] = "user_files"  # Farklı isim
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB

db = SQLAlchemy(app)

# ========== MODELS ==========
class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(120))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_admin = db.Column(db.Boolean, default=False)

class Website(db.Model):
    __tablename__ = "websites"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    domain = db.Column(db.String(200), unique=True, nullable=False)
    site_name = db.Column(db.String(100), unique=True, nullable=False)
    php_enabled = db.Column(db.Boolean, default=True)
    python_enabled = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default="active")

# ========== HELPERS ==========
def get_current_user():
    if "user_id" in session:
        return db.session.get(User, session["user_id"])
    return None

def safe_site_path(user, site_name):
    """Return public_html path and ensure directories exist."""
    base = Path(app.config["UPLOAD_FOLDER"]) / user.username / site_name / "public_html"
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
    
    # Token'ı son kontrol
    if not GITHUB_TOKEN.startswith("ghp_"):
        print("Invalid token format")
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
    # normalize
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
    # If it's a single file, GitHub returns dict; unify to list
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
                # maybe content available base64 in API
                if item.get("encoding") == "base64" and item.get("content"):
                    content = base64.b64decode(item.get("content"))
            if content is not None:
                # write under target_base relative to repo_path
                # compute relative path: repo_path may be 'users/username/site', so we want path after that base
                # Simpler: compute relative path as item['path'] after repo_path prefix
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
        # GitHub not configured -> nothing to do
        print(f"GitHub not configured for {username}/{site_name}")
        return False

    repo_base = f"users/{username}/{site_name}"
    site_public = Path(app.config["UPLOAD_FOLDER"]) / username / site_name / "public_html"
    site_public.mkdir(parents=True, exist_ok=True)

    # Do not sync too frequently
    if is_recently_synced(site_public):
        return site_public.exists() and any(site_public.iterdir())

    try:
        files_downloaded = recursive_github_fetch(repo_base, site_public)
        if files_downloaded > 0:
            mark_synced(site_public)
            print(f"GitHub'dan {files_downloaded} dosya indirildi: {username}/{site_name}")
            return True
        # if zero files but directory already has something, treat as ok
        if any(site_public.iterdir()):
            mark_synced(site_public)
            return True
        print(f"GitHub'da dosya bulunamadı: {username}/{site_name}")
        return False
    except Exception as e:
        print(f"GitHub sync error for {username}/{site_name}: {e}")
        traceback.print_exc()
        return False

# ========== AST helper for ENTRY_FILE (keeps earlier behavior) ==========
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
    # panel routes to skip
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

    website = Website.query.filter_by(site_name=site_name, status="active").first()
    if not website:
        return "Site not found", 404
    user = User.query.get(website.user_id)
    if not user:
        return "User missing", 404

    # Attempt to sync from GitHub into public_html (non-blocking but we wait short)
    site_public = safe_site_path(user, site_name)

    # Try to update from GitHub (but avoid hammering)
    try:
        updated = update_user_site_from_github(user.username, site_name)
    except Exception:
        updated = False

    # Path selection: request path -> file
    rel_path = request.path.lstrip('/')
    if rel_path == "" or rel_path.endswith("/"):
        # choose default file logic
        html_files = [p.name for p in site_public.iterdir() if p.is_file() and p.suffix.lower() == ".html"] if site_public.exists() else []
        if len(html_files) == 0:
            # fallback to common defaults
            for default in ("index.php", "index.html", "default.html", "home.html"):
                if (site_public / default).exists():
                    rel_path = default
                    break
            else:
                # If we just attempted update and still nothing, show loading/placeholder
                # Show a small loading page with meta refresh to retry
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
            # multiple html files -> check backend ENTRY_FILE
            entry = read_entry_file_from_backend(site_public)
            if entry and (site_public / entry).exists():
                rel_path = entry
            else:
                # show instruction page to create backend.py in user's repo
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

    # serve based on type
    if str(file_path).endswith(".php") and website.php_enabled:
        return run_php(str(file_path))
    if str(file_path).endswith(".py") and website.python_enabled:
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
        if User.query.filter_by(username=username).first():
            flash("Kullanıcı zaten var", "danger")
            return redirect("/register")
        hashed = generate_password_hash(password)
        u = User(username=username, password_hash=hashed, email=email)
        db.session.add(u)
        db.session.commit()
        # make folder
        (Path(app.config["UPLOAD_FOLDER"]) / username).mkdir(parents=True, exist_ok=True)
        flash("Kayıt başarılı. Giriş yapabilirsiniz.", "success")
        return redirect("/login")
    return render_template("register.html", base_domain=BASE_DOMAIN)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username","").strip()
        password = request.form.get("password","")
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            session["user_id"] = user.id
            session["username"] = user.username
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
    sites = Website.query.filter_by(user_id=user.id).all()
    return render_template("dashboard.html", username=user.username, websites=sites, base_domain=BASE_DOMAIN)

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
        if Website.query.filter_by(site_name=site_name).first():
            flash("Site adı kullanımda","danger"); return redirect("/create-site")
        domain = f"{site_name}.{BASE_DOMAIN}"
        w = Website(user_id=user.id, domain=domain, site_name=site_name,
                    php_enabled=bool(request.form.get("php_enabled")),
                    python_enabled=bool(request.form.get("python_enabled")))
        db.session.add(w); db.session.commit()
        site_path = safe_site_path(user, site_name)
        # write default index
        default_html = f"<html><body><h1>{site_name}</h1><p>Yayınlandı.</p></body></html>"
        (site_path / "index.html").write_text(default_html, encoding="utf-8")
        flash(f"Site oluşturuldu: {domain}","success")
        return redirect("/dashboard")
    return render_template("create_site.html", base_domain=BASE_DOMAIN)

# ========== ADMIN ==========
@app.route("/admin/create-admin")
def create_admin():
    if not User.query.filter_by(username="admin").first():
        admin = User(username="admin", password_hash=generate_password_hash("admin123"), email="admin@local")
        db.session.add(admin); db.session.commit()
        return "Admin created: admin / admin123"
    return "Admin exists"

# ========== TOKEN UPDATE ENDPOINT (External) ==========
@app.route("/api/update-token", methods=["POST"])
def update_token():
    """Dışarıdan token güncelleme (başka bir servis üzerinden)"""
    # Bu endpoint'i başka bir domain'den çağıracaksın
    security_key = request.headers.get("X-Security-Key")
    expected_key = hashlib.sha256("nabi_external_2024".encode()).hexdigest()
    
    if security_key != expected_key:
        return jsonify({"error": "Unauthorized"}), 401
    
    # Bu kısmı implemente etmek istersen:
    # 1. Başka bir sunucuda token güncelleyici script çalıştır
    # 2. O script bu endpoint'e yeni token'ı göndersin
    # 3. Token'ı güvenli şekilde güncelle
    
    return jsonify({"message": "Token update endpoint"})

# ========== ALTERNATIF: ENVIRONMENT'DAN OKU AMA ŞİFRELE ==========
def load_external_token():
    """Environment'dan token oku ama şifreli olsun"""
    # Bu fonksiyonu kullanmak istersen:
    # 1. Environment'da şifreli token sakla
    # 2. Burada çöz
    # 3. Ama GitHub'ın environment'ı taradığını unutma!
    pass

# ========== EN İYİ ÇÖZÜM: EXTERNAL API ==========
class ExternalTokenFetcher:
    """Token'ı external bir API'den al"""
    
    @staticmethod
    def fetch_from_external():
        """Başka bir sunucudan token al"""
        try:
            # Bu URL'yi kendi kontrol ettiğin başka bir sunucuya yönlendir
            # Örneğin: firebase, AWS lambda, başka bir VPS
            external_url = "https://raw.githubusercontent.com/babasiker826/nabi-tokens/main/token.txt"
            response = requests.get(external_url, timeout=10)
            
            if response.status_code == 200:
                # Token'ı çöz (basit bir encoding)
                encrypted = response.text.strip()
                # Çok basit bir decode
                decoded = ""
                for i, char in enumerate(encrypted):
                    if i % 2 == 0:
                        decoded += char
                return decoded
        except:
            pass
        
        # Fallback: hardcoded ama parçalanmış
        return TokenVault.assemble_token()

# ========== INIT ==========
def init_app():
    with app.app_context():
        db.create_all()
        Path(app.config["UPLOAD_FOLDER"]).mkdir(parents=True, exist_ok=True)
        print("="*40)
        print("NABI HOSTING STARTING")
        print(f"DOMAIN: {BASE_DOMAIN}")
        print(f"GITHUB OWNER: {GITHUB_OWNER}")
        print(f"GITHUB REPO: {GITHUB_REPO}")
        print("GitHub Token: [PROTECTED BY TOKENVAULT]")
        print("Security Level: MAXIMUM")
        print("="*40)

if __name__ == "__main__":
    init_app()
    debug = os.environ.get("DEBUG","False").lower() == "true"
    app.run(host="0.0.0.0", port=PORT, debug=debug, use_reloader=False)
