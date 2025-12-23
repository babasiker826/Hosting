# backend.py (GÜNCEL - ENTRY_FILE / AST destekli)
from flask import (
    Flask, render_template, request, redirect, url_for, session,
    jsonify, send_file, flash, render_template_string
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
import os, socket, subprocess, shutil, pathlib, ast

# ========== CONFIG ==========
BASE_DOMAIN = "x.2026tr.xyz"       # Test için lvh.me önerilir (tüm alt domainleri 127.0.0.1'e çözer)
DEFAULT_PORT_CHECK = 5000    # önce bu porta bakacağız, doluysa 5001 kullan

# Dinamik port tespiti (5000 meşgul ise 5001 kullan)
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
PORT = 5001 if s.connect_ex(("127.0.0.1", DEFAULT_PORT_CHECK)) == 0 else DEFAULT_PORT_CHECK
s.close()

# Flask app — NOTE: SERVER_NAME KULLANILMIYOR (esnek host dispatch)
app = Flask(__name__, template_folder="templates", static_folder="static")
app.secret_key = os.urandom(24)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///hosting.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["UPLOAD_FOLDER"] = "users"

db = SQLAlchemy(app)

# ========== MODELS ==========
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(120))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_admin = db.Column(db.Boolean, default=False)

class Website(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
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
    base = pathlib.Path(app.config["UPLOAD_FOLDER"]) / user.username / site_name / "public_html"
    return base

def run_php(file_path, timeout=8):
    try:
        res = subprocess.run(["php", file_path], capture_output=True, text=True, timeout=timeout)
        return res.stdout or res.stderr
    except subprocess.TimeoutExpired:
        return "PHP execution timeout"
    except Exception as e:
        return f"PHP exec error: {e}"

def run_python(file_path, timeout=8):
    try:
        res = subprocess.run(["python3", file_path], capture_output=True, text=True, timeout=timeout)
        return res.stdout or res.stderr
    except subprocess.TimeoutExpired:
        return "Python execution timeout"
    except Exception as e:
        return f"Python exec error: {e}"

# ========== AST helper: read ENTRY_FILE from public_html/backend.py (sadece sabit okunur) ==========
def read_entry_file_from_backend(site_base: pathlib.Path):
    """
    site_base: pathlib.Path -> users/<username>/<site>/public_html
    Aranacak dosya: site_base / 'backend.py'
    Eğer içinde ENTRY_FILE = "xxx.html" şeklinde bir atama varsa döndürür.
    Güvenlik: dosyayı çalıştırmaz, sadece AST ile parse eder.
    """
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
                        # Python 3.8+: Constant, önceki versiyonlarda Str
                        if isinstance(value, ast.Constant) and isinstance(value.value, str):
                            fname = os.path.basename(value.value)
                            return fname
                        elif isinstance(value, ast.Str):
                            fname = os.path.basename(value.s)
                            return fname
        return None
    except Exception:
        return None

# ========== HOST-BASED SUBDOMAIN DISPATCHER ==========
from flask import abort

def extract_site_from_host(host):
    """
    host ör: 'siteadi.lvh.me:5001' veya '127.0.0.1:5001'
    Buradan ilk label'ı site_name olarak al.
    """
    host_only = (host or "").split(":")[0].strip()
    if not host_only:
        return None
    if host_only in (BASE_DOMAIN, "localhost", "127.0.0.1"):
        return None
    if '.' in host_only:
        return host_only.split('.')[0]
    return None

@app.before_request
def host_dispatcher():
    """
    Eğer gelen istek panelin kendi rotalarına ait değilse ve Host header
    bir subdomain (siteadı.base) içeriyorsa doğrudan siteyi servis et.
    """
    # Panel ile ilişkili prefix'leri atla (bunlar panel rotaları)
    panel_prefixes = (
        "/login", "/logout", "/dashboard", "/websites", "/create-site",
        "/file-manager", "/api", "/save-file", "/create-file", "/delete-file",
        "/upload-file", "/toggle-site", "/delete-site", "/settings", "/static"
    )
    # Eğer panel rotalarından biriyse normal route'lar işlesin
    for p in panel_prefixes:
        if request.path.startswith(p):
            return None

    host = request.host or ""
    site_name = extract_site_from_host(host)
    if not site_name:
        return None  # panel isteği veya localhost isteği

    # Subdomain isteği -> site dosyalarını servis et
    website = Website.query.filter_by(site_name=site_name).first()
    if not website or website.status != "active":
        return "Site not found", 404

    user = db.session.get(User, website.user_id)
    if not user:
        return "Owner not found", 404

    site_base = safe_site_path(user, site_name)

    # Eğer path boşsa veya klasör isteği ise default dosya bulma mantığı
    path = request.path.lstrip('/')
    if path == "" or path.endswith('/'):
        # .html dosyalarını tara
        html_files = []
        if site_base.exists():
            for p in site_base.iterdir():
                if p.is_file() and p.suffix.lower() == ".html":
                    html_files.append(p.name)
        # Hiç .html yoksa (ama php/python veya başka dosya olabilir) önce default php/html kontrolü:
        if len(html_files) == 0:
            # önce index.php / index.html dosyasına bak
            for default in ("index.php","index.html","default.html"):
                candidate = site_base / default
                if candidate.exists():
                    path = default
                    break
            else:
                return "No default file found (no .html present)", 404
        # Tek .html varsa onu kullan
        elif len(html_files) == 1:
            path = html_files[0]
        else:
            # Birden fazla .html -> public_html/backend.py içindeki ENTRY_FILE bekle
            entry = read_entry_file_from_backend(site_base)
            if entry and entry in html_files:
                path = entry
            else:
                # Kullanıcıya okunaklı bir yönlendirme sayfası göster
                files_list_html = "<ul>" + "".join(f"<li>{f}</li>" for f in html_files) + "</ul>"
                example_backend = ('ENTRY_FILE = "index.html"  # örnek: ana sayfa olarak index.html seçilir\n'
                                   '# Dosya public_html/backend.py içine konmalı ve sadece ENTRY_FILE ataması içermeli.')
                info_html = f"""
                    <html><head><meta charset="utf-8"><title>Action needed</title>
                    <style>body{{font-family:Inter,Arial;background:#071026;color:#e6eef8;padding:30px}} pre{{background:#001021;padding:12px;border-radius:8px;color:#bfe}}</style>
                    </head><body>
                    <h2>Uyarı: Birden fazla .html dosyası bulundu</h2>
                    <p>Bu site dizininde birden fazla .html dosyası bulundu. Hangisinin ana sayfa (entry) olacağını belirtmek için <code>public_html/backend.py</code> oluşturun ve içinde şu satırı koyun:</p>
                    <pre>{example_backend}</pre>
                    <p>Mevcut .html dosyalar:</p>
                    {files_list_html}
                    <p>Not: backend.py dosyası çalıştırılmayacak; sunucu yalnızca <code>ENTRY_FILE</code> sabitini güvenle okuyacak.</p>
                    </body></html>
                """
                return info_html, 400

    file_path = site_base / path
    if not file_path.exists():
        return "File not found", 404

    # PHP / Python / Static handling
    if str(file_path).endswith(".php") and website.php_enabled:
        return run_php(str(file_path))
    if str(file_path).endswith(".py") and website.python_enabled:
        return run_python(str(file_path))
    try:
        return send_file(str(file_path))
    except Exception as e:
        return f"File send error: {e}", 500

# ========== PANEL ROUTES ==========
@app.route("/", methods=["GET"])
def index():
    if get_current_user():
        return redirect("/dashboard")
    return render_template("login.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            session["user_id"] = user.id
            session["username"] = user.username
            flash("Başarıyla giriş yapıldı!", "success")
            return redirect("/dashboard")
        flash("Geçersiz kullanıcı adı veya şifre!", "danger")
        return redirect("/")
    return render_template("login.html")

@app.route("/register", methods=["POST"])
def register():
    username = request.form.get("username", "").strip()
    email = request.form.get("email", "").strip()
    password = request.form.get("password", "")
    confirm = request.form.get("confirm_password", "")
    if password != confirm:
        flash("Şifreler eşleşmiyor!", "danger")
        return redirect("/")
    if User.query.filter_by(username=username).first():
        flash("Bu kullanıcı adı zaten alınmış!", "danger")
        return redirect("/")
    hashed = generate_password_hash(password)
    new_user = User(username=username, email=email, password_hash=hashed)
    db.session.add(new_user)
    db.session.commit()
    # create user folders
    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
    os.makedirs(os.path.join(app.config["UPLOAD_FOLDER"], username), exist_ok=True)
    flash("Hesap oluşturuldu! Giriş yapabilirsiniz.", "success")
    return redirect("/")

@app.route("/logout")
def logout():
    session.clear()
    flash("Çıkış yapıldı.", "success")
    return redirect("/")

@app.route("/dashboard")
def dashboard():
    user = get_current_user()
    if not user:
        return redirect("/")
    sites = Website.query.filter_by(user_id=user.id).all()
    return render_template("dashboard.html",
                           username=user.username,
                           websites=sites,
                           sites_count=len(sites),
                           base_domain=BASE_DOMAIN,
                           port=PORT)

@app.route("/websites")
def websites_page():
    user = get_current_user()
    if not user:
        return redirect("/")
    sites = Website.query.filter_by(user_id=user.id).all()
    return render_template("websites.html", websites=sites, base_domain=BASE_DOMAIN, port=PORT)

@app.route("/create-site", methods=["GET", "POST"])
def create_site():
    user = get_current_user()
    if not user:
        return redirect("/")
    if request.method == "POST":
        site_name = request.form.get("site_name", "").lower().strip().replace(" ", "-")
        php_enabled = bool(request.form.get("php_enabled"))
        python_enabled = bool(request.form.get("python_enabled"))
        if not site_name:
            flash("Site adı gerekli", "danger")
            return redirect("/create-site")
        domain = f"{site_name}.{BASE_DOMAIN}"
        if Website.query.filter_by(domain=domain).first() or Website.query.filter_by(site_name=site_name).first():
            flash("Bu site adı zaten kullanımda!", "danger")
            return redirect("/create-site")
        new_site = Website(user_id=user.id, domain=domain, site_name=site_name,
                           php_enabled=php_enabled, python_enabled=python_enabled)
        db.session.add(new_site)
        db.session.commit()
        # create file tree
        site_path = safe_site_path(user, site_name)
        os.makedirs(site_path, exist_ok=True)
        # default index
        with open(site_path / "index.html", "w", encoding="utf-8") as f:
            f.write(f"""<!doctype html>
<html><head><meta charset="utf-8"><title>{site_name}</title></head>
<body style="font-family:Inter,Arial;background:#071026;color:#e6eef8;display:flex;align-items:center;justify-content:center;height:100vh;margin:0">
  <div style="text-align:center">
    <h1 style="font-size:48px;margin:0">{site_name}</h1>
    <p style="opacity:0.8">URL: http://{site_name}.{BASE_DOMAIN}:{PORT}</p>
  </div>
</body></html>""")
        flash(f"Site oluşturuldu! URL: http://{site_name}.{BASE_DOMAIN}:{PORT}", "success")
        return redirect("/websites")
    return render_template("create_site.html", base_domain=BASE_DOMAIN, port=PORT)

@app.route("/file-manager")
def file_manager():
    user = get_current_user()
    if not user:
        return redirect("/")
    websites = Website.query.filter_by(user_id=user.id).all()
    return render_template("file_manager.html", websites=websites, base_domain=BASE_DOMAIN, port=PORT)

# ========== API (Files) ==========
@app.route("/api/files/<int:website_id>")
def api_files(website_id):
    user = get_current_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 403
    website = db.session.get(Website, website_id)
    if not website or website.user_id != user.id:
        return jsonify({"error": "Unauthorized"}), 403
    site_path = safe_site_path(user, website.site_name)
    files = []
    if site_path.exists():
        for item in sorted(os.listdir(site_path)):
            item_path = site_path / item
            files.append(item + ("/" if os.path.isdir(item_path) else ""))
    return jsonify({"files": files})

@app.route("/api/file/<int:website_id>/<path:filename>")
def api_file(website_id, filename):
    user = get_current_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 403
    website = db.session.get(Website, website_id)
    if not website or website.user_id != user.id:
        return jsonify({"error": "Unauthorized"}), 403
    file_path = safe_site_path(user, website.site_name) / filename
    if file_path.exists() and file_path.is_file():
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
            return jsonify({"filename": filename, "content": content})
        except Exception as e:
            return jsonify({"error": "Dosya okunamadı", "detail": str(e)}), 500
    return jsonify({"error": "Dosya bulunamadı"}), 404

@app.route("/save-file/<int:website_id>/<path:filename>", methods=["POST"])
def save_file(website_id, filename):
    user = get_current_user()
    if not user:
        return jsonify({"success": False, "error": "Unauthorized"}), 403
    website = db.session.get(Website, website_id)
    if not website or website.user_id != user.id:
        return jsonify({"success": False, "error": "Unauthorized"}), 403
    data = request.json or {}
    content = data.get("content", "")
    safe_name = os.path.normpath(filename)
    # Prevent path traversal
    safe_name = os.path.basename(safe_name)
    file_path = safe_site_path(user, website.site_name) / safe_name
    try:
        os.makedirs(file_path.parent, exist_ok=True)
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(content)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/create-file/<int:website_id>", methods=["POST"])
def create_file(website_id):
    user = get_current_user()
    if not user:
        return jsonify({"success": False, "error": "Unauthorized"}), 403
    website = db.session.get(Website, website_id)
    if not website or website.user_id != user.id:
        return jsonify({"success": False, "error": "Unauthorized"}), 403
    data = request.json or {}
    filename = data.get("filename", "").strip()
    if not filename:
        return jsonify({"success": False, "error": "Dosya adı gerekli"})
    filename = secure_filename(filename)
    file_path = safe_site_path(user, website.site_name) / filename
    try:
        os.makedirs(file_path.parent, exist_ok=True)
        with open(file_path, "w", encoding="utf-8") as f:
            f.write("")
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/delete-file/<int:website_id>/<path:filename>", methods=["DELETE"])
def delete_file(website_id, filename):
    user = get_current_user()
    if not user:
        return jsonify({"success": False, "error": "Unauthorized"}), 403
    website = db.session.get(Website, website_id)
    if not website or website.user_id != user.id:
        return jsonify({"success": False, "error": "Unauthorized"}), 403
    # normalize and prevent traversal
    safe_name = os.path.basename(os.path.normpath(filename))
    file_path = safe_site_path(user, website.site_name) / safe_name
    try:
        if file_path.exists():
            if file_path.is_dir():
                shutil.rmtree(file_path)
            else:
                file_path.unlink()
            return jsonify({"success": True})
        else:
            return jsonify({"success": False, "error": "Dosya bulunamadı"}), 404
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/upload-file/<int:website_id>", methods=["POST"])
def upload_file(website_id):
    user = get_current_user()
    if not user:
        return jsonify({"success": False, "error": "Unauthorized"}), 403
    website = db.session.get(Website, website_id)
    if not website or website.user_id != user.id:
        return jsonify({"success": False, "error": "Unauthorized"}), 403
    if 'files[]' not in request.files:
        return jsonify({"success": False, "error": "No files uploaded"})
    files = request.files.getlist("files[]")
    uploaded = []
    for file in files:
        if not file:
            continue
        filename = secure_filename(file.filename)
        save_path = safe_site_path(user, website.site_name) / filename
        os.makedirs(save_path.parent, exist_ok=True)
        file.save(str(save_path))
        uploaded.append(filename)
    return jsonify({"success": True, "uploaded": uploaded})

# ========== SITE TOGGLE / DELETE ==========
@app.route("/toggle-site/<int:site_id>")
def toggle_site(site_id):
    user = get_current_user()
    if not user:
        return redirect("/")
    website = db.session.get(Website, site_id)
    if website and website.user_id == user.id:
        website.status = "inactive" if website.status == "active" else "active"
        db.session.commit()
        flash(f"Site durumu değiştirildi: {website.status}", "success")
    return redirect("/websites")

@app.route("/delete-site/<int:site_id>")
def delete_site(site_id):
    user = get_current_user()
    if not user:
        return redirect("/")
    website = db.session.get(Website, site_id)
    if website and website.user_id == user.id:
        site_path = safe_site_path(user, website.site_name)
        if site_path.exists():
            shutil.rmtree(site_path.parent)
        db.session.delete(website)
        db.session.commit()
        flash("Site silindi!", "success")
    return redirect("/websites")

# ========== SETTINGS (inline render) ==========
@app.route("/settings")
def settings():
    user = get_current_user()
    if not user:
        return redirect("/")
    return render_template_string('''
    {% extends "base.html" %}
    {% block title %}Ayarlar{% endblock %}
    {% block content %}
    <div class="card">
        <h1>⚙️ Ayarlar</h1>
        <div class="form-group">
            <label>Kullanıcı Adı</label>
            <input type="text" class="form-control" value="{{ session.username }}" readonly>
        </div>
        <a href="/logout" class="btn btn-danger">🚪 Çıkış Yap</a>
    </div>
    {% endblock %}
    ''')

# ========== DB INIT ==========
def init_db():
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username="admin").first():
            admin = User(username="admin", password_hash=generate_password_hash("admin123"),
                         email="admin@localhost", is_admin=True)
            db.session.add(admin)
            db.session.commit()
            print("Admin oluşturuldu: admin / admin123")

# ========== RUN ==========
if __name__ == "__main__":
    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
    init_db()

    print("\n" + "="*50)
    print("🚀 Nabi Hosting (Termux/Local) Başlatılıyor")
    print(f"Panel: http://{BASE_DOMAIN}:{PORT}")
    print(f"Site örneği: http://siteadi.{BASE_DOMAIN}:{PORT}")
    print("="*50 + "\n")

    # Reloader kapalı: port/restart karışıklıklarını engeller
    app.run(host="0.0.0.0", port=PORT, debug=True, use_reloader=False)
