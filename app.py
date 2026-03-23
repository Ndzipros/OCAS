from flask import Flask, render_template, request, redirect, session, jsonify
import time, threading, hashlib, os

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "ocas_secret_2025")

connected_devices = {}
DEVICE_TIMEOUT = 30
DATABASE_URL = os.environ.get("DATABASE_URL")

if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

# ─── DB HELPERS ─────────────────────────────────────────
def get_db():
    if DATABASE_URL:
        import psycopg2
        return psycopg2.connect(DATABASE_URL)
    else:
        import sqlite3
        conn = sqlite3.connect("alerts.db")
        conn.row_factory = sqlite3.Row
        return conn

def ph():
    return "%s" if DATABASE_URL else "?"

def row_to_dict(row):
    if row is None:
        return None
    if DATABASE_URL:
        return dict(row)
    import sqlite3
    return dict(row)

def db_fetchall(query, params=()):
    if DATABASE_URL:
        import psycopg2.extras
        conn = get_db()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute(query, params)
        rows = [dict(r) for r in cur.fetchall()]
        cur.close(); conn.close()
        return rows
    else:
        conn = get_db()
        rows = [dict(r) for r in conn.execute(query, params).fetchall()]
        conn.close()
        return rows

def db_fetchone(query, params=()):
    if DATABASE_URL:
        import psycopg2.extras
        conn = get_db()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute(query, params)
        row = cur.fetchone()
        cur.close(); conn.close()
        return dict(row) if row else None
    else:
        conn = get_db()
        row = conn.execute(query, params).fetchone()
        conn.close()
        return dict(row) if row else None

def db_execute(query, params=()):
    if DATABASE_URL:
        conn = get_db()
        cur = conn.cursor()
        cur.execute(query, params)
        conn.commit(); cur.close(); conn.close()
    else:
        conn = get_db()
        conn.execute(query, params)
        conn.commit(); conn.close()

def db_count(query, params=()):
    if DATABASE_URL:
        conn = get_db()
        cur = conn.cursor()
        cur.execute(query, params)
        result = cur.fetchone()[0]
        cur.close(); conn.close()
        return result
    else:
        conn = get_db()
        result = conn.execute(query, params).fetchone()[0]
        conn.close()
        return result

def init_db():
    P = ph()
    if DATABASE_URL:
        db_execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id SERIAL PRIMARY KEY,
                title TEXT NOT NULL,
                message TEXT NOT NULL,
                priority TEXT NOT NULL,
                time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        db_execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                fullname TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role TEXT DEFAULT 'client',
                joined TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
    else:
        db_execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                message TEXT NOT NULL,
                priority TEXT NOT NULL,
                time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        db_execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                fullname TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role TEXT DEFAULT 'client',
                joined TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

init_db()

# ─── UTILS ──────────────────────────────────────────────
def hash_pw(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect("/admin/login")
        return f(*args, **kwargs)
    return decorated

def client_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("client_logged_in"):
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated

def clean_devices():
    while True:
        now = time.time()
        for ip in list(connected_devices):
            if now - connected_devices[ip] > DEVICE_TIMEOUT:
                del connected_devices[ip]
        time.sleep(10)

threading.Thread(target=clean_devices, daemon=True).start()

# ─── ROUTES ─────────────────────────────────────────────
@app.route("/")
def welcome():
    return render_template("welcome.html")

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if session.get("client_logged_in"):
        return redirect("/feed")
    error = None
    if request.method == "POST":
        fullname = request.form["fullname"].strip()
        email    = request.form["email"].strip().lower()
        password = request.form["password"]
        confirm  = request.form["confirm"]
        if len(password) < 6:
            error = "Password must be at least 6 characters."
        elif password != confirm:
            error = "Passwords do not match."
        else:
            try:
                P = ph()
                db_execute(f"INSERT INTO users (fullname,email,password) VALUES ({P},{P},{P})",
                           (fullname, email, hash_pw(password)))
                return redirect("/login?registered=1")
            except Exception:
                error = "An account with this email already exists."
    return render_template("signup.html", error=error)

@app.route("/login", methods=["GET", "POST"])
def client_login():
    if session.get("client_logged_in"):
        return redirect("/feed")
    error   = None
    success = request.args.get("registered")
    if request.method == "POST":
        email    = request.form["email"].strip().lower()
        password = request.form["password"]
        P = ph()
        user = db_fetchone(f"SELECT * FROM users WHERE email={P} AND password={P}",
                           (email, hash_pw(password)))
        if user:
            session["client_logged_in"] = True
            session["client_name"]      = user["fullname"]
            session["client_email"]     = user["email"]
            return redirect("/feed")
        error = "Incorrect email or password."
    return render_template("login_client.html", error=error, success=success)

@app.route("/client-logout")
def client_logout():
    session.pop("client_logged_in", None)
    session.pop("client_name", None)
    session.pop("client_email", None)
    return redirect("/")

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if session.get("logged_in"):
        return redirect("/dashboard")
    error = None
    if request.method == "POST":
        if request.form["username"] == "admin" and request.form["password"] == "admin1234":
            session["logged_in"] = True
            return redirect("/dashboard")
        error = "Invalid credentials."
    return render_template("login.html", error=error)

@app.route("/logout")
def logout():
    session.pop("logged_in", None)
    return redirect("/admin/login")

@app.route("/dashboard")
@login_required
def dashboard():
    P = ph()
    total       = db_count("SELECT COUNT(*) FROM alerts")
    emergency   = db_count(f"SELECT COUNT(*) FROM alerts WHERE priority={P}", ("Emergency",))
    warning     = db_count(f"SELECT COUNT(*) FROM alerts WHERE priority={P}", ("Warning",))
    info        = db_count(f"SELECT COUNT(*) FROM alerts WHERE priority={P}", ("Information",))
    recent      = db_fetchall("SELECT * FROM alerts ORDER BY time DESC LIMIT 3")
    users_count = db_count("SELECT COUNT(*) FROM users")
    return render_template("dashboard.html", total=total, emergency=emergency,
                           warning=warning, info=info, recent=recent,
                           device_count=len(connected_devices),
                           users_count=users_count)

@app.route("/create-alert", methods=["GET", "POST"])
@login_required
def create_alert():
    if request.method == "POST":
        P = ph()
        db_execute(f"INSERT INTO alerts (title,message,priority) VALUES ({P},{P},{P})",
                   (request.form["title"], request.form["message"], request.form["priority"]))
        return redirect("/alerts")
    return render_template("create_alert.html")

@app.route("/alerts")
@login_required
def view_alerts():
    alerts = db_fetchall("SELECT * FROM alerts ORDER BY time DESC")
    return render_template("alerts.html", alerts=alerts)

@app.route("/delete-alert/<int:alert_id>", methods=["POST"])
@login_required
def delete_alert(alert_id):
    P = ph()
    db_execute(f"DELETE FROM alerts WHERE id={P}", (alert_id,))
    return redirect("/alerts")

@app.route("/feed")
@client_required
def public_feed():
    connected_devices[request.remote_addr] = time.time()
    alerts = db_fetchall("SELECT * FROM alerts ORDER BY time DESC LIMIT 10")
    return render_template("feed.html", alerts=alerts, client_name=session.get("client_name","User"))

@app.route("/api/latest")
def api_latest():
    connected_devices[request.remote_addr] = time.time()
    row = db_fetchone("SELECT * FROM alerts ORDER BY time DESC LIMIT 1")
    if row:
        return jsonify({"id": row["id"], "title": row["title"],
                        "message": row["message"], "priority": row["priority"],
                        "time": str(row["time"])})
    return jsonify({"id": 0})

@app.route("/api/devices")
@login_required
def api_devices():
    return jsonify({"count": len(connected_devices)})

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")
