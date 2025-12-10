import logging
import os
import secrets
from datetime import datetime, timedelta
from logging.handlers import RotatingFileHandler

from cs50 import SQL
from flask import Flask, abort, flash, redirect, render_template, request, session, url_for
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from functools import wraps

# Configure application
app = Flask(__name__)

# Environment-driven settings
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///clubhub.db")
SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret")
DEBUG_MODE = os.getenv("DEBUG", "False").lower() == "true"
SESSION_COOKIE_SECURE_FLAG = os.getenv("SESSION_COOKIE_SECURE", "False").lower() == "true"

# Configure Flask settings
app.config.update(
    TEMPLATES_AUTO_RELOAD=True,
    SESSION_PERMANENT=True,
    PERMANENT_SESSION_LIFETIME=timedelta(hours=1),
    SESSION_TYPE="filesystem",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=SESSION_COOKIE_SECURE_FLAG,
    SECRET_KEY=SECRET_KEY,
    DEBUG=DEBUG_MODE,
)
Session(app)

# Configure CS50 Library to use SQLite database (or DATABASE_URL)
db = SQL(DATABASE_URL)
# Enforce foreign keys on SQLite
if DATABASE_URL.startswith("sqlite"):
    try:
        db.execute("PRAGMA foreign_keys = ON")
    except Exception:
        pass

# Logging (rotating file) in non-debug environments
if not DEBUG_MODE:
    handler = RotatingFileHandler("clubhub.log", maxBytes=10240, backupCount=10)
    handler.setLevel(logging.INFO)
    app.logger.addHandler(handler)

# CSRF helpers
def _get_csrf_token():
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_hex(16)
        session["_csrf_token"] = token
    return token


def _is_global_officer():
    uid = session.get("user_id")
    if not uid:
        return False
    rows = db.execute("SELECT is_officer FROM users WHERE id = ?", uid)
    return len(rows) == 1 and rows[0]["is_officer"] == 1


@app.context_processor
def inject_globals():
    return {
        "csrf_token": _get_csrf_token(),
        "is_officer": _is_global_officer(),
    }


# Ensure join_code column exists and populate missing codes
try:
    db.execute("SELECT join_code FROM clubs LIMIT 1")
except Exception:
    try:
        db.execute("ALTER TABLE clubs ADD COLUMN join_code TEXT")
    except Exception:
        pass

try:
    rows = db.execute("SELECT id, join_code FROM clubs WHERE join_code IS NULL OR join_code = ''")
    for row in rows:
        db.execute("UPDATE clubs SET join_code = ? WHERE id = ?", generate_join_code(), row["id"])
except Exception:
    pass

# Ensure announcements have club_id column
try:
    db.execute("SELECT club_id FROM announcements LIMIT 1")
except Exception:
    try:
        db.execute("ALTER TABLE announcements ADD COLUMN club_id INTEGER REFERENCES clubs(id)")
    except Exception:
        pass

# Ensure club_roles table exists
try:
    db.execute(
        "CREATE TABLE IF NOT EXISTS club_roles ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "club_id INTEGER NOT NULL, "
        "name TEXT NOT NULL, "
        "description TEXT, "
        "can_manage_members INTEGER NOT NULL DEFAULT 0, "
        "can_manage_roles INTEGER NOT NULL DEFAULT 0, "
        "can_manage_events INTEGER NOT NULL DEFAULT 0, "
        "can_manage_attendance INTEGER NOT NULL DEFAULT 0, "
        "can_manage_announcements INTEGER NOT NULL DEFAULT 0, "
        "can_manage_join_code INTEGER NOT NULL DEFAULT 0, "
        "can_manage_budget INTEGER NOT NULL DEFAULT 0, "
        "is_default_member INTEGER NOT NULL DEFAULT 0, "
        "is_president INTEGER NOT NULL DEFAULT 0, "
        "FOREIGN KEY (club_id) REFERENCES clubs(id) ON DELETE CASCADE)"
    )
    db.execute("CREATE INDEX IF NOT EXISTS idx_club_roles_club_id ON club_roles(club_id)")
except Exception:
    pass


def ensure_default_roles_for_club(club_id):
    """Ensure core roles exist for a club. Returns dict with keys president_id, member_id, officer_id (optional)."""
    roles = db.execute("SELECT id, name, is_president, is_default_member FROM club_roles WHERE club_id = ?", club_id)
    names = {r["name"]: r["id"] for r in roles}
    president_id = next((r["id"] for r in roles if r["is_president"] == 1), None)
    member_id = next((r["id"] for r in roles if r["is_default_member"] == 1), None)
    # Create president if missing
    if not president_id:
        db.execute(
            "INSERT INTO club_roles (club_id, name, description, can_manage_members, can_manage_roles, can_manage_events, can_manage_attendance, can_manage_announcements, can_manage_join_code, can_manage_budget, is_president) "
            "VALUES (?, 'President', 'Leads the club', 1, 1, 1, 1, 1, 1, 1, 1)",
            club_id,
        )
        president_id = db.execute("SELECT id FROM club_roles WHERE club_id = ? AND is_president = 1 ORDER BY id DESC LIMIT 1", club_id)[0]["id"]
    # Create member if missing
    if not member_id:
        db.execute(
            "INSERT INTO club_roles (club_id, name, description, is_default_member) VALUES (?, 'Member', 'Default club member', 1)",
            club_id,
        )
        member_id = db.execute("SELECT id FROM club_roles WHERE club_id = ? AND is_default_member = 1 ORDER BY id DESC LIMIT 1", club_id)[0]["id"]
    # Create officer role if not present
    officer_id = names.get("Officer")
    if not officer_id:
        db.execute(
            "INSERT INTO club_roles (club_id, name, description, can_manage_events, can_manage_attendance, can_manage_announcements) "
            "VALUES (?, 'Officer', 'Supports club operations', 1, 1, 1)",
            club_id,
        )
        officer_id = db.execute("SELECT id FROM club_roles WHERE club_id = ? AND name = 'Officer' ORDER BY id DESC LIMIT 1", club_id)[0]["id"]
    return {"president_id": president_id, "member_id": member_id, "officer_id": officer_id}


def migrate_memberships_to_roles():
    """Map legacy role strings to new role_id per club."""
    # Ensure defaults for all clubs
    clubs = db.execute("SELECT id FROM clubs")
    defaults = {}
    for c in clubs:
        defaults[c["id"]] = ensure_default_roles_for_club(c["id"])

    # Add role_id if missing/null
    rows = db.execute("SELECT id, club_id, user_id, role, role_id FROM club_membership")
    for row in rows:
        if row.get("role_id"):
            continue
        club_id = row["club_id"]
        role_str = (row.get("role") or "member").lower()
        target = defaults.get(club_id) or ensure_default_roles_for_club(club_id)
        role_id = target["member_id"]
        if role_str == "president":
            role_id = target["president_id"]
        elif role_str == "officer":
            role_id = target["officer_id"]
        elif role_str == "student":
            role_id = target["member_id"]
        try:
            db.execute("UPDATE club_membership SET role_id = ? WHERE id = ?", role_id, row["id"])
        except Exception:
            pass

    # Fill any remaining nulls with default member
    rows = db.execute("SELECT cm.id, cm.club_id FROM club_membership cm WHERE cm.role_id IS NULL")
    for row in rows:
        target = defaults.get(row["club_id"]) or ensure_default_roles_for_club(row["club_id"])
        try:
            db.execute("UPDATE club_membership SET role_id = ? WHERE id = ?", target["member_id"], row["id"])
        except Exception:
            pass


# Run migration to new role system
try:
    migrate_memberships_to_roles()
except Exception:
    pass

# Ensure club_membership has role_id column
try:
    db.execute("SELECT role_id FROM club_membership LIMIT 1")
except Exception:
    try:
        db.execute("ALTER TABLE club_membership ADD COLUMN role_id INTEGER")
    except Exception:
        pass


@app.before_request
def csrf_protect():
    if request.method == "POST":
        token = session.get("_csrf_token")
        form_token = request.form.get("_csrf_token")
        if not token or not form_token or token != form_token:
            abort(400)


def generate_join_code():
    return secrets.token_urlsafe(6)


def is_club_officer(user_id, club_id):
    """Check if user is officer for the given club (or global officer)."""
    if user_id is None:
        return False
    if _is_global_officer():
        return True
    membership = get_membership(user_id, club_id)
    if not membership:
        return False
    return membership.get("can_manage_events") == 1 or membership.get("can_manage_members") == 1


def is_club_president(user_id, club_id):
    if user_id is None:
        return False
    if _is_global_officer():
        return True
    membership = get_membership(user_id, club_id)
    if not membership:
        return False
    return membership.get("is_president") == 1


def is_club_member(user_id, club_id):
    if user_id is None:
        return False
    rows = db.execute(
        "SELECT 1 FROM club_membership WHERE user_id = ? AND club_id = ?",
        user_id,
        club_id,
    )
    return len(rows) > 0


def get_membership(user_id, club_id):
    rows = db.execute(
        "SELECT cm.*, cr.name AS role_name, cr.can_manage_members, cr.can_manage_roles, cr.can_manage_events, "
        "cr.can_manage_attendance, cr.can_manage_announcements, cr.can_manage_join_code, cr.can_manage_budget, cr.is_president "
        "FROM club_membership cm JOIN club_roles cr ON cm.role_id = cr.id "
        "WHERE cm.user_id = ? AND cm.club_id = ?",
        user_id,
        club_id,
    )
    return rows[0] if rows else None


def require_club_permission(club_id, permission_field):
    if _is_global_officer():
        return
    membership = get_membership(session.get("user_id"), club_id)
    if not membership:
        abort(403)
    if not membership.get(permission_field, 0):
        abort(403)

# Ensure clubs table exists and events table has club_id column (migration-safe)
try:
    db.execute(
        "CREATE TABLE IF NOT EXISTS clubs (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, description TEXT, sponsor TEXT, join_code TEXT)"
    )
except Exception:
    pass

# Add club_id column to events if it's missing
try:
    db.execute("SELECT club_id FROM events LIMIT 1")
except Exception:
    try:
        db.execute("ALTER TABLE events ADD COLUMN club_id INTEGER")
    except Exception:
        # Some SQLite builds may not allow ALTER TABLE in this environment; ignore if fails
        pass

# Ensure club_membership table exists (user roles per club)
try:
    db.execute(
        "CREATE TABLE IF NOT EXISTS club_membership ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, club_id INTEGER NOT NULL, role_id INTEGER, "
        "UNIQUE(user_id, club_id), "
        "FOREIGN KEY(user_id) REFERENCES users(id), "
        "FOREIGN KEY(club_id) REFERENCES clubs(id), "
        "FOREIGN KEY(role_id) REFERENCES club_roles(id) ON DELETE SET NULL)"
    )
except Exception:
    pass


# Custom Jinja2 filter for formatting datetime strings
@app.template_filter('format_datetime')
def format_datetime(value):
    """Format ISO datetime string (YYYY-MM-DDTHH:MM) to readable format"""
    if not value:
        return ""
    try:
        # Parse the ISO format string (2025-12-22T09:00)
        dt = datetime.fromisoformat(value)
        # Return formatted: "Dec 22, 2025 at 9:00 AM"
        return dt.strftime("%b %d, %Y at %-I:%M %p").replace("24:00", "12:00 AM")
    except (ValueError, AttributeError):
        return value


def login_required(f):
    """
    Decorate routes to require login.
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            flash("Please log in first.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function


def officer_required(f):
    """
    Decorate routes to require officer permissions.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            flash("Please log in first.", "warning")
            return redirect(url_for("login"))
        if not _is_global_officer():
            abort(403)
        return f(*args, **kwargs)
    return decorated_function


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    # Secure cookies for production
    if SESSION_COOKIE_SECURE_FLAG:
        response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
    return response


# INDEX: show announcements + upcoming events
@app.route("/")
@login_required
def index():
    membership_rows = db.execute(
        "SELECT club_id FROM club_membership WHERE user_id = ?", session["user_id"]
    )
    member_club_ids = [row["club_id"] for row in membership_rows]

    base_sql = (
        "SELECT a.id, a.title, a.body, a.created_at, a.created_by AS author_id, a.club_id, "
        "u.username AS author, c.name AS club_name "
        "FROM announcements a JOIN users u ON a.created_by = u.id "
        "LEFT JOIN clubs c ON a.club_id = c.id "
    )
    params = []
    if not _is_global_officer():
        if member_club_ids:
            placeholders = ",".join(["?"] * len(member_club_ids))
            base_sql += f"WHERE a.club_id IS NULL OR a.club_id IN ({placeholders}) "
            params.extend(member_club_ids)
        else:
            base_sql += "WHERE a.club_id IS NULL "
    base_sql += "ORDER BY datetime(a.created_at) DESC LIMIT 10"
    announcements = db.execute(base_sql, *params)

    if _is_global_officer():
        upcoming_events = db.execute(
            "SELECT id, title, start_time, location "
            "FROM events "
            "ORDER BY datetime(start_time) ASC "
            "LIMIT 5"
        )
    else:
        upcoming_events = db.execute(
            "SELECT e.id, e.title, e.start_time, e.location "
            "FROM events e JOIN club_membership cm ON cm.club_id = e.club_id AND cm.user_id = ? "
            "ORDER BY datetime(e.start_time) ASC "
            "LIMIT 5",
            session["user_id"],
        )

    return render_template("index.html",
                           announcements=announcements,
                           upcoming_events=upcoming_events)


# DASHBOARD: show current user's stats
@app.route("/dashboard")
@login_required
def dashboard():
    user = db.execute(
        "SELECT id, username, points, is_officer FROM users WHERE id = ?",
        session["user_id"],
    )[0]

    # Membership filter
    memberships = db.execute(
        "SELECT club_id FROM club_membership WHERE user_id = ?",
        user["id"],
    )
    member_club_ids = {row["club_id"] for row in memberships}

    total_attended = 0
    attended_events = []
    if member_club_ids:
        placeholders = ",".join(["?"] * len(member_club_ids))
        total_attended = db.execute(
            f"SELECT COUNT(*) AS c FROM attendance a JOIN events e ON a.event_id = e.id WHERE a.user_id = ? AND e.club_id IN ({placeholders})",
            user["id"],
            *member_club_ids,
        )[0]["c"]

        attended_events = db.execute(
            f"SELECT e.title, e.start_time, e.location "
            f"FROM attendance a JOIN events e ON a.event_id = e.id "
            f"WHERE a.user_id = ? AND e.club_id IN ({placeholders}) "
            f"ORDER BY datetime(e.start_time) DESC "
            f"LIMIT 10",
            user["id"],
            *member_club_ids,
        )

    return render_template(
        "dashboard.html",
        user=user,
        total_attended=total_attended,
        attended_events=attended_events,
    )


# Register
@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        if not username:
            flash("Username is required.", "danger")
            return redirect("/register")

        if not password:
            flash("Password is required.", "danger")
            return redirect("/register")

        if password != confirmation:
            flash("Passwords do not match.", "danger")
            return redirect("/register")

        # Check if username taken
        rows = db.execute("SELECT * FROM users WHERE username = ?", username)

        if len(rows) != 0:
            flash("Username already taken.", "danger")
            return redirect("/register")

        hash_ = generate_password_hash(password)

        db.execute("INSERT INTO users (username, hash) VALUES(?, ?)", username, hash_)

        # Make the very first user an officer by default
        new_user = db.execute("SELECT * FROM users WHERE username = ?", username)[0]
        count = db.execute("SELECT COUNT(*) AS c FROM users")[0]["c"]
        if count == 1:
            db.execute("UPDATE users SET is_officer = 1 WHERE id = ?", new_user["id"])

        # Log user in
        session["user_id"] = new_user["id"]
        session["is_officer"] = new_user.get("is_officer") == 1
        session.permanent = True

        flash("Registered and logging in!", "success")
        return redirect("/")

    else:
        return render_template("register.html")


# Login
@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""
    # Forget any user_id
    session.clear()

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if not username:
            flash("Username is required.", "danger")
            return redirect("/login")

        if not password:
            flash("Password is required.", "danger")
            return redirect("/login")

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", username)

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], password):
            flash("Invalid username and/or password.", "danger")
            return redirect("/login")

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]
        session["is_officer"] = rows[0].get("is_officer") == 1
        session.permanent = True

        flash("Logged in!", "success")
        return redirect("/")

    else:
        return render_template("login.html")


# Logout
@app.route("/logout")
def logout():
    """Log user out"""
    # Forget any user_id
    session.clear()

    flash("Logged out!", "success")
    return redirect("/login")


# Events List
@app.route("/events")
@login_required
def events():
    """Show list of events with search and filter"""
    q = request.args.get("q", "").strip()
    event_type = request.args.get("type", "").strip()
    page = request.args.get("page", 1)
    try:
        page = int(page)
    except Exception:
        page = 1
    if page < 1:
        page = 1
    per_page = 9
    limit = per_page + 1
    offset = (page - 1) * per_page

    sql = (
        "SELECT e.id, e.title, e.description, e.event_type, e.club_id, c.name AS club_name, "
        "       e.start_time, e.end_time, e.location, u.username AS author, "
        "       COUNT(CASE WHEN a.status = 'going' THEN 1 END) AS going_count, "
        "       COUNT(CASE WHEN a.status = 'maybe' THEN 1 END) AS maybe_count, "
        "       (SELECT status FROM attendance WHERE user_id = ? AND event_id = e.id) AS user_status, "
        "       COALESCE(cr.can_manage_events, 0) AS can_manage_events, "
        "       COALESCE(cr.can_manage_attendance, 0) AS can_manage_attendance, "
        "       cr.name AS user_role_name "
        "FROM events e "
        "JOIN users u ON e.created_by = u.id "
        "LEFT JOIN clubs c ON e.club_id = c.id "
        "LEFT JOIN attendance a ON e.id = a.event_id "
        "LEFT JOIN club_membership cm ON cm.club_id = e.club_id AND cm.user_id = ? "
        "LEFT JOIN club_roles cr ON cr.id = cm.role_id "
    )
    params = [session["user_id"], session["user_id"]]

    # Restrict to clubs the user belongs to unless global officer
    if not _is_global_officer():
        sql += "WHERE cm.user_id IS NOT NULL "
    else:
        sql += "WHERE 1=1 "

    if q:
        sql += "AND (e.title LIKE ? OR e.description LIKE ?) "
        params += [f"%{q}%", f"%{q}%"]

    if event_type:
        sql += "AND e.event_type = ? "
        params.append(event_type)

    sql += "GROUP BY e.id ORDER BY datetime(e.start_time) ASC LIMIT ? OFFSET ?"
    params += [limit, offset]

    events_list = db.execute(sql, *params)
    has_next = len(events_list) > per_page
    events_list = events_list[:per_page]
    has_prev = page > 1

    # Get all event types for filter dropdown
    if _is_global_officer():
        all_types = db.execute(
            "SELECT DISTINCT event_type FROM events WHERE event_type IS NOT NULL ORDER BY event_type"
        )
    else:
        all_types = db.execute(
            "SELECT DISTINCT event_type FROM events e JOIN club_membership cm ON cm.club_id = e.club_id AND cm.user_id = ? WHERE event_type IS NOT NULL ORDER BY event_type",
            session["user_id"],
        )
    event_types = [row["event_type"] for row in all_types]

    user_rows = db.execute(
        "SELECT is_officer FROM users WHERE id = ?", session["user_id"]
    )
    
    # If user not found, log them out
    if len(user_rows) == 0:
        session.clear()
        flash("Your session has expired. Please log in again.", "danger")
        return redirect("/login")
    
    user = user_rows[0]
    can_create_events = _is_global_officer() or bool(db.execute(
        "SELECT 1 FROM club_membership cm JOIN club_roles cr ON cm.role_id = cr.id WHERE cm.user_id = ? AND cr.can_manage_events = 1 LIMIT 1",
        session["user_id"],
    ))

    return render_template(
        "events.html",
        events=events_list,
        is_officer=user["is_officer"],
        q=q,
        event_type=event_type,
        event_types=event_types,
        can_create_events=can_create_events,
        page=page,
        has_next=has_next,
        has_prev=has_prev,
    )


# RSVP to Event
@app.route("/events/<int:event_id>/rsvp", methods=["POST"])
@login_required
def rsvp(event_id):
    """RSVP to an event (going or maybe)"""
    # Check if event exists
    event_rows = db.execute("SELECT id, club_id FROM events WHERE id = ?", event_id)
    if len(event_rows) == 0:
        flash("Event not found.", "danger")
        return redirect("/events")
    event = event_rows[0]
    if not (_is_global_officer() or is_club_member(session.get("user_id"), event["club_id"])):
        flash("You must be a member of this club to RSVP.", "danger")
        return redirect("/events")

    status = request.form.get("status", "").strip()

    if status not in ("going", "maybe"):
        flash("Invalid RSVP status.", "danger")
        return redirect("/events")

    db.execute(
        "INSERT OR REPLACE INTO attendance (user_id, event_id, status) VALUES (?, ?, ?)",
        session["user_id"],
        event_id,
        status,
    )

    flash(f"RSVP updated to '{status}'!", "success")
    return redirect("/events")


# Create Event (officers only)
@app.route("/events/new", methods=["GET", "POST"])
@login_required
def new_event():
    """Create a new event"""
    # Clubs current user can create for
    if _is_global_officer():
        allowed_clubs = db.execute("SELECT id, name FROM clubs ORDER BY name")
    else:
        allowed_clubs = db.execute(
            "SELECT c.id, c.name FROM clubs c JOIN club_membership cm ON cm.club_id = c.id JOIN club_roles cr ON cm.role_id = cr.id WHERE cm.user_id = ? AND cr.can_manage_events = 1 ORDER BY c.name",
            session["user_id"],
        )
    if request.method == "GET" and not allowed_clubs:
        flash("You are not an officer for any club to create events.", "danger")
        return redirect("/events")
    if request.method == "POST":
        title = request.form.get("title")
        description = request.form.get("description")
        event_type = request.form.get("event_type")
        start_time = request.form.get("start_time")  # from datetime-local input
        end_time = request.form.get("end_time")
        location = request.form.get("location")
        club_id = request.form.get("club_id")
        # Basic validation
        if not title:
            flash("Title is required.", "danger")
            return redirect("/events/new")
        if not start_time:
            flash("Start Time is required.", "danger")
            return redirect("/events/new")
        if end_time and start_time and end_time < start_time:
            flash("End time cannot be before start time.", "danger")
            return redirect("/events/new")
        if not club_id:
            flash("Club is required for an event.", "danger")
            return redirect("/events/new")
        try:
            club_id_int = int(club_id)
        except ValueError:
            flash("Invalid club.", "danger")
            return redirect("/events/new")
        try:
            require_club_permission(club_id_int, "can_manage_events")
        except Exception:
            flash("You do not have permission to create events for that club.", "danger")
            return redirect("/events")

        try:
            db.execute(
                "INSERT INTO events (title, description, event_type, start_time, end_time, location, created_by, club_id) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                title,
                description,
                event_type,
                start_time,
                end_time,
                location,
                session["user_id"],
                club_id_int,
            )
        except Exception:
            flash("Could not create event.", "danger")
            return redirect("/events/new")

        flash("Event created successfully!", "success")
        return redirect("/events")

        # NOTE: This route design and query were assisted by ChatGPT,
        # then reviewed and adapted manually by me.

    return render_template("new_event.html", clubs=allowed_clubs)


# Edit Event (officers only)
@app.route("/events/<int:event_id>/edit", methods=["GET", "POST"])
@login_required
def edit_event(event_id):
    """Edit an existing event"""
    rows = db.execute("SELECT * FROM events WHERE id = ?", event_id)
    if len(rows) != 1:
        flash("Event not found.", "danger")
        return redirect("/events")

    event = rows[0]
    # Permission check: global or officer for this club
    try:
        require_club_permission(event.get("club_id"), "can_manage_events")
    except Exception:
        flash("You do not have permission to edit this event.", "danger")
        return redirect("/events")
    # Clubs current user can select
    if _is_global_officer():
        allowed_clubs = db.execute("SELECT id, name FROM clubs ORDER BY name")
    else:
        allowed_clubs = db.execute(
            "SELECT c.id, c.name FROM clubs c JOIN club_membership cm ON cm.club_id = c.id JOIN club_roles cr ON cm.role_id = cr.id WHERE cm.user_id = ? AND cr.can_manage_events = 1 ORDER BY c.name",
            session["user_id"],
        )

    if request.method == "POST":
        title = request.form.get("title")
        description = request.form.get("description")
        event_type = request.form.get("event_type")
        start_time = request.form.get("start_time")
        end_time = request.form.get("end_time")
        location = request.form.get("location")
        club_id = request.form.get("club_id")
        if not title:
            flash("Title is required.", "danger")
            return redirect(f"/events/{event_id}/edit")
        if not start_time:
            flash("Start Time is required.", "danger")
            return redirect(f"/events/{event_id}/edit")
        if end_time and start_time and end_time < start_time:
            flash("End time cannot be before start time.", "danger")
            return redirect(f"/events/{event_id}/edit")
        try:
            club_id_int = int(club_id) if club_id else None
        except ValueError:
            flash("Invalid club.", "danger")
            return redirect(f"/events/{event_id}/edit")
        if club_id_int and not (_is_global_officer() or is_club_officer(session.get("user_id"), club_id_int)):
            flash("You do not have permission to edit events for that club.", "danger")
            return redirect("/events")

        try:
            db.execute(
                "UPDATE events SET title = ?, description = ?, event_type = ?, start_time = ?, end_time = ?, location = ?, club_id = ? WHERE id = ?",
                title,
                description,
                event_type,
                start_time,
                end_time,
                location,
                club_id_int,
                event_id,
            )
            flash("Event updated successfully!", "success")
        except Exception:
            flash("Could not update event.", "danger")

        return redirect("/events")

    # GET -> render prefilled form
    return render_template("edit_event.html", event=event, clubs=allowed_clubs)


@app.route("/events/<int:event_id>/delete", methods=["POST"])
@login_required
def delete_event(event_id):
    """Delete an event and related attendance (officers only)"""
    rows = db.execute("SELECT id, club_id FROM events WHERE id = ?", event_id)
    if len(rows) != 1:
        flash("Event not found.", "danger")
        return redirect("/events")
    event = rows[0]
    try:
        require_club_permission(event.get("club_id"), "can_manage_events")
    except Exception:
        flash("You do not have permission to delete this event.", "danger")
        return redirect("/events")

    try:
        # Remove attendance rows first to keep data tidy
        db.execute("DELETE FROM attendance WHERE event_id = ?", event_id)
        db.execute("DELETE FROM events WHERE id = ?", event_id)
        flash("Event deleted.", "success")
    except Exception:
        flash("Could not delete event.", "danger")

    return redirect("/events")


# Manage Attendance (officers only)
@app.route("/events/<int:event_id>/attendance", methods=["GET", "POST"])
@login_required
def manage_attendance(event_id):
    """View and update attendance for an event"""
    # Get event or redirect if not found
    events = db.execute("SELECT * FROM events WHERE id = ?", event_id)
    if len(events) != 1:
        flash("Event not found.", "danger")
        return redirect("/events")

    event = events[0]
    try:
        require_club_permission(event.get("club_id"), "can_manage_attendance")
    except Exception:
        flash("You do not have permission to manage attendance for this event.", "danger")
        return redirect("/events")

    if request.method == "POST":
        # Clear existing attendance for this event
        db.execute("DELETE FROM attendance WHERE event_id = ?", event_id)

        # Get selected users from form
        selected_ids = request.form.getlist("attended")  # list of strings

        for uid in selected_ids:
            db.execute(
                "INSERT INTO attendance (user_id, event_id) VALUES (?, ?)",
                int(uid),
                event_id,
            )

        # Recompute points for all users: 1 point per attendance record
        db.execute("UPDATE users SET points = 0")
        rows = db.execute(
            "SELECT user_id, COUNT(*) AS c FROM attendance GROUP BY user_id"
        )
        for row in rows:
            db.execute(
                "UPDATE users SET points = ? WHERE id = ?",
                row["c"],
                row["user_id"],
            )

        flash("Attendance updated.", "success")
        return redirect("/events")

    # GET: show form with all users and which ones are already marked attended
    users = db.execute(
        "SELECT u.id, u.username FROM users u JOIN club_membership cm ON cm.user_id = u.id WHERE cm.club_id = ? ORDER BY u.username",
        event.get("club_id"),
    )
    attended_rows = db.execute(
        "SELECT user_id FROM attendance WHERE event_id = ?", event_id
    )
    attended_ids = {row["user_id"] for row in attended_rows}

    return render_template(
        "attendance.html",
        event=event,
        users=users,
        attended_ids=attended_ids,
    )


# Announcements List
@app.route("/announcements")
@login_required
def announcements():
    """Show list of announcements"""
    page = request.args.get("page", 1)
    try:
        page = int(page)
    except Exception:
        page = 1
    if page < 1:
        page = 1
    per_page = 10
    limit = per_page + 1
    offset = (page - 1) * per_page

    membership_rows = db.execute("SELECT club_id FROM club_membership WHERE user_id = ?", session["user_id"])
    member_club_ids = [row["club_id"] for row in membership_rows]
    manageable = db.execute(
        "SELECT c.id FROM clubs c "
        "JOIN club_membership cm ON cm.club_id = c.id AND cm.user_id = ? "
        "JOIN club_roles cr ON cr.id = cm.role_id AND cr.can_manage_announcements = 1",
        session["user_id"],
    )
    can_post = _is_global_officer() or len(manageable) > 0
    sql = (
        "SELECT a.id, a.title, a.body, a.created_at, a.created_by AS author_id, a.club_id, "
        "u.username AS author, c.name AS club_name "
        "FROM announcements a JOIN users u ON a.created_by = u.id "
        "LEFT JOIN clubs c ON a.club_id = c.id "
    )
    params = []
    if not _is_global_officer():
        if member_club_ids:
            placeholders = ",".join(["?"] * len(member_club_ids))
            sql += f"WHERE a.club_id IS NULL OR a.club_id IN ({placeholders}) "
            params.extend(member_club_ids)
        else:
            sql += "WHERE a.club_id IS NULL "
    sql += "ORDER BY datetime(a.created_at) DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    announcements = db.execute(sql, *params)
    has_next = len(announcements) > per_page
    announcements = announcements[:per_page]
    has_prev = page > 1
    # annotate permissions
    def _can_edit_ann(row):
        if _is_global_officer():
            return True
        cid = row.get("club_id")
        if cid:
            membership = get_membership(session.get("user_id"), cid)
            return membership and membership.get("can_manage_announcements")
        return False
    for a in announcements:
        a["can_edit"] = _can_edit_ann(a)

    return render_template(
        "announcements.html",
        announcements=announcements,
        page=page,
        has_next=has_next,
        has_prev=has_prev,
        can_post=can_post,
    )


# Clubs list
@app.route("/clubs")
@login_required
def clubs():
    """Show list of clubs"""
    view = request.args.get("view", "all")
    base_sql = (
        "SELECT c.id, c.name, c.description, cr.name AS role_name "
        "FROM clubs c "
        "LEFT JOIN club_membership cm ON cm.club_id = c.id AND cm.user_id = ? "
        "LEFT JOIN club_roles cr ON cr.id = cm.role_id "
    )
    params = [session["user_id"]]
    if view == "mine":
        base_sql += "WHERE cm.user_id IS NOT NULL "
    base_sql += "ORDER BY c.name ASC"
    clubs = db.execute(base_sql, *params)
    return render_template("clubs.html", clubs=clubs, view=view)


# Friendly redirect for singular path
@app.route("/club")
@login_required
def clubs_redirect():
    return redirect("/clubs")


# Create Club (global officer)
@app.route("/clubs/new", methods=["GET", "POST"])
@login_required
@officer_required
def new_club():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        description = request.form.get("description")
        sponsor = request.form.get("sponsor")
        if not name:
            flash("Name is required.", "danger")
            return redirect("/clubs/new")
        try:
            db.execute(
                "INSERT INTO clubs (name, description, sponsor, join_code) VALUES (?, ?, ?, ?)",
                name,
                description,
                sponsor,
                generate_join_code(),
            )
            club_id = db.execute("SELECT id FROM clubs WHERE name = ?", name)[0]["id"]
            roles = ensure_default_roles_for_club(club_id)
            # Assign creator as president
            db.execute(
                "INSERT OR REPLACE INTO club_membership (user_id, club_id, role_id) VALUES (?, ?, ?)",
                session["user_id"],
                club_id,
                roles["president_id"],
            )
            flash("Club created.", "success")
            return redirect("/clubs")
        except Exception:
            flash("Could not create club (maybe duplicate name).", "danger")
            return redirect("/clubs/new")
    return render_template("new_club.html")


# Delete Club (global officer)
@app.route("/clubs/<int:club_id>/delete", methods=["POST"])
@login_required
@officer_required
def delete_club(club_id):
    # Clean up related data
    try:
        event_ids = db.execute("SELECT id FROM events WHERE club_id = ?", club_id)
        for e in event_ids:
            db.execute("DELETE FROM attendance WHERE event_id = ?", e["id"])
        db.execute("DELETE FROM events WHERE club_id = ?", club_id)
        db.execute("DELETE FROM club_membership WHERE club_id = ?", club_id)
        db.execute("DELETE FROM clubs WHERE id = ?", club_id)
        flash("Club deleted.", "success")
    except Exception:
        flash("Could not delete club.", "danger")
    return redirect("/clubs")


# Club detail
@app.route("/clubs/<int:club_id>")
@login_required
def club_detail(club_id):
    rows = db.execute("SELECT * FROM clubs WHERE id = ?", club_id)
    if len(rows) == 0:
        flash("Club not found.", "danger")
        return redirect("/clubs")
    club = rows[0]

    # Get upcoming events for this club only if member or global officer
    events = []
    if _is_global_officer() or is_club_member(session.get("user_id"), club_id):
        try:
            events = db.execute(
                "SELECT id, title, start_time, location FROM events WHERE club_id = ? ORDER BY datetime(start_time) ASC",
                club_id,
            )
        except Exception:
            events = []

    membership = get_membership(session.get("user_id"), club_id)
    is_officer_for_club = _is_global_officer() or (membership and (membership.get("can_manage_events") or membership.get("can_manage_members") or membership.get("can_manage_roles")))
    is_president = (_is_global_officer()) or (membership and membership.get("is_president") == 1)
    is_member = membership is not None
    can_manage_members = _is_global_officer() or (membership and membership.get("can_manage_members"))
    can_manage_roles = _is_global_officer() or (membership and membership.get("can_manage_roles"))
    can_manage_join_code = _is_global_officer() or (membership and membership.get("can_manage_join_code"))
    member_count = db.execute("SELECT COUNT(*) AS c FROM club_membership WHERE club_id = ?", club_id)[0]["c"]
    role_name = membership.get("role_name") if membership else None
    return render_template(
        "club_detail.html",
        club=club,
        events=events,
        is_officer=is_officer_for_club,
        is_president=is_president,
        is_member=is_member,
        can_manage_members=can_manage_members,
        can_manage_roles=can_manage_roles,
        can_manage_join_code=can_manage_join_code,
        member_count=member_count,
        role_name=role_name,
    )


@app.route("/clubs/<int:club_id>/join", methods=["GET", "POST"])
@login_required
def join_club(club_id):
    club_rows = db.execute("SELECT id, name, join_code FROM clubs WHERE id = ?", club_id)
    if len(club_rows) == 0:
        flash("Club not found.", "danger")
        return redirect("/clubs")
    club = club_rows[0]
    if request.method == "POST":
        code = request.form.get("code", "").strip()
        if not code:
            flash("Access code is required.", "danger")
            return redirect(f"/clubs/{club_id}/join")
        if code != club.get("join_code"):
            flash("Invalid access code for this club.", "danger")
            return redirect(f"/clubs/{club_id}/join")
        existing = db.execute(
            "SELECT 1 FROM club_membership WHERE user_id = ? AND club_id = ?",
            session["user_id"],
            club_id,
        )
        if len(existing) > 0:
            flash("You are already a member of this club.", "info")
            return redirect(f"/clubs/{club_id}")
        try:
            default_role = db.execute("SELECT id FROM club_roles WHERE club_id = ? AND is_default_member = 1 LIMIT 1", club_id)
            role_id = default_role[0]["id"] if len(default_role) else None
            if not role_id:
                roles = ensure_default_roles_for_club(club_id)
                role_id = roles["member_id"]
            db.execute(
                "INSERT INTO club_membership (user_id, club_id, role_id) VALUES (?, ?, ?)",
                session["user_id"],
                club_id,
                role_id,
            )
            flash("You joined this club!", "success")
        except Exception:
            flash("Could not join this club.", "danger")
        return redirect(f"/clubs/{club_id}")
    return render_template("join_club.html", club=club)


@app.route("/join", methods=["GET", "POST"])
@login_required
def join_club_by_code():
    if request.method == "POST":
        code = request.form.get("code", "").strip()
        if not code:
            flash("Access code is required.", "danger")
            return redirect("/join")
        club_rows = db.execute("SELECT id FROM clubs WHERE join_code = ?", code)
        if len(club_rows) == 0:
            flash("Invalid access code.", "danger")
            return redirect("/join")
        club_id = club_rows[0]["id"]
        # reuse existing join flow logic
        return join_club(club_id)
    return render_template("join_via_code.html")


@app.route("/officer")
@login_required
@officer_required
def officer_panel():
    clubs = db.execute("SELECT id, name, sponsor FROM clubs ORDER BY name")
    events = db.execute(
        "SELECT e.id, e.title, e.start_time, e.location, c.name AS club_name "
        "FROM events e LEFT JOIN clubs c ON e.club_id = c.id "
        "ORDER BY datetime(e.start_time) DESC "
        "LIMIT 15"
    )
    officers = db.execute(
        "SELECT id, username FROM users WHERE is_officer = 1 ORDER BY username"
    )
    return render_template(
        "officer_panel.html",
        clubs=clubs,
        events=events,
        officers=officers,
    )


# Manage club members (requires permission)
@app.route("/clubs/<int:club_id>/members", methods=["GET", "POST"])
@login_required
def manage_club_members(club_id):
    require_club_permission(club_id, "can_manage_members")

    page_param = request.form.get("page") if request.method == "POST" else request.args.get("page", 1)
    try:
        page = int(page_param)
    except Exception:
        page = 1
    if page < 1:
        page = 1
    per_page = 15
    limit = per_page + 1
    offset = (page - 1) * per_page

    club = db.execute("SELECT * FROM clubs WHERE id = ?", club_id)
    if len(club) == 0:
        flash("Club not found.", "danger")
        return redirect("/clubs")
    club = club[0]
    membership = get_membership(session.get("user_id"), club_id)
    can_manage_join_code = _is_global_officer() or (membership and membership.get("can_manage_join_code"))
    ensure_default_roles_for_club(club_id)

    # POST: add/update membership
    if request.method == "POST":
        uid = request.form.get("user_id")
        role_id = request.form.get("role_id")
        redirect_page = request.form.get("page", page)
        if not uid:
            flash("User is required.", "danger")
            return redirect(f"/clubs/{club_id}/members?page={redirect_page}")
        try:
            role_id_int = int(role_id)
        except Exception:
            flash("Invalid role.", "danger")
            return redirect(f"/clubs/{club_id}/members?page={redirect_page}")
        # Verify role belongs to this club
        role_row = db.execute("SELECT id FROM club_roles WHERE id = ? AND club_id = ?", role_id_int, club_id)
        if len(role_row) == 0:
            flash("Role not found for this club.", "danger")
            return redirect(f"/clubs/{club_id}/members?page={redirect_page}")
        try:
            db.execute(
                "INSERT OR REPLACE INTO club_membership (user_id, club_id, role_id) VALUES (?, ?, ?)",
                int(uid), club_id, role_id_int,
            )
            flash("Membership updated.", "success")
        except Exception:
            flash("Could not update membership.", "danger")
        return redirect(f"/clubs/{club_id}/members?page={redirect_page}")

    # GET: show form and members
    users = db.execute("SELECT id, username FROM users ORDER BY username")
    roles = db.execute("SELECT id, name FROM club_roles WHERE club_id = ? ORDER BY is_president DESC, name", club_id)
    members = db.execute(
        "SELECT cm.user_id, cm.role_id, u.username, cr.name as role_name FROM club_membership cm JOIN users u ON cm.user_id = u.id JOIN club_roles cr ON cm.role_id = cr.id WHERE cm.club_id = ? ORDER BY u.username LIMIT ? OFFSET ?",
        club_id,
        limit,
        offset,
    )
    has_next = len(members) > per_page
    members = members[:per_page]
    has_prev = page > 1

    return render_template(
        "club_members.html",
        club=club,
        users=users,
        members=members,
        roles=roles,
        page=page,
        has_next=has_next,
        has_prev=has_prev,
        can_manage_join_code=can_manage_join_code,
    )


@app.route("/clubs/<int:club_id>/members/remove", methods=["POST"])
@login_required
def remove_club_member(club_id):
    require_club_permission(club_id, "can_manage_members")

    uid = request.form.get("user_id")
    page_raw = request.form.get("page", 1)
    try:
        page = int(page_raw)
    except Exception:
        page = 1
    if page < 1:
        page = 1
    if uid:
        try:
            db.execute("DELETE FROM club_membership WHERE user_id = ? AND club_id = ?", int(uid), club_id)
            flash("Member removed.", "success")
        except Exception:
            flash("Could not remove member.", "danger")

    return redirect(f"/clubs/{club_id}/members?page={page}")


@app.route("/clubs/<int:club_id>/leave", methods=["POST"])
@login_required
def leave_club(club_id):
    membership = get_membership(session.get("user_id"), club_id)
    if not membership:
        flash("You are not a member of this club.", "danger")
        return redirect("/clubs")
    if membership.get("is_president") == 1 and not _is_global_officer():
        flash("Presidents cannot leave the club. Transfer role first.", "danger")
        return redirect(f"/clubs/{club_id}")
    try:
        db.execute("DELETE FROM club_membership WHERE user_id = ? AND club_id = ?", session["user_id"], club_id)
        flash("You left the club.", "success")
    except Exception:
        flash("Could not leave the club.", "danger")
    return redirect("/clubs")


@app.route("/clubs/<int:club_id>/join_code/regenerate", methods=["POST"])
@login_required
def regenerate_join_code(club_id):
    require_club_permission(club_id, "can_manage_join_code")
    club_rows = db.execute("SELECT id FROM clubs WHERE id = ?", club_id)
    if len(club_rows) == 0:
        flash("Club not found.", "danger")
        return redirect("/clubs")
    try:
        new_code = generate_join_code()
        db.execute("UPDATE clubs SET join_code = ? WHERE id = ?", new_code, club_id)
        flash("Join code regenerated.", "success")
    except Exception:
        flash("Could not regenerate join code.", "danger")
    return redirect(f"/clubs/{club_id}/members")


@app.route("/clubs/<int:club_id>/roles", methods=["GET", "POST"])
@login_required
def manage_club_roles(club_id):
    require_club_permission(club_id, "can_manage_roles")
    club_rows = db.execute("SELECT * FROM clubs WHERE id = ?", club_id)
    if len(club_rows) == 0:
        flash("Club not found.", "danger")
        return redirect("/clubs")
    club = club_rows[0]

    def flag(name):
        return 1 if request.form.get(name) else 0

    if request.method == "POST":
        role_id = request.form.get("role_id")
        name = request.form.get("name", "").strip()
        description = request.form.get("description")
        can_manage_members = flag("can_manage_members")
        can_manage_roles = flag("can_manage_roles")
        can_manage_events = flag("can_manage_events")
        can_manage_attendance = flag("can_manage_attendance")
        can_manage_announcements = flag("can_manage_announcements")
        can_manage_join_code = flag("can_manage_join_code")
        can_manage_budget = flag("can_manage_budget")
        is_default_member = flag("is_default_member")
        is_president_flag = flag("is_president")

        if not name:
            flash("Role name is required.", "danger")
            return redirect(f"/clubs/{club_id}/roles")

        if role_id:
            existing = db.execute("SELECT * FROM club_roles WHERE id = ? AND club_id = ?", role_id, club_id)
            if len(existing) == 0:
                flash("Role not found.", "danger")
                return redirect(f"/clubs/{club_id}/roles")
            existing = existing[0]
            if existing.get("is_president") == 1:
                is_president_flag = 1
                can_manage_roles = 1
            try:
                db.execute(
                    "UPDATE club_roles SET name = ?, description = ?, can_manage_members = ?, can_manage_roles = ?, can_manage_events = ?, "
                    "can_manage_attendance = ?, can_manage_announcements = ?, can_manage_join_code = ?, can_manage_budget = ?, "
                    "is_default_member = ?, is_president = ? "
                    "WHERE id = ? AND club_id = ?",
                    name,
                    description,
                    can_manage_members,
                    can_manage_roles,
                    can_manage_events,
                    can_manage_attendance,
                    can_manage_announcements,
                    can_manage_join_code,
                    can_manage_budget,
                    is_default_member,
                    is_president_flag,
                    role_id,
                    club_id,
                )
                count_roles = db.execute("SELECT COUNT(*) AS c FROM club_roles WHERE club_id = ? AND can_manage_roles = 1", club_id)[0]["c"]
                if count_roles == 0:
                    db.execute("UPDATE club_roles SET can_manage_roles = 1 WHERE id = ? AND club_id = ?", role_id, club_id)
                    flash("At least one role must manage roles. Restored permission.", "danger")
                else:
                    flash("Role updated.", "success")
            except Exception:
                flash("Could not update role.", "danger")
        else:
            if is_president_flag:
                can_manage_roles = 1
            try:
                db.execute(
                    "INSERT INTO club_roles (club_id, name, description, can_manage_members, can_manage_roles, can_manage_events, can_manage_attendance, can_manage_announcements, can_manage_join_code, can_manage_budget, is_default_member, is_president) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    club_id,
                    name,
                    description,
                    can_manage_members,
                    can_manage_roles,
                    can_manage_events,
                    can_manage_attendance,
                    can_manage_announcements,
                    can_manage_join_code,
                    can_manage_budget,
                    is_default_member,
                    is_president_flag,
                )
                flash("Role created.", "success")
            except Exception:
                flash("Could not create role.", "danger")
        return redirect(f"/clubs/{club_id}/roles")

    roles = db.execute("SELECT * FROM club_roles WHERE club_id = ? ORDER BY is_president DESC, name", club_id)
    return render_template("club_roles.html", club=club, roles=roles)


# My RSVPs - list events the current user has RSVP'd to
@app.route("/my_rsvps")
@login_required
def my_rsvps():
    """Show events the user has RSVP'd to (going/maybe)"""
    user_id = session.get("user_id")

    rows = db.execute(
        "SELECT e.id, e.title, e.start_time, e.location, a.status "
        "FROM attendance a JOIN events e ON a.event_id = e.id "
        "JOIN club_membership cm ON cm.club_id = e.club_id AND cm.user_id = a.user_id "
        "WHERE a.user_id = ? "
        "GROUP BY e.id "
        "ORDER BY datetime(e.start_time) ASC",
        user_id,
    )

    return render_template("my_rsvps.html", events=rows)


# Create Announcement (officers only)
@app.route("/announcements/new", methods=["GET", "POST"])
@login_required
def new_announcement():
    """Create a new announcement (club-specific or global for admins)"""
    user_id = session["user_id"]
    # clubs where user can manage announcements
    manageable = db.execute(
        "SELECT c.id, c.name FROM clubs c "
        "JOIN club_membership cm ON cm.club_id = c.id AND cm.user_id = ? "
        "JOIN club_roles cr ON cr.id = cm.role_id AND cr.can_manage_announcements = 1 "
        "ORDER BY c.name",
        user_id,
    )
    is_global_admin = _is_global_officer()
    if request.method == "POST":
        title = request.form.get("title")
        body = request.form.get("body")
        club_id_raw = request.form.get("club_id") or ""

        if not title:
            flash("Title is required.", "danger")
            return redirect("/announcements/new")
        if not body:
            flash("Body is required.", "danger")
            return redirect("/announcements/new")

        club_id = None
        if club_id_raw:
            try:
                club_id_int = int(club_id_raw)
            except Exception:
                flash("Invalid club selection.", "danger")
                return redirect("/announcements/new")
            allowed_ids = {row["id"] for row in manageable}
            if club_id_int not in allowed_ids and not is_global_admin:
                abort(403)
            club_id = club_id_int
        else:
            # global announcements only allowed for global officers
            if not is_global_admin:
                flash("Choose a club for your announcement.", "danger")
                return redirect("/announcements/new")

        try:
            db.execute(
                "INSERT INTO announcements (title, body, created_by, club_id) "
                "VALUES (?, ?, ?, ?)",
                title,
                body,
                user_id,
                club_id,
            )
        except Exception:
            flash("Could not create announcement.", "danger")
            return redirect("/announcements/new")

        flash("Announcement created successfully!", "success")
        return redirect("/")

    if not manageable and not is_global_admin:
        flash("You do not have permission to post announcements.", "danger")
        return redirect("/announcements")

    return render_template("new_announcement.html", manageable_clubs=manageable, is_global_admin=is_global_admin, announcement=None, edit_mode=False)


def _announcement_or_404(announcement_id):
    rows = db.execute(
        "SELECT a.*, c.name AS club_name FROM announcements a LEFT JOIN clubs c ON a.club_id = c.id WHERE a.id = ?",
        announcement_id,
    )
    if len(rows) == 0:
        abort(404)
    return rows[0]


def _can_manage_announcement(row):
    if _is_global_officer():
        return True
    cid = row.get("club_id")
    if cid:
        membership = get_membership(session.get("user_id"), cid)
        return membership and membership.get("can_manage_announcements")
    return False


@app.route("/announcements/<int:announcement_id>/edit", methods=["GET", "POST"])
@login_required
def edit_announcement(announcement_id):
    ann = _announcement_or_404(announcement_id)
    if not _can_manage_announcement(ann):
        abort(403)
    user_id = session["user_id"]
    manageable = db.execute(
        "SELECT c.id, c.name FROM clubs c "
        "JOIN club_membership cm ON cm.club_id = c.id AND cm.user_id = ? "
        "JOIN club_roles cr ON cr.id = cm.role_id AND cr.can_manage_announcements = 1 "
        "ORDER BY c.name",
        user_id,
    )
    is_global_admin = _is_global_officer()
    if request.method == "POST":
        title = request.form.get("title")
        body = request.form.get("body")
        club_id_raw = request.form.get("club_id") or ""
        if not title or not body:
            flash("Title and body are required.", "danger")
            return redirect(f"/announcements/{announcement_id}/edit")
        club_id = None
        if club_id_raw:
            try:
                club_id_int = int(club_id_raw)
            except Exception:
                flash("Invalid club selection.", "danger")
                return redirect(f"/announcements/{announcement_id}/edit")
            allowed_ids = {row["id"] for row in manageable}
            if club_id_int not in allowed_ids and not is_global_admin:
                abort(403)
            club_id = club_id_int
        else:
            if not is_global_admin:
                flash("Choose a club for your announcement.", "danger")
                return redirect(f"/announcements/{announcement_id}/edit")
        try:
            db.execute(
                "UPDATE announcements SET title = ?, body = ?, club_id = ? WHERE id = ?",
                title,
                body,
                club_id,
                announcement_id,
            )
            flash("Announcement updated.", "success")
            return redirect("/announcements")
        except Exception:
            flash("Could not update announcement.", "danger")
            return redirect(f"/announcements/{announcement_id}/edit")

    return render_template(
        "new_announcement.html",
        manageable_clubs=manageable,
        is_global_admin=is_global_admin,
        announcement=ann,
        edit_mode=True,
    )


@app.route("/announcements/<int:announcement_id>/delete", methods=["POST"])
@login_required
def delete_announcement(announcement_id):
    ann = _announcement_or_404(announcement_id)
    if not _can_manage_announcement(ann):
        abort(403)
    try:
        db.execute("DELETE FROM announcements WHERE id = ?", announcement_id)
        flash("Announcement deleted.", "success")
    except Exception:
        flash("Could not delete announcement.", "danger")
    return redirect("/announcements")


if __name__ == "__main__":
    app.run(debug=DEBUG_MODE)
# Error handlers
@app.errorhandler(404)
def not_found_error(e):
    return render_template("404.html"), 404


@app.errorhandler(500)
def internal_error(e):
    app.logger.exception("Server error: %s", e)
    return render_template("500.html"), 500
