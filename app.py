import os
from datetime import datetime

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from functools import wraps

# Configure application
app = Flask(__name__)

# Configure Flask settings
app.config.update(
    TEMPLATES_AUTO_RELOAD=True,
    SESSION_PERMANENT=False,
    SESSION_TYPE="filesystem",
)
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///clubhub.db")


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
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function


def officer_required(f):
    """
    Decorate routes to require officer permissions.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_id = session.get("user_id")
        if user_id is None:
            return redirect("/login")
        rows = db.execute("SELECT is_officer FROM users WHERE id = ?", user_id)
        if len(rows) != 1 or rows[0]["is_officer"] == 0:
            flash("You do not have permission to access that page.", "danger")
            return redirect("/")
        return f(*args, **kwargs)
    return decorated_function


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# INDEX: show announcements + upcoming events
@app.route("/")
@login_required
def index():
    announcements = db.execute(
        "SELECT a.id, a.title, a.body, a.created_at, u.username AS author "
        "FROM announcements a JOIN users u ON a.created_by = u.id "
        "ORDER BY datetime(a.created_at) DESC"
    )

    upcoming_events = db.execute(
        "SELECT id, title, start_time, location "
        "FROM events "
        "ORDER BY datetime(start_time) ASC "
        "LIMIT 5"
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

    total_attended = db.execute(
        "SELECT COUNT(*) AS c FROM attendance WHERE user_id = ?",
        user["id"],
    )[0]["c"]

    attended_events = db.execute(
        "SELECT e.title, e.start_time, e.location "
        "FROM attendance a JOIN events e ON a.event_id = e.id "
        "WHERE a.user_id = ? "
        "ORDER BY datetime(e.start_time) DESC "
        "LIMIT 10",
        user["id"],
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

    sql = (
        "SELECT e.id, e.title, e.description, e.event_type, "
        "       e.start_time, e.end_time, e.location, u.username AS author, "
        "       COUNT(CASE WHEN a.status = 'going' THEN 1 END) AS going_count, "
        "       COUNT(CASE WHEN a.status = 'maybe' THEN 1 END) AS maybe_count, "
        "       (SELECT status FROM attendance WHERE user_id = ? AND event_id = e.id) AS user_status "
        "FROM events e "
        "JOIN users u ON e.created_by = u.id "
        "LEFT JOIN attendance a ON e.id = a.event_id "
        "WHERE 1=1 "
    )
    params = [session["user_id"]]

    if q:
        sql += "AND (e.title LIKE ? OR e.description LIKE ?) "
        params += [f"%{q}%", f"%{q}%"]

    if event_type:
        sql += "AND e.event_type = ? "
        params.append(event_type)

    sql += "GROUP BY e.id ORDER BY datetime(e.start_time) ASC"

    events_list = db.execute(sql, *params)

    # Get all event types for filter dropdown
    all_types = db.execute(
        "SELECT DISTINCT event_type FROM events WHERE event_type IS NOT NULL ORDER BY event_type"
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

    return render_template(
        "events.html",
        events=events_list,
        is_officer=user["is_officer"],
        q=q,
        event_type=event_type,
        event_types=event_types,
    )


# RSVP to Event
@app.route("/events/<int:event_id>/rsvp", methods=["POST"])
@login_required
def rsvp(event_id):
    """RSVP to an event (going or maybe)"""
    # Check if event exists
    event_rows = db.execute("SELECT id FROM events WHERE id = ?", event_id)
    if len(event_rows) == 0:
        flash("Event not found.", "danger")
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
@officer_required
def new_event():
    """Create a new event"""
    if request.method == "POST":
        title = request.form.get("title")
        description = request.form.get("description")
        event_type = request.form.get("event_type")
        start_time = request.form.get("start_time")  # from datetime-local input
        end_time = request.form.get("end_time")
        location = request.form.get("location")

        if not title or not start_time:
            flash("Title and Start Time are required.", "danger")
            return redirect("/events/new")

        db.execute(
            "INSERT INTO events (title, description, event_type, start_time, end_time, location, created_by) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            title,
            description,
            event_type,
            start_time,
            end_time,
            location,
            session["user_id"]
        )

        flash("Event created successfully!", "success")
        return redirect("/events")

        # NOTE: This route design and query were assisted by ChatGPT,
        # then reviewed and adapted manually by me.

    return render_template("new_event.html")


# Manage Attendance (officers only)
@app.route("/events/<int:event_id>/attendance", methods=["GET", "POST"])
@login_required
@officer_required
def manage_attendance(event_id):
    """View and update attendance for an event"""
    # Get event or redirect if not found
    events = db.execute("SELECT * FROM events WHERE id = ?", event_id)
    if len(events) != 1:
        flash("Event not found.", "danger")
        return redirect("/events")

    event = events[0]

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
    users = db.execute("SELECT id, username FROM users ORDER BY username")
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
    announcements = db.execute(
        "SELECT a.id, a.title, a.body, a.created_at, u.username AS author "
        "FROM announcements a JOIN users u ON a.created_by = u.id "
        "ORDER BY datetime(a.created_at) DESC"
    )

    return render_template("announcements.html", announcements=announcements)


# Create Announcement (officers only)
@app.route("/announcements/new", methods=["GET", "POST"])
@login_required
@officer_required
def new_announcement():
    """Create a new announcement"""
    if request.method == "POST":
        title = request.form.get("title")
        body = request.form.get("body")

        if not title or not body:
            flash("Title and Body are required.", "danger")
            return redirect("/announcements/new")

        db.execute(
            "INSERT INTO announcements (title, body, created_by) "
            "VALUES (?, ?, ?)",
            title,
            body,
            session["user_id"]
        )

        flash("Announcement created successfully!", "success")
        return redirect("/")

        # NOTE: This route design and query were assisted by ChatGPT,
        # then reviewed, modified, and adapted manually by me.

    return render_template("new_announcement.html")


if __name__ == "__main__":
    app.run(debug=True)
