"""
Seed script to load sample users, clubs, events, and memberships for demos.

Usage:
  export DATABASE_URL="sqlite:///clubhub.db"  # or your DB string
  python seed.py
"""

import os
from datetime import datetime, timedelta

from cs50 import SQL
from werkzeug.security import generate_password_hash
import secrets


DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///clubhub.db")
db = SQL(DATABASE_URL)


def generate_join_code():
    return secrets.token_urlsafe(6)


def get_or_create_user(username, password, is_officer=False):
    rows = db.execute("SELECT id FROM users WHERE username = ?", username)
    if rows:
        # Keep existing officer flag if already set
        if is_officer and rows[0].get("id"):
            db.execute("UPDATE users SET is_officer = 1 WHERE id = ?", rows[0]["id"])
        return rows[0]["id"]

    hash_ = generate_password_hash(password)
    db.execute(
        "INSERT INTO users (username, hash, is_officer) VALUES (?, ?, ?)",
        username,
        hash_,
        1 if is_officer else 0,
    )
    return db.execute("SELECT id FROM users WHERE username = ?", username)[0]["id"]


def get_or_create_club(name, description, sponsor=None):
    rows = db.execute("SELECT id FROM clubs WHERE name = ?", name)
    if rows:
        return rows[0]["id"]

    db.execute(
        "INSERT INTO clubs (name, description, sponsor, join_code) VALUES (?, ?, ?, ?)",
        name,
        description,
        sponsor,
        generate_join_code(),
    )
    return db.execute("SELECT id FROM clubs WHERE name = ?", name)[0]["id"]


def ensure_default_roles(club_id):
    roles = db.execute("SELECT id, name, is_president, is_default_member FROM club_roles WHERE club_id = ?", club_id)
    president_id = next((r["id"] for r in roles if r["is_president"] == 1), None)
    member_id = next((r["id"] for r in roles if r["is_default_member"] == 1), None)
    officer_id = next((r["id"] for r in roles if r["name"] == "Officer"), None)
    if not president_id:
        db.execute(
            "INSERT INTO club_roles (club_id, name, description, can_manage_members, can_manage_roles, can_manage_events, can_manage_attendance, can_manage_announcements, can_manage_join_code, can_manage_budget, is_president) "
            "VALUES (?, 'President', 'Leads the club', 1, 1, 1, 1, 1, 1, 1, 1)",
            club_id,
        )
        president_id = db.execute("SELECT id FROM club_roles WHERE club_id = ? AND is_president = 1 ORDER BY id DESC LIMIT 1", club_id)[0]["id"]
    if not member_id:
        db.execute(
            "INSERT INTO club_roles (club_id, name, description, is_default_member) VALUES (?, 'Member', 'Default club member', 1)",
            club_id,
        )
        member_id = db.execute("SELECT id FROM club_roles WHERE club_id = ? AND is_default_member = 1 ORDER BY id DESC LIMIT 1", club_id)[0]["id"]
    if not officer_id:
        db.execute(
            "INSERT INTO club_roles (club_id, name, description, can_manage_events, can_manage_attendance, can_manage_announcements) VALUES (?, 'Officer', 'Supports club operations', 1, 1, 1)",
            club_id,
        )
        officer_id = db.execute("SELECT id FROM club_roles WHERE club_id = ? AND name = 'Officer' ORDER BY id DESC LIMIT 1", club_id)[0]["id"]
    return {"president_id": president_id, "member_id": member_id, "officer_id": officer_id}


def get_or_create_event(title, start_time, created_by, club_id=None, **kwargs):
    rows = db.execute(
        "SELECT id FROM events WHERE title = ? AND start_time = ?",
        title,
        start_time,
    )
    if rows:
        return rows[0]["id"]

    db.execute(
        "INSERT INTO events (title, description, event_type, start_time, end_time, location, created_by, club_id) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        title,
        kwargs.get("description"),
        kwargs.get("event_type"),
        start_time,
        kwargs.get("end_time"),
        kwargs.get("location"),
        created_by,
        club_id,
    )
    return db.execute(
        "SELECT id FROM events WHERE title = ? AND start_time = ?", title, start_time
    )[0]["id"]


def ensure_membership(user_id, club_id, role="member"):
    roles = ensure_default_roles(club_id)
    role = (role or "member").lower()
    role_id = roles["member_id"]
    if role == "president":
        role_id = roles["president_id"]
    elif role == "officer":
        role_id = roles["officer_id"]
    db.execute(
        "INSERT OR REPLACE INTO club_membership (user_id, club_id, role_id) VALUES (?, ?, ?)",
        user_id,
        club_id,
        role_id,
    )


def ensure_rsvp(user_id, event_id, status="going"):
    db.execute(
        "INSERT OR REPLACE INTO attendance (user_id, event_id, status) VALUES (?, ?, ?)",
        user_id,
        event_id,
        status,
    )


def main():
    # Users
    alice_id = get_or_create_user("alice_officer", "password123", is_officer=True)
    bob_id = get_or_create_user("bob_student", "password123", is_officer=False)
    carol_id = get_or_create_user("carol_student", "password123", is_officer=False)

    # Clubs
    robotics_id = get_or_create_club(
        "Robotics Club",
        "Build and compete with robots.",
        sponsor="Ms. Chen",
    )
    math_id = get_or_create_club(
        "Math Club",
        "Weekly problem-solving and competitions.",
        sponsor="Mr. Patel",
    )
    art_id = get_or_create_club(
        "Art Society",
        "Sketching, painting, and gallery visits.",
        sponsor="Ms. Lopez",
    )

    # Memberships (officer for robotics, students for others)
    ensure_membership(alice_id, robotics_id, role="officer")
    ensure_membership(bob_id, robotics_id, role="student")
    ensure_membership(carol_id, math_id, role="student")

    # Events (dates are future-dated relative to now)
    now = datetime.utcnow()
    events_data = [
        {
            "title": "Robotics Kickoff",
            "description": "Season overview and team assignments.",
            "event_type": "Meeting",
            "start_time": (now + timedelta(days=3)).strftime("%Y-%m-%dT%H:%M"),
            "end_time": (now + timedelta(days=3, hours=2)).strftime("%Y-%m-%dT%H:%M"),
            "location": "Lab 201",
            "club_id": robotics_id,
        },
        {
            "title": "Math Contest Practice",
            "description": "Prepare for AMC/ARML style problems.",
            "event_type": "Practice",
            "start_time": (now + timedelta(days=5)).strftime("%Y-%m-%dT%H:%M"),
            "end_time": (now + timedelta(days=5, hours=1)).strftime("%Y-%m-%dT%H:%M"),
            "location": "Room 104",
            "club_id": math_id,
        },
        {
            "title": "Art Museum Visit",
            "description": "Field trip to the downtown art museum.",
            "event_type": "Outing",
            "start_time": (now + timedelta(days=10)).strftime("%Y-%m-%dT%H:%M"),
            "end_time": (now + timedelta(days=10, hours=3)).strftime("%Y-%m-%dT%H:%M"),
            "location": "Meet at main entrance",
            "club_id": art_id,
        },
    ]

    event_ids = []
    for data in events_data:
        eid = get_or_create_event(
            data["title"],
            data["start_time"],
            created_by=alice_id,
            club_id=data["club_id"],
            description=data["description"],
            event_type=data["event_type"],
            end_time=data["end_time"],
            location=data["location"],
        )
        event_ids.append(eid)

    # Sample RSVPs
    for eid in event_ids:
        ensure_rsvp(bob_id, eid, status="going")
        ensure_rsvp(carol_id, eid, status="maybe")

    print("Seed complete:")
    print(f"  Users: {alice_id}, {bob_id}, {carol_id}")
    print(f"  Clubs: {robotics_id}, {math_id}, {art_id}")
    print(f"  Events: {event_ids}")
    print("Sample passwords: password123")


if __name__ == "__main__":
    main()
