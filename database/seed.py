"""
Seed script to load sample users, clubs, roles, memberships, events, and announcements.

Usage:
  export DATABASE_URL="sqlite:///clubhub.db"  # or your Postgres URL
  python database/seed.py
"""

import os
import secrets
from datetime import datetime, timedelta

from cs50 import SQL
from werkzeug.security import generate_password_hash


def normalize_db_url(url: str) -> str:
    if url and url.startswith("postgres://"):
        return url.replace("postgres://", "postgresql://", 1)
    return url


DATABASE_URL = normalize_db_url(os.getenv("DATABASE_URL", "sqlite:///clubhub.db"))
db = SQL(DATABASE_URL)


def generate_join_code():
    return secrets.token_urlsafe(6)


def upsert_user(username: str, password: str, is_officer: bool = False):
    db.execute(
        "INSERT INTO users (username, hash, is_officer) VALUES (?, ?, ?) "
        "ON CONFLICT(username) DO UPDATE SET hash = excluded.hash, is_officer = CASE WHEN users.is_officer = 1 THEN 1 ELSE excluded.is_officer END",
        username,
        generate_password_hash(password),
        1 if is_officer else 0,
    )
    return db.execute("SELECT id FROM users WHERE username = ?", username)[0]["id"]


def upsert_club(name: str, description: str, sponsor: str | None, join_code: str):
    db.execute(
        "INSERT INTO clubs (name, description, sponsor, join_code) VALUES (?, ?, ?, ?) "
        "ON CONFLICT(name) DO UPDATE SET description = excluded.description, sponsor = excluded.sponsor, join_code = excluded.join_code",
        name,
        description,
        sponsor,
        join_code,
    )
    return db.execute("SELECT id FROM clubs WHERE name = ?", name)[0]["id"]


def ensure_roles(club_id: int):
    roles = db.execute("SELECT id, name, is_president, is_default_member FROM club_roles WHERE club_id = ?", club_id)
    ids = {r["name"]: r["id"] for r in roles}
    president_id = next((r["id"] for r in roles if r["is_president"] == 1), None)
    member_id = next((r["id"] for r in roles if r["is_default_member"] == 1), None)
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
    officer_id = ids.get("Officer")
    if not officer_id:
        db.execute(
            "INSERT INTO club_roles (club_id, name, description, can_manage_events, can_manage_attendance, can_manage_announcements) VALUES (?, 'Officer', 'Supports club operations', 1, 1, 1)",
            club_id,
        )
        officer_id = db.execute("SELECT id FROM club_roles WHERE club_id = ? AND name = 'Officer' ORDER BY id DESC LIMIT 1", club_id)[0]["id"]
    return {"president_id": president_id, "member_id": member_id, "officer_id": officer_id}


def set_membership(user_id: int, club_id: int, role: str):
    roles = ensure_roles(club_id)
    role_lower = (role or "member").lower()
    role_id = roles["member_id"]
    if role_lower == "president":
        role_id = roles["president_id"]
    elif role_lower == "officer":
        role_id = roles["officer_id"]
    db.execute(
        "INSERT INTO club_membership (user_id, club_id, role_id) VALUES (?, ?, ?) "
        "ON CONFLICT(user_id, club_id) DO UPDATE SET role_id = excluded.role_id",
        user_id,
        club_id,
        role_id,
    )


def upsert_event(title: str, start: str, created_by: int, club_id: int, **kwargs):
    row = db.execute("SELECT id FROM events WHERE title = ? AND start_time = ?", title, start)
    if row:
        return row[0]["id"]
    db.execute(
        "INSERT INTO events (title, description, event_type, start_time, end_time, location, created_by, club_id) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        title,
        kwargs.get("description"),
        kwargs.get("event_type"),
        start,
        kwargs.get("end_time"),
        kwargs.get("location"),
        created_by,
        club_id,
    )
    return db.execute("SELECT id FROM events WHERE title = ? AND start_time = ?", title, start)[0]["id"]


def ensure_rsvp(user_id: int, event_id: int, status: str = "going"):
    db.execute(
        "INSERT INTO attendance (user_id, event_id, status) VALUES (?, ?, ?) "
        "ON CONFLICT(user_id, event_id) DO UPDATE SET status = excluded.status",
        user_id,
        event_id,
        status,
    )


def main():
    # Users (demo creds: admin/admin, pres/pres, off/off, mem/mem, student/student)
    admin_id = upsert_user("admin", "admin", is_officer=True)
    pres_id = upsert_user("pres", "pres", is_officer=False)
    off_id = upsert_user("off", "off", is_officer=False)
    mem_id = upsert_user("mem", "mem", is_officer=False)
    student_id = upsert_user("student", "student", is_officer=False)

    # Clubs with fixed join codes for testing
    robotics_id = upsert_club("Robotics", "Build and compete with robots.", "Ms. Chen", "robot1")
    chess_id = upsert_club("Chess", "Casual and competitive chess.", "Mr. Patel", "chess1")
    art_id = upsert_club("Art", "Drawing and gallery visits.", "Ms. Lopez", "art1")

    # Roles and memberships
    set_membership(admin_id, robotics_id, "president")
    set_membership(admin_id, chess_id, "officer")
    set_membership(admin_id, art_id, "member")

    set_membership(pres_id, chess_id, "president")
    set_membership(off_id, robotics_id, "officer")
    set_membership(mem_id, robotics_id, "member")
    set_membership(student_id, robotics_id, "member")

    # Events
    now = datetime.utcnow()
    events = [
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
            "title": "Chess Ladder Night",
            "description": "Match play to climb the ladder.",
            "event_type": "Tournament",
            "start_time": (now + timedelta(days=5)).strftime("%Y-%m-%dT%H:%M"),
            "end_time": (now + timedelta(days=5, hours=2)).strftime("%Y-%m-%dT%H:%M"),
            "location": "Room 104",
            "club_id": chess_id,
        },
        {
            "title": "Art Gallery Visit",
            "description": "Field trip to the downtown gallery.",
            "event_type": "Outing",
            "start_time": (now + timedelta(days=8)).strftime("%Y-%m-%dT%H:%M"),
            "end_time": (now + timedelta(days=8, hours=3)).strftime("%Y-%m-%dT%H:%M"),
            "location": "Meet at main entrance",
            "club_id": art_id,
        },
    ]
    event_ids = []
    for data in events:
        eid = upsert_event(
            data["title"],
            data["start_time"],
            created_by=admin_id,
            club_id=data["club_id"],
            description=data["description"],
            event_type=data["event_type"],
            end_time=data["end_time"],
            location=data["location"],
        )
        event_ids.append(eid)

    # RSVPs
    for eid in event_ids:
        ensure_rsvp(off_id, eid, "going")
        ensure_rsvp(mem_id, eid, "maybe")
        ensure_rsvp(student_id, eid, "maybe")

    # Announcements
    db.execute(
        "INSERT INTO announcements (title, body, created_by, club_id) VALUES (?, ?, ?, ?) "
        "ON CONFLICT DO NOTHING",
        "Welcome to ClubHub",
        "This is your new dashboard for clubs, events, and announcements.",
        admin_id,
        None,
    )

    print("Seed complete.")
    print("Demo accounts:")
    print("  admin / admin (global admin + Robotics President, Chess Officer, Art Member)")
    print("  pres / pres (Chess President)")
    print("  off / off (Robotics Officer)")
    print("  mem / mem (Robotics Member)")
    print("  student / student (no clubs by default)")
    print("Join codes: Robotics robot1, Chess chess1, Art art1")


if __name__ == "__main__":
    main()
