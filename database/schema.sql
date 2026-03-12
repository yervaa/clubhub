-- ClubHub schema for SQLite/Postgres
-- Run this to create a fresh database schema.

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    hash TEXT NOT NULL,
    is_officer INTEGER NOT NULL DEFAULT 0,
    points INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS clubs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    description TEXT,
    sponsor TEXT,
    join_code TEXT
);

CREATE TABLE IF NOT EXISTS club_roles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    club_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    can_manage_members INTEGER NOT NULL DEFAULT 0,
    can_manage_roles INTEGER NOT NULL DEFAULT 0,
    can_manage_events INTEGER NOT NULL DEFAULT 0,
    can_manage_attendance INTEGER NOT NULL DEFAULT 0,
    can_manage_announcements INTEGER NOT NULL DEFAULT 0,
    can_manage_join_code INTEGER NOT NULL DEFAULT 0,
    can_manage_budget INTEGER NOT NULL DEFAULT 0,
    is_default_member INTEGER NOT NULL DEFAULT 0,
    is_president INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (club_id) REFERENCES clubs(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_club_roles_club_id ON club_roles(club_id);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    description TEXT,
    event_type TEXT,
    start_time TEXT NOT NULL,
    end_time TEXT,
    location TEXT,
    created_by INTEGER NOT NULL,
    club_id INTEGER,
    FOREIGN KEY (created_by) REFERENCES users(id),
    FOREIGN KEY (club_id) REFERENCES clubs(id)
);
CREATE INDEX IF NOT EXISTS idx_events_start_time ON events(start_time);
CREATE INDEX IF NOT EXISTS idx_events_club_id ON events(club_id);

CREATE TABLE IF NOT EXISTS announcements (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    body TEXT NOT NULL,
    created_by INTEGER NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    club_id INTEGER,
    FOREIGN KEY (created_by) REFERENCES users(id),
    FOREIGN KEY (club_id) REFERENCES clubs(id)
);
CREATE INDEX IF NOT EXISTS idx_announcements_created ON announcements(created_at);

CREATE TABLE IF NOT EXISTS attendance (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    event_id INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'going' CHECK (status IN ('going', 'maybe', 'not_going')),
    checked_in_at TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (event_id) REFERENCES events(id) ON DELETE CASCADE,
    UNIQUE (user_id, event_id)
);
CREATE INDEX IF NOT EXISTS idx_attendance_event_id ON attendance(event_id);
CREATE INDEX IF NOT EXISTS idx_attendance_user_id ON attendance(user_id);

CREATE TABLE IF NOT EXISTS club_membership (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    club_id INTEGER NOT NULL,
    role_id INTEGER NOT NULL,
    UNIQUE (user_id, club_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (club_id) REFERENCES clubs(id) ON DELETE CASCADE,
    FOREIGN KEY (role_id) REFERENCES club_roles(id)
);
