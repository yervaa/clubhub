# ClubHub – A Web Application for School Clubs
#### Video Demo: https://www.youtube.com/watch?v=rWseNQfRKuk
#### Description:
ClubHub is a web-based platform designed to make school club management easier and more organized. The purpose of the project is to provide a central place where club members and officers can track events, view announcements, manage attendance, earn participation points, and monitor personal involvement through a dedicated dashboard.  

The motivation behind this project was to solve a real problem in many high-school organizations: clubs often lack an organized system for communicating with members and tracking engagement. Most clubs rely on group chats, paper sign-in sheets, or disorganized spreadsheets. ClubHub consolidates all these needs into a single clean, simple, and secure application.

This project was built entirely in Python using the Flask framework, along with SQLite for the database, Jinja templating for the UI, and Bootstrap for styling. The application supports user authentication, role-based permissions (officers vs. members), event creation, attendance tracking, point calculation, announcements, dashboards, and CRUD-style workflows. It is designed to be easily expandable to support additional clubs, features, and future integrations.

---

## Features

### **User Authentication**
Users can register, log in, and log out. Passwords are securely hashed using Werkzeug’s security utilities. Sessions are managed with Flask-Session.

### **Role-Based Permissions**
ClubHub distinguishes between:
- **Officers** – can create events, post announcements, and manage attendance.
- **Members** – can view events, announcements, and their own dashboard.

The first account ever created automatically becomes an officer. All subsequent accounts are members by default.

### **Events System**
Officers can:
- Create new events with title, description, type, time, and location.
- Access an “Attendance Management” page for each event.

Members can:
- View all events sorted by date.
- See upcoming events on the homepage.

### **Attendance Tracking**
Officers can open an event and check off which users attended.  

Upon saving:
- Attendance is stored in the `attendance` table.
- User points are automatically recalculated (1 point per event attended).

### **Announcements**
Officers may post announcements.  
Members can view them in reverse-chronological order on:
- The homepage (`/`)
- The announcements list (`/announcements`)

### **User Dashboard**
Every logged-in user has a dashboard showing:
- Total points earned
- Total events attended
- Recent events attended (last 10)
- Account role status (Officer or Member)

---

## File Structure

clubhub/
│
├── app.py # Main Flask application with all routes and logic
├── clubhub.db # SQLite database file
├── schema.sql # Database schema for tables
│
├── templates/
│ ├── layout.html # Base layout with navbar, Bootstrap, and flash messages
│ ├── index.html # Homepage showing announcements + upcoming events
│ ├── login.html # Login form
│ ├── register.html # Registration form
│ ├── dashboard.html # User stats and event history
│ ├── events.html # Event list + officer attendance controls
│ ├── new_event.html # Event creation form
│ ├── attendance.html # Officer attendance checklist
│ ├── announcements.html # Announcements list
│ ├── new_announcement.html # Officer announcement creation form
│
└── static/
└── css/clubhub.css # Custom styling

---

## Database Design

### **users**
| Column     | Type     | Notes                               |
|------------|----------|-------------------------------------|
| id         | INTEGER  | Primary key                         |
| username   | TEXT     | Unique                              |
| hash       | TEXT     | Hashed password                     |
| is_officer | INTEGER  | 1 = officer, 0 = member             |
| points     | INTEGER  | Automatically updated from attendance |

### **events**
Stores all club events created by officers.

### **announcements**
Stores announcements posted by club officers.

### **attendance**
Tracks which users attended which events.  
Each user-event combination is unique.

---

## How Attendance and Points Work

1. Officer opens event → clicks “Manage Attendance”
2. Officer checks which users attended → submits form
3. Server:
   - Deletes old attendance for that event
   - Inserts new attendance rows
   - Recalculates points for all users:
     ```sql
     points = COUNT(attendance_records)
     ```
4. Dashboard updates automatically

This system ensures:
- No duplicates  
- Easy recalculation  
- Clean relational structure  

---

## Design Decisions

### **Why Flask?**
Flask is lightweight, flexible, and matches the CS50 curriculum. It also pairs well with Jinja templates, allowing a simple full-stack workflow.

### **Why role-based access?**
In real club environments, officers have more responsibilities.  
This feature simulates an actual organizational structure.

### **Why auto-assign the first user as officer?**
Simple solution for deployments with no manual database editing.  
The very first account is always the admin.

### **Why recalculate points on every attendance update?**
Keeps data consistent and avoids stale values if attendance is modified.

### **Why SQLite?**
CS50 Codespace supports SQLite natively and it requires no server setup.

---

## How to Run the App

1. Navigate into the project folder: `cd clubhub`
2. Install deps: `pip install -r requirements.txt`
3. Set env vars (recommended):
   - `export SECRET_KEY="change-me"`
   - `export DATABASE_URL="sqlite:///clubhub.db"` (or your DB string)
   - `export DEBUG=true` (only for local dev)
4. Run the Flask server: `flask run` (or `python app.py`)
5. Open the provided URL in your browser.

## Seed sample data

To load demo users/clubs/events (safe to re-run; uses upsert logic):

```bash
export DATABASE_URL="sqlite:///clubhub.db"
python seed.py
```

Demo users created: `alice_officer` (officer), `bob_student`, `carol_student` — all with password `password123`.

## Database migrations (Alembic)

Use Alembic instead of rerunning `schema.sql` once you have real data:

```bash
pip install -r requirements.txt  # includes alembic
alembic init migrations
```

Then edit `alembic.ini` to point `sqlalchemy.url` at your `DATABASE_URL`, and update `env.py` to use your models/metadata (or reflect). To capture the current schema and apply it:

```bash
alembic revision --autogenerate -m "initial schema"
alembic upgrade head
```

Repeat with a new revision whenever the schema changes; deploys should run `alembic upgrade head`.

---

## Design Decisions

I chose Flask because it is lightweight, easy to control, and closely matches the patterns used in CS50. The decision to auto-assign the first user as an officer removes the need for database editing. Attendance is stored simply using a join table (user_id + event_id), allowing clean counting and recalculating points whenever needed.

I used Bootstrap to ensure the site looks clean without heavy custom CSS. Pages are organized using Jinja templates to avoid repeating layout code.

The app is intentionally structured so new features (such as resource uploads, multiple clubs, analytics, or RSVP features) could be added later.

---

## AI Assistance Statement (Required)

Some parts of this project (such as structuring routes, designing templates, and debugging) were assisted by ChatGPT. All generated code was reviewed, modified, and integrated manually by me. Comments inside `app.py` also mark where AI assistance occurred.

---

## Future Improvements

If I had more time, I would add:
- File/resource upload system  
- Multiple clubs support  
- Event RSVP  
- Messaging or notification system  
- Officer dashboards with graphs and charts  

---

## Features

### 1. Event RSVP System

Users can RSVP to events with **“I’m going”** or **“Maybe”** and update their choice at any time.

**What it does**

- Allows each user to RSVP per event with a status of `going` or `maybe`
- Displays real-time RSVP counts on each event card
- Changes button appearance based on the user’s current RSVP status
- Stores RSVPs centrally in the database so officers can see engagement

**How it’s implemented**

- `attendance` table now includes a `status` field
- `POST /events/<event_id>/rsvp` route in `app.py` handles creating/updating RSVPs
- `events()` route aggregates RSVP counts with SQL (e.g., `COUNT(CASE WHEN status = 'going' THEN 1 END)`)
- `events.html` template shows RSVP statistics and interactive buttons

---

### 2. Search and Filter for Events

The Events page now supports searching and filtering so members can quickly find what they need.

**What it does**

- Full-text search by event title and description via a query box
- Filter by event type (e.g., Meeting, Practice, Fundraiser)
- Event types in the dropdown are pulled dynamically from the database
- Active filters are reflected in the UI with a “Clear filters” option

**How it’s implemented**

- `events()` route reads query parameters `q` (search) and `type` (filter)
- Builds the SQL `WHERE` clause conditionally based on those parameters
- Fetches distinct `event_type` values from the database for the filter dropdown
- `events.html` uses a search card with an input and `<select>` for filtering

---

### 3. Improved Events UI

The Events page has been redesigned to be more usable and mobile-friendly.

**What it includes**

- Responsive card-based layout for events
- Search/filter card at the top of the page
- On each event card:
  - Title, type, description
  - Date/time and location
  - Created-by username
  - RSVP statistics (Going / Maybe)
  - RSVP buttons with visual feedback
- Officers see an additional “Manage Attendance” button for check-ins


# End of README
