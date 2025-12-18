# Less Wild West Forum 
**Author:** Sany Dagher  
**Course:** COS 498 – Serverside Web Development  
**Semester:** Fall 2025

A web forum built with Node.js, Express, Handlebars, SQLite, and Socket.IO.
Deployed behind Nginx Proxy Manager with HTTPS (Let’s Encrypt).

## Live / Dev URLs
- Local/dev (direct Express): http://159.203.109.52:3000
- Live (behind Nginx Proxy Manager + HTTPS):
  - https://final.zombo3.store
  - https://www.final.zombo3.store

## Setup Instructions

### 1) Clone & Install
```bash
git clone https://github.com/Zombo3/insecure-forum.git
cd insecure-forum/server
npm install
```
###2) Run (Development)
```
node server.js
```
###3) Run (Production / Always-On)
The forum runs as a persistent Node.js process using PM2.
```
pm2 start server.js --name less-wild-west-forum
pm2 save
pm2 status
```

## Features Overview

### Authentication / Accounts
- User registration with **unique email** and **unique display name**
- Password hashing with **Argon2**
- Login lockout: **5 failed attempts → 15 minute lock**
- Logout deletes the session from the database
- Password recovery via email (token-based reset)

### Profile
- Update display name (also updates author display name on old comments)
- Update email
- Change password
- Customization fields (name color, avatar, bio)

### Comments
- Paginated comments (`/comments?page=N`) with limited results per page
- Edit own comment (ownership enforced)
- Delete own comment (ownership enforced)
- Comment likes/upvotes (one per user, stored in DB, count shown)

### Real-time Chat
- Socket.IO real-time chat integrated into the same Express server
- Authenticated via DB-backed session cookie during socket handshake
- Messages stored in SQLite (`chat_messages`) with timestamps and room_id
- Chat history sent on connect

## Security Features Implemented

- **Argon2 password hashing** for all stored user passwords
- **Unique email and display name enforcement**
- **Login lockout protection**
  - 5 consecutive failed login attempts
  - Account locked for 15 minutes
- **DB-backed sessions**
  - Session ID stored in a secure cookie
  - Session data stored server-side in SQLite
- **Session invalidation on logout**
  - Logout deletes the session record from the database
- **Authorization enforcement**
  - Users may only edit or delete their own comments
  - Comment likes are limited to one per user
- **Socket.IO authentication**
  - Socket connections are authenticated using the existing session cookie
  - Unauthorized users cannot send or receive chat messages

---



## Project Structure

```text
insecure-forum/
├── README.md
├── docker-compose.yml
├── nginx/
│   ├── Dockerfile
│   └── default.conf
├── static/
│   ├── css/
│   │   └── main.css
│   └── img/
│       └── zombo3.png
└── server/
    ├── Dockerfile
    ├── package.json
    ├── package-lock.json
    ├── server.js
    ├── sessionStore.js
    ├── public/
    │   └── css/
    │       └── styles.css
    ├── db/
    │   ├── forum.sqlite
    │   ├── schema.sql
    │   └── db.js
    └── views/
        ├── layouts/
        │   └── main.hbs
        ├── partials/
        │   ├── nav.hbs
        │   └── footer.hbs
        ├── home.hbs
        ├── comments.hbs
        ├── new-comment.hbs
        ├── edit-comment.hbs
        ├── login.hbs
        ├── register.hbs
        └── profile.hbs
```

## Routes

| Method | Path | Description |
| ------ | ---- | ----------- |
| GET | `/` | Home page (includes real-time chat UI) |
| GET | `/register` | Registration page |
| POST | `/register` | Create new user account |
| GET | `/login` | Login page |
| POST | `/login` | Authenticate user (lockout after repeated failures) |
| POST | `/logout` | Logout (deletes DB-backed session) |

### Profile (auth required)
| Method | Path | Description |
| ------ | ---- | ----------- |
| GET | `/profile` | View your profile |
| POST | `/profile/display-name` | Change display name (also updates old comments’ display_name) |
| POST | `/profile/customize` | Update customization (name_color, avatar, bio) |
| POST | `/profile/email` | Change email (requires current password, must be unique) |
| POST | `/profile/password` | Change password (requires current password; deletes DB sessions) |

### Comments
| Method | Path | Description |
| ------ | ---- | ----------- |
| GET | `/comments?page=N` | Paginated comment history (newest first) |
| GET | `/comment/new` | New comment form (login required) |
| POST | `/comment` | Create a new comment (login required) |
| GET | `/comment/:id/edit` | Edit comment form (owner only) |
| POST | `/comment/:id/edit` | Save edited comment (owner only) |
| POST | `/comment/:id/delete` | Delete comment (owner only) |
| POST | `/comment/:id/like` | Toggle like/upvote (login required; returns JSON) |

### Chat API (auth required)
| Method | Path | Description |
| ------ | ---- | ----------- |
| GET | `/api/chat/history` | Retrieve recent chat history (JSON) |
| POST | `/api/chat/send` | Send a chat message (JSON; also broadcasts via Socket.IO) |

### Chat API Details (JSON)

All chat API endpoints require the user to be logged in.

#### POST `/api/chat/send`
Sends a new chat message and broadcasts it via Socket.IO.

**Request Body**
```json
{
  "message": "Hello everyone",
  "room_id": 1
}
```
Response (200)
```
{ "ok": true }
```
Errors
401 Unauthorized if not logged in
400 Bad Request if message is missing or empty

## Environment Variables & Configuration

This project does **not** require a `.env` file.

### Configuration Details
- The Express application listens on port **3000**
- Nginx Proxy Manager forwards HTTPS traffic to this port
- SQLite is used for persistent storage:
  - Database file: `server/db/forum.sqlite`

### Notes
- All configuration is defined directly in `server.js`
- No external services or environment variables are required to run the application


## Nginx Proxy Manager Setup (HTTPS)

This application is deployed behind **Nginx Proxy Manager (NPM)** with **Let’s Encrypt** SSL.

### Proxy Host Configuration
Create a new Proxy Host in Nginx Proxy Manager with the following settings:

- **Domain Names**
  - `final.zombo3.store`
  - `www.final.zombo3.store`
- **Scheme:** `http`
- **Forward Hostname / IP:** `159.203.109.52`
- **Forward Port:** `3000`
- **Websockets Support:** **ON** (required for Socket.IO)
- **Block Common Exploits:** ON (recommended)

### SSL Configuration
Under the SSL tab:
- Request a new **Let’s Encrypt** certificate
- Enable **Force SSL**
- Enable **HTTP/2 Support** (optional)

### Notes
- The Express server listens on port **3000**
- Nginx Proxy Manager forwards HTTPS traffic to this port
- Websockets must be enabled for real-time chat to function


## Database Schema Documentation

The application uses **SQLite** for persistent storage.
The database file is located at:

server/db/forum.sqlite

To inspect the database manually:

```bash
sqlite3 db/forum.sqlite
.tables
.schema table_name
.exit
```
## Database Schema Documentation

### `users`

| Column | Description |
| ------ | ----------- |
| id | Primary key |
| username | Unique login name |
| password_hash | Argon2 password hash |
| email | Unique email address |
| display_name | Public display name |
| name_color | Profile name color |
| avatar | Avatar identifier |
| bio | Short user bio |
| failed_attempts | Failed login counter |
| locked_until | Account lockout timestamp |
| created_at | Account creation timestamp |
| updated_at | Last update timestamp |

### `sessions`

| Column | Description |
| ------ | ----------- |
| session_id | UUID stored in cookie |
| user_id | References users(id) |
| expires_at | Session expiration timestamp |
| created_at | Session creation timestamp |
| last_seen | Last activity timestamp |

### `comments`

| Column | Description |
| ------ | ----------- |
| id | Primary key |
| user_id | References users(id) |
| display_name | Cached display name |
| text | Comment body |
| created_at | Timestamp |

### `comment_likes`

| Column | Description |
| ------ | ----------- |
| comment_id | References comments(id) |
| user_id | References users(id) |
| created_at | Timestamp |

### `chat_messages`

| Column | Description |
| ------ | ----------- |
| id | Primary key |
| user_id | References users(id) |
| display_name | Cached display name |
| name_color | Cached name color |
| avatar | Cached avatar |
| message | Chat text |
| created_at | Timestamp |
| room_id | Chat room identifier |

### `login_attempts`

| Column | Description |
| ------ | ----------- |
| id | Primary key |
| username | Attempted username |
| ip | Client IP address |
| ts | Timestamp |
| success | Success flag |

### `password_resets`

| Column | Description |
| ------ | ----------- |
| id | Primary key |
| user_id | References users(id) |
| token | Reset token |
| expires_at | Expiration timestamp |
| used | Token usage flag |
