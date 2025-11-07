The Zombo3 Zone 
A deliberately insecure web forum built with Node.js, Express, Handlebars, 
and Docker + Nginx for educational purposes.

Quick Start

with Docker:
git clone https://github.com/Zombo3/insecure-forum.git
cd insecure-forum
docker compose up -d --build
Visit http://159.203.109.52:8080

Project Structure:
insecure-forum/
├── docker-compose.yml
├── nginx/
│   ├── nginx.conf
│   └── static/
│       └── css/
│           └── styles.css
├── static/
│   ├── css/
│   │   └── main.css
│   └── img/
│       └── zombo3.png
└── server/
    ├── server.js
    ├── package.json
    └── views/
        ├── layouts/
        │   └── main.hbs
        ├── index.hbs
        ├── login.hbs
        ├── register.hbs
        └── comments.hbs
Routes:
| Method | Path                               | Description       |
| ------ | ---------------------------------- | ----------------- |
| GET    | `/`                                | Home page         |
| GET    | `/login`, `/register`              | Auth pages        |
| GET    | `/comments`                        | View all comments |
| POST   | `/login`, `/register`, `/comments` | Form actions      |

Intentional Insecurities:
  -Plaintext passwords in memory
  -Weak, unprotected cookies
  -No CSRF protection
  -No rate limiting

Docker Overview:
Browser → Nginx (80→8080) → Express Server (3000)

Mian commands:
docker compose up -d --build   # build & start
docker compose down            # stop containers
docker compose logs -f         # view logs


