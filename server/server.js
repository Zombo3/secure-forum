import express from 'express';
import cookieParser from 'cookie-parser';
import { v4 as uuidv4 } from 'uuid';
import path from 'path';
import { fileURLToPath } from 'url';
import { engine } from 'express-handlebars';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

const users = [
  { username: 'alice', password: 'password' },
  { username: 'bob', password: '1234' }
];

const comments = [
  {
    author: 'alice',
    text: '<b>Hello world!</b> Try some <script>alert("XSS")</script>',
    createdAt: new Date()
  },
  { author: 'bob', text: 'This is intentionally insecure', createdAt: new Date() }
];

const sessions = new Map(); // sessionId -> { user, expires }

app.engine('hbs',engine({
    extname: 'hbs',
    defaultLayout: 'main',
    layoutsDir: path.join(__dirname, 'views', 'layouts'),
    partialsDir: path.join(__dirname, 'views', 'partials'),
    helpers: {
      formatDate: (d) => new Date(d).toLocaleString()
    }
 }));
app.set('view engine', 'hbs');
app.set('views', path.join(__dirname, 'views'));

app.use(express.urlencoded({ extended: false })); //parse from bodies
app.use(cookieParser()); // read cookies into req.cookies

app.use('/public', express.static(path.join(__dirname, 'public')));

// Static files are served by Nginx at /static/, so this route just reminds us:
app.get('/static/*', (req, res) => res.status(404).send('Static is served by Nginx container'));

// Helper to get current user from an unsigned cookie
function getCurrentUser(req) {
  const sid = req.cookies && req.cookies.sessionId;
  if (!sid) return null;
  const record = sessions.get(sid);
  if (!record) return null;
  if (record.expires < new Date()) {
    sessions.delete(sid);
    return null;
  }
  return record.user;
}

// Make currentUser available to templates
app.use((req, res, next) => {
  res.locals.currentUser = getCurrentUser(req);
  next();
});

// Home
app.get('/', (req, res) => {
  res.render('home', { title: 'Insecure Forum' });
});

// Register (GET)
app.get('/register', (req, res) => {
  res.render('register', { title: 'Register' });
});

// Register (POST)
app.post('/register', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res
      .status(400)
      .render('register', { title: 'Register', error: 'Username and password required.' });
  }

  if (users.find((u) => u.username === username)) {
    return res
      .status(400)
      .render('register', { title: 'Register', error: 'Username already taken.' });
  }

  users.push({ username, password });
  return res.render('login', { title: 'Login', message: 'Account created. Please log in.' });
});

// Login (GET)
app.get('/login', (req, res) => {
  res.render('login', { title: 'Login' });
});

// Login (POST)
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const user = users.find((u) => u.username === username && u.password === password);

  if (!user) {
    return res
      .status(401)
      .render('login', { title: 'Login', error: 'Invalid username or password.' });
  }

  const sessionId = uuidv4();
  const expires = new Date(Date.now() + 1000 * 60 * 60); // 1 hour
  sessions.set(sessionId, { user: username, expires });

  // Intentionally insecure cookie: not httpOnly, not secure, not signed
  res.cookie('sessionId', sessionId, {
    expires
    // httpOnly: false,
    // secure: false
  });

  res.redirect('/');
});

// Logout (POST)
app.post('/logout', (req, res) => {
  const sid = req.cookies && req.cookies.sessionId;
  if (sid) sessions.delete(sid);
  res.clearCookie('sessionId');
  res.redirect('/');
});

// Comments feed (GET)
app.get('/comments', (req, res) => {
  const list = [...comments].sort((a, b) => b.createdAt - a.createdAt);
  res.render('comments', { title: 'All Comments', comments: list });
});

// New comment form (GET)
app.get('/comment/new', (req, res) => {
  const user = getCurrentUser(req);
  if (!user) {
    return res
      .status(401)
      .render('login', { title: 'Login', error: 'Please log in to post a comment.' });
  }
  res.render('new-comment', { title: 'New Comment' });
});

// Create comment (POST)
app.post('/comment', (req, res) => {
  const user = getCurrentUser(req);
  if (!user) {
    return res
      .status(401)
      .render('login', { title: 'Login', error: 'You must be logged in to comment.' });
  }

  const { text } = req.body;
  if (!text || text.trim() === '') {
    return res
      .status(400)
      .render('new-comment', { title: 'New Comment', error: 'Comment text is required.' });
  }

  comments.push({ author: user, text, createdAt: new Date() });
  res.redirect('/comments');
});

app.listen(PORT, () => {
  console.log(`Insecure Forum running on port ${PORT}`);
});
