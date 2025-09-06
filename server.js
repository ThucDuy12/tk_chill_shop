require('dotenv').config();

const express = require('express');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const DiscordStrategy = require('passport-discord').Strategy;

const fs = require('fs').promises;
const path = require('path');

const cors = require('cors');
const morgan = require('morgan');

const app = express();
const PORT = process.env.PORT || 3000;

// ---- file used to store local users (demo) ----
const USERS_FILE = path.join(__dirname, 'users.json');

// ---- middleware ----
app.use(morgan('dev'));

// If frontend served from same origin you can use origin: true to echo back origin
app.use(cors({
  origin: true,
  credentials: true
}));
app.options('*', cors({ origin: true, credentials: true }));

app.use(express.json()); // parse JSON bodies

// session cookie config
const sessionName = process.env.SESSION_NAME || 'connect.sid';
app.use(session({
  name: sessionName,
  secret: process.env.SESSION_SECRET || 'changeme_local_secret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 24 * 60 * 60 * 1000,
    sameSite: 'lax', // 'lax' helps with auth flows while reducing CSRF risk
    secure: (process.env.NODE_ENV === 'production') // set true in production with HTTPS
  }
}));

app.use(passport.initialize());
app.use(passport.session());

/* ------------------ Passport serialize/deserialize ------------------ */
passport.serializeUser((user, done) => {
  done(null, user);
});
passport.deserializeUser((obj, done) => {
  done(null, obj);
});

/* ------------------ OAuth strategies (optional) ------------------ */
if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
  passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.GOOGLE_CALLBACK_URL || 'http://localhost:3000/auth/google/callback'
  }, (accessToken, refreshToken, profile, done) => {
    return done(null, { provider: 'google', profile, accessToken });
  }));
} else {
  console.warn('Google OAuth not configured (set GOOGLE_CLIENT_ID & GOOGLE_CLIENT_SECRET in .env)');
}

if (process.env.DISCORD_CLIENT_ID && process.env.DISCORD_CLIENT_SECRET) {
  passport.use(new DiscordStrategy({
    clientID: process.env.DISCORD_CLIENT_ID,
    clientSecret: process.env.DISCORD_CLIENT_SECRET,
    callbackURL: process.env.DISCORD_CALLBACK_URL || 'http://localhost:3000/auth/discord/callback',
    scope: ['identify', 'email']
  }, (accessToken, refreshToken, profile, done) => {
    return done(null, { provider: 'discord', profile, accessToken });
  }));
} else {
  console.warn('Discord OAuth not configured (set DISCORD_CLIENT_ID & DISCORD_CLIENT_SECRET in .env)');
}

/* ------------------ users.json helpers ------------------ */
async function ensureUsersFile() {
  try {
    await fs.access(USERS_FILE);
  } catch (err) {
    await fs.writeFile(USERS_FILE, '[]', 'utf8');
  }
}

async function readUsers() {
  await ensureUsersFile();
  const txt = await fs.readFile(USERS_FILE, 'utf8');
  try { return JSON.parse(txt || '[]'); } catch (e) { return []; }
}
async function writeUsers(users) {
  await fs.writeFile(USERS_FILE, JSON.stringify(users, null, 2), 'utf8');
}

async function getOrCreateUserRecord(sessionUser) {
  const users = await readUsers();
  const profile = sessionUser && sessionUser.profile ? sessionUser.profile : sessionUser;
  const email = (profile && ((profile.emails && profile.emails[0] && profile.emails[0].value) || profile.email)) || '';
  const profileId = (profile && (profile.id || profile._id)) || '';

  let idx = -1;
  if (email) idx = users.findIndex(u => u.email === email);
  if (idx === -1 && profileId) idx = users.findIndex(u => String(u.id) === String(profileId));
  if (idx === -1) {
    const newRec = {
      id: profileId ? String(profileId) : Date.now().toString(),
      name: profile.displayName || profile.name || profile.username || 'User',
      email: email || '',
      password: '',
      cart: []
    };
    users.push(newRec);
    await writeUsers(users);
    return { user: newRec, users, index: users.length - 1 };
  }
  return { user: users[idx], users, index: idx };
}

/* ------------------ Local auth endpoints (demo) ------------------ */
app.post('/api/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password) return res.status(400).json({ ok: false, message: 'Thiếu thông tin' });

    const users = await readUsers();
    if (users.some(u => u.email === email)) return res.status(409).json({ ok: false, message: 'Email đã tồn tại' });

    const newUser = {
      id: Date.now().toString(),
      name,
      email,
      password,
      cart: []
    };
    users.push(newUser);
    await writeUsers(users);

    req.login({ provider: 'local', profile: newUser }, (err) => {
      if (err) return res.status(500).json({ ok: false, message: 'Lỗi khi đăng nhập sau đăng ký' });
      return res.json({ ok: true, user: newUser });
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false, message: 'Server error' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ ok: false, message: 'Thiếu thông tin' });

    const users = await readUsers();
    const user = users.find(u => u.email === email && u.password === password);
    if (!user) return res.status(401).json({ ok: false, message: 'Email hoặc mật khẩu không đúng' });

    req.login({ provider: 'local', profile: user }, err => {
      if (err) return res.status(500).json({ ok: false, message: 'Lỗi khi đăng nhập' });
      return res.json({ ok: true, user });
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false, message: 'Server error' });
  }
});

// Logout - improved: log, clear cookie, handle errors
app.post('/api/logout', (req, res, next) => {
  console.log('POST /api/logout hit, req.user=', !!req.user);
  // Passport 0.6 requires callback
  req.logout(function(err) {
    if (err) {
      console.error('req.logout error', err);
      return next(err);
    }
    if (req.session) {
      req.session.destroy((err2) => {
        if (err2) {
          console.error('session.destroy error', err2);
          // still try to clear cookie
          res.clearCookie(sessionName, { path: '/' });
          return res.status(500).json({ ok: false, message: 'Không thể huỷ session' });
        }
        // clear cookie on client
        res.clearCookie(sessionName, { path: '/' });
        return res.json({ ok: true });
      });
    } else {
      res.clearCookie(sessionName, { path: '/' });
      return res.json({ ok: true });
    }
  });
});

/* ------------------ Cart endpoints (store inside users.json) ------------------ */
app.get('/api/cart', async (req, res) => {
  if (!req.user) return res.status(401).json({ ok: false, message: 'Chưa đăng nhập' });
  try {
    const { user } = await getOrCreateUserRecord(req.user);
    return res.json({ ok: true, cart: user.cart || [] });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ ok: false, message: 'Lỗi server' });
  }
});

app.post('/api/cart', async (req, res) => {
  if (!req.user) return res.status(401).json({ ok: false, message: 'Chưa đăng nhập' });
  try {
    const newCart = Array.isArray(req.body.cart) ? req.body.cart : [];
    const { users, index } = await getOrCreateUserRecord(req.user);
    users[index].cart = newCart;
    await writeUsers(users);
    return res.json({ ok: true, cart: users[index].cart });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ ok: false, message: 'Lỗi server' });
  }
});

app.post('/api/checkout', async (req, res) => {
  if (!req.user) return res.status(401).json({ ok: false, message: 'Chưa đăng nhập' });
  try {
    const { users, index } = await getOrCreateUserRecord(req.user);
    const cart = users[index].cart || [];
    if (!cart.length) return res.status(400).json({ ok: false, message: 'Giỏ hàng trống' });

    const orderId = 'ORD-' + Date.now();
    users[index].cart = [];
    await writeUsers(users);

    return res.json({ ok: true, orderId, message: 'Thanh toán thành công (mô phỏng)' });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ ok: false, message: 'Lỗi server' });
  }
});

/* ------------------ OAuth routes ------------------ */
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/?auth=fail' }),
  (req, res) => res.redirect('/?auth=success')
);

app.get('/auth/discord', passport.authenticate('discord'));
app.get('/auth/discord/callback',
  passport.authenticate('discord', { failureRedirect: '/?auth=fail' }),
  (req, res) => res.redirect('/?auth=success')
);

/* ------------------ API to get current user ------------------ */
app.get('/api/me', (req, res) => {
  if (!req.user) return res.json({ loggedIn: false });
  const { provider, profile } = req.user;
  const userInfo = {
    provider,
    id: profile.id || '',
    name: profile.displayName || profile.name || profile.username || '',
    email: (profile.emails && profile.emails[0] && profile.emails[0].value) || profile.email || '',
    avatar: (profile.photos && profile.photos[0] && profile.photos[0].value) || null,
    raw: profile
  };
  res.json({ loggedIn: true, user: userInfo });
});

/* ------------------ Serve static frontend ------------------ */
app.use(express.static('public'));

/* ------------------ Start server ------------------ */
app.listen(PORT, () => {
  console.log(`Server started: http://localhost:${PORT}`);
});
