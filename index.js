require('dotenv').config();
const { 
  PORT,
  PORT_INTERNAL,
  ROOT_EMAIL,
  ROOT_PASS,
  SESSION_SECRET,
  BCRYPT_ROUNDS,
  SECURE_COOKIES
} = process.env;

const express = require('express');
const bodyParser = require('body-parser');
const app = express();
const internal = express();
const http = require('http').createServer(app);
const httpInternal = require('http').createServer(internal);
const bcrypt = require('bcrypt');
const db = require('./db');
const path = require('path');
const session = require('express-session');
const SQLiteSession = require('connect-sqlite3')(session);
const sessionStore = new SQLiteSession();

app.use(session({
  store: sessionStore,
  secret: SESSION_SECRET,
  resave: true,
  saveUninitialized: false,
  cookie: { 
    secure: !!+SECURE_COOKIES,
    maxAge: 7 * 24 * 60 * 60 * 1000 // 1 week
  }
}));
app.use(bodyParser.json());
app.use('/', express.static(path.join(__dirname, 'public')));

app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.sendStatus(400);
  }

  const user = await db.User.findOne({
    where: {
      email
    }
  });

  if (!user) {
    return res.sendStatus(401);
  }

  const passwordMatches = await bcrypt.compare(password, user.password);
  if (passwordMatches === true) {
    req.session.userId = user.id;

    return res.sendStatus(200);
  } else {
    return res.sendStatus(401);
  }
});

app.get('/permissions', async (req, res) => {
  if (!req.session.userId) {
    return res.sendStatus(403);
  }

  const user = await db.User.findByPk(req.session.userId, {
    include: db.Permission
  });
  const permissions = user.Permissions.map(p => p.name);

  res.send(permissions);
});

internal.get('/permissions/:sessionId', async (req, res) => {
  sessionStore.get(req.params.sessionId, async (err, data) => {
    if (err) {
      res.sendStatus(500);
      throw err;
    }

    if (!data) {
      return res.sendStatus(403);
    }

    const userId = data.userId;
    const user = await db.User.findByPk(userId, {
      include: db.Permission
    });

    if (!user) {
      res.send([]);
    } else {
      const permissions = user.Permissions.map(p => p.name);
    
      res.send(permissions);
    }
  });
});

db.isReady().then(async () => {
  if (process.argv.includes('--seed')) {
    console.log('Seeding root user and permissions.');

    const hashedRootPw = await bcrypt.hash(ROOT_PASS, +BCRYPT_ROUNDS);
    const rootUser = await db.User.create({
      email: ROOT_EMAIL,
      password: hashedRootPw
    });

    await rootUser.createPermission({
      name: 'MANAGE_PERMISSIONS'
    });

    console.log('Root user and permissions seeded.');
  }  

  http.listen(PORT, () => {
    console.log(`Oth running on port ${PORT}`);
  });

  httpInternal.listen(PORT_INTERNAL, () => {
    console.log(`Oth internal running on port ${PORT_INTERNAL}`);
  });
});
