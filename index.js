require('dotenv').config();
const { 
  PORT,
  PORT_INTERNAL,
  ROOT_EMAIL,
  ROOT_PASS,
  SESSION_SECRET,
  BCRYPT_ROUNDS,
  SECURE_COOKIES,
  MAIL_SMTP_HOST,
  MAIL_SMTP_PORT,
  MAIL_SMTP_SECURE,
  MAIL_SMTP_USER,
  MAIL_SMTP_PASS,
  MAIL_SMTP_FROM
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
const nodemailer = require("nodemailer");
const sessionStore = new SQLiteSession();
const cookieMaxAge = 365 * 24 * 60 * 60 * 1000;
const mailTransporter = nodemailer.createTransport({
  host: MAIL_SMTP_HOST,
  port: +MAIL_SMTP_PORT,
  secure: !!+MAIL_SMTP_SECURE,
  auth: {
    user: MAIL_SMTP_USER,
    pass: MAIL_SMTP_PASS
  }
});


app.use(session({
  store: sessionStore,
  secret: SESSION_SECRET,
  resave: true,
  saveUninitialized: false,
  cookie: { 
    secure: !!+SECURE_COOKIES,
    maxAge: cookieMaxAge
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
    res.cookie('sid', req.sessionID, {
      maxAge: cookieMaxAge
    });

    return res.sendStatus(200);
  } else {
    return res.sendStatus(401);
  }
});

app.post('/register', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.sendStatus(400);
  }

  const user = await db.User.findOne({
    where: {
      email
    }
  });

  if (user) {
    return res.sendStatus(409);
  }

  // user doesn't exist, let's create it
  const hashedPw = await bcrypt.hash(password, +BCRYPT_ROUNDS);
  const newUser = await db.User.create({
    email,
    password: hashedPw
  });

  return res.sendStatus(200);
});

/*
transporter.sendMail({
  from: MAIL_SMTP_FROM,
  to: "blah@outlook.com",
  subject: "Hello ✔",
  html: "<b>Hello world?</b>",
});
*/

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
  const sessionId = req.params.sessionId;

  sessionStore.get(sessionId, async (err, data) => {
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
    await rootUser.createPermission({
      name: 'MODIFY_STREAMLIST'
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
