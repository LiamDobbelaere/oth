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
const { LOADIPHLPAPI } = require('dns');
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

app.get('/logged-in', async (req, res) => {
  if (req.session.userId) {
    const user = await db.User.findByPk(req.session.userId, {
      include: db.Permission
    });
    const permissions = user.Permissions.map(p => p.name);

    if (!user) {
      return res.sendStatus(404);
    }

    return res.send({
      email: user.email,
      permissions
    });
  } else {
    return res.sendStatus(403);
  }
});

app.post('/logout', (req, res) => {
  delete req.session.userId;

  return res.sendStatus(200);
});

function loginUser(userId, req, res) {
  req.session.userId = userId;
  res.cookie('sid', req.sessionID, {
    maxAge: cookieMaxAge
  });
}

async function hasPermission(name, userId) {
  const user = await db.User.findByPk(userId, {
    include: db.Permission
  });
  const permissions = user.Permissions.map(p => p.name);

  return permissions.includes(name);
}

app.get('/manage-permissions/users-and-permissions', async (req, res) => {
  if (!req.session.userId) {
    return res.status(403).send({
      error: "Not logged in."
    });
  }

  const allowed = await hasPermission("MANAGE_PERMISSIONS", req.session.userId);
  if (!allowed) {
    return res.status(403).send({
      error: "You don't have permissions to do that."
    });
  }

  const usersWithPermissions = await db.User.findAll({
    include: db.Permission
  });

  const result = usersWithPermissions.reduce((acc, userWithPermissions) => {
    acc[userWithPermissions.email] = userWithPermissions.Permissions.map(p => p.name);
    return acc;
  }, {});

  res.status(200).send(result);
});

app.post('/manage-permissions/add', async (req, res) => {
  if (!req.session.userId) {
    return res.status(403).send({
      error: "Not logged in."
    });
  }

  const { email, permission } = req.body;

  if (!email || !permission) {
    return res.status(400).send({
      error: "Email or permission not provided."
    });
  }

  const permissionInstance = await db.Permission.findOne({
    where: {
      name: permission
    }
  });

  if (!permissionInstance) {
    return res.status(404).send({
      error: "Permission not found."
    });
  }

  const user = await db.User.findOne({
    where: {
      email
    }
  });

  if (!user) {
    return res.status(404).send({
      error: "User not found."
    });
  }

  await user.addPermission(permissionInstance);

  return res.sendStatus(200);
});

app.post('/manage-permissions/remove', async (req, res) => {
  if (!req.session.userId) {
    return res.status(403).send({
      error: "Not logged in."
    });
  }

  const { email, permission } = req.body;

  if (!email || !permission) {
    return res.status(400).send({
      error: "Email or permission not provided."
    });
  }

  const permissionInstance = await db.Permission.findOne({
    where: {
      name: permission
    }
  });

  if (!permissionInstance) {
    return res.status(404).send({
      error: "Permission not found."
    });
  }

  const user = await db.User.findOne({
    where: {
      email
    }
  });

  if (!user) {
    return res.status(404).send({
      error: "User not found."
    });
  }

  await user.removePermission(permissionInstance);

  return res.sendStatus(200);
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).send({
      error: "Email or password not provided."
    });
  }

  const user = await db.User.findOne({
    where: {
      email
    }
  });

  if (!user) {
    return res.status(401).send({
      error: "User does not exist."
    });
  }

  const passwordMatches = await bcrypt.compare(password, user.password);
  if (passwordMatches === true) {
    loginUser(user.id, req, res);

    return res.sendStatus(200);
  } else {
    return res.status(401).send({
      error: "Wrong credentials."
    });
  }
});

app.post('/register', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).send({
      error: "Email or password not provided."
    });
  }

  const user = await db.User.findOne({
    where: {
      email
    }
  });

  if (user) {
    return res.status(409).send({
      error: "A user with that e-mail already exists."
    });
  }

  // user doesn't exist, let's create it
  const hashedPw = await bcrypt.hash(password, +BCRYPT_ROUNDS);
  const newUser = await db.User.create({
    email,
    password: hashedPw
  });

  // log them in while we're at it
  loginUser(newUser.id, req, res);

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

internal.get('/session/:sessionId/user-info', async (req, res) => {
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
      res.status(404).send({
        error: "User not found from sid."
      });
    } else {
      const permissions = user.Permissions.map(p => p.name);
    
      res.send({
        email: user.email,
        permissions
      });
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
