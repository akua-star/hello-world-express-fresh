import * as bodyParser from "body-parser";
import bcrypt from 'bcryptjs';
import * as JWT from 'jsonwebtoken';
import { expressjwt } from "express-jwt";
import crypto from "crypto";

const app = express();
const port = process.env.PORT || 10000;

app.use(bodyParser.default.json()); // Remove duplicate

app.use(
  expressjwt({
    secret: process.env.JWT_SECRET,
    algorithms: ["HS256"],
  }).unless({ path: ["/login", "/signup", '/'] })
);

app.get('/', (req, res, next) => {
  res.json({ message: "Hello, World!" });
});

// Signup Route
app.post('/signup', async (req, res, next) => {
  const { username, email, password } = req.body;
  const encryption_key = crypto.randomBytes(16).toString('hex');
  const hashedPassword = await hashStr(password);
  const hashedKey = await hashStr(encryption_key);
  const modelsObj = await models.default;
  const user = await modelsObj.User.create({ username, email, password: hashedPassword, encryption_key: hashedKey });
  const token = await generateJWT(user);
  res.json({ message: 'User created', user: { id: user.id, username, email }, token });
});

// Login Route
app.post('/login', async (req, res, next) => {
  const { username, password } = req.body;
  const modelsObj = await models.default;
  const user = await modelsObj.User.findOne({ where: { username } });
  if (user && await bcrypt.compare(password, user.password)) {
    const token = await generateJWT(user);
    res.json({ message: 'Login successful', token });
  } else {
    res.status(401).json({ message: 'Invalid credentials' });
  }
});

// Save Password Route
app.post('/passwords/save', async (req, res, next) => {
  const { url, username, password, encryption_key, label } = req.body;
  const userId = req.auth.id;
  const modelsObj = await models.default;
  const userRecord = await modelsObj.User.findOne({
    attributes: ['encryption_key'], where: { id: userId }
  });
  if (!userRecord) {
    res.status(403);
    return res.json({ message: 'Unable to find the account' });
  }
  const matched = await bcrypt.compare(encryption_key, userRecord.encryption_key);
  if (!matched) {
    res.status(400);
    return res.json({ message: 'Incorrect encryption key' });
  }
  if (!(username && password && url)) {
    res.status(400);
    return res.json({ message: 'Missing parameters' });
  }
  const encryptedUsername = encrypt(username, encryption_key);
  const encryptedPassword = encrypt(password, encryption_key);
  const result = await modelsObj.UserPassword.create({
    ownerUserId: userId, password: encryptedPassword, username: encryptedUsername, url, label
  });
  res.status(200);
  res.json({ message: 'Password is saved' });
});

// Utility Functions
async function hashStr(str) {
  const salt = await bcrypt.genSalt(10);
  return bcrypt.hash(str, salt);
}

function generateJWT(user) {
  return new Promise((resolve, reject) => {
    JWT.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' }, (err, token) => {
      if (err) reject(err);
      resolve(token);
    });
  });
}

function encrypt(unencrypted_string, key) {
  const algorithm = 'aes-256-ctr';
  const iv = crypto.randomBytes(16);
  const encKey = crypto.createHash('sha256').update(String(key)).digest('base64').slice(0, 32);
  const cipher = crypto.createCipheriv(algorithm, encKey, iv);
  let crypted = cipher.update(unencrypted_string, 'utf-8', 'base64') + cipher.final('base64');
  return `${crypted}-${iv.toString('base64')}`;
}

function decrypt(encStr, key) {
  const algorithm = 'aes-256-ctr';
  const encArr = encStr.split('-');
  const encKey = crypto.createHash('sha256').update(String(key)).digest('base64').slice(0, 32);
  const decipher = crypto.createDecipheriv(algorithm, encKey, Buffer.from(encArr[1], 'base64'));
  let decrypted = decipher.update(encArr[0], 'base64', 'utf-8');
  decrypted += decipher.final('utf-8');
  return decrypted;
}

import models from './models'; // Ensure this is at the bottom due to circular dependency

app.listen(port, () => {
  console.log(`Server listening on port ${port}`);
});