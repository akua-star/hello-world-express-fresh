const express = require('express');
const { Sequelize, DataTypes } = require('sequelize');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { expressjwt } = require("express-jwt");

const app = express();
app.use(express.json());
app.use(
  expressjwt({
    secret: process.env.JWT_SECRET,
    algorithms: ["HS256"],
  }).unless({ path: ["/login", "/signup", '/'] })
);

const sequelize = new Sequelize(process.env.DATABASE_URL, {
  dialect: 'postgres',
  protocol: 'postgres',
  logging: false,
  dialectOptions: {
    ssl: {
      require: true,
      rejectUnauthorized: false
    }
  }
});

const User = sequelize.define('User', {
  id: { type: DataTypes.INTEGER, autoIncrement: true, primaryKey: true },
  username: { type: DataTypes.STRING, allowNull: false },
  email: { type: DataTypes.STRING, allowNull: false, unique: true },
  password: { type: DataTypes.STRING, allowNull: false },
  encryption_key: { type: DataTypes.STRING, allowNull: false },
  created_at: { type: DataTypes.DATE, allowNull: false },
}, { timestamps: false, tableName: 'users' });

const Password = sequelize.define('Password', {
  id: { type: DataTypes.INTEGER, autoIncrement: true, primaryKey: true },
  label: { type: DataTypes.STRING, allowNull: false },
  username: { type: DataTypes.STRING, allowNull: false },
  encrypted_password: { type: DataTypes.STRING, allowNull: false },
  url: { type: DataTypes.STRING, allowNull: false },
  encrypted_key_hash: { type: DataTypes.STRING, allowNull: false },
  userId: { type: DataTypes.INTEGER, allowNull: false },
}, { timestamps: false, tableName: 'passwords' });

(async () => {
  try {
    await sequelize.sync({ alter: true });
    console.log('Database synced');
  } catch (err) {
    console.error('Database sync error:', err);
  }
})();

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

function encrypt(unenrypted_string, key) {
  const algorithm = 'aes-256-ctr';
  const iv = crypto.randomBytes(16);
  const encKey = crypto.createHash('sha256').update(String(key)).digest('base64').slice(0, 32);
  const cipher = crypto.createCipheriv(algorithm, encKey, iv);
  let crypted = cipher.update(unenrypted_string, 'utf-8', "base64") + cipher.final("base64");
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

app.get('/', (req, res) => {
  res.json({ message: "Hello, World!" });
});

app.post('/signup', async (req, res) => {
  const { username, email, password, encryption_key } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  const hashedKey = await bcrypt.hash(encryption_key, 10);
  const existingUser = await User.findOne({ where: { email } });
  if (existingUser) {
    return res.status(400).json({ message: 'Email already exists' });
  }
  const user = await User.create({ username, email, password: hashedPassword, encryption_key: hashedKey, created_at: new Date() });
  res.json({ message: 'User created', user: { id: user.id, username, email } });
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ where: { username } });
  if (user && await bcrypt.compare(password, user.password)) {
    const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ message: 'Login successful', token });
  } else {
    res.status(401).json({ message: 'Invalid credentials' });
  }
});

app.post('/save-password', async (req, res) => {
  const { label, username, password, url, encryption_key } = req.body;
  try {
    const user = await User.findByPk(req.auth.id);
    if (!user) {
      return res.status(401).json({ error: 'User not found' });
    }
    const isValidKey = await bcrypt.compare(encryption_key, user.encryption_key);
    if (!isValidKey) {
      return res.status(400).json({ error: 'Invalid encryption key' });
    }
    if (!label || !username || !password || !url || !encryption_key) {
      return res.status(400).json({ error: 'Missing required fields' });
    }
    const encryptedPassword = encrypt(password, encryption_key);
    const encryptedKeyHash = await bcrypt.hash(encryption_key, 10);
    await Password.create({
      label,
      username: encrypt(username, encryption_key),
      encrypted_password: encryptedPassword,
      url,
      encrypted_key_hash: encryptedKeyHash,
      userId: user.id,
    });
    res.json({ message: 'Password saved' });
  } catch (err) {
    console.error('Error saving password:', err);
    res.status(401).json({ error: 'Invalid token' });
  }
});

app.post('/passwords/list', async (req, res, next) => {
  const userId = req.auth.id;
  const encryptionKey = req.body.encryption_key;
  try {
    let passwords = await Password.findAll({
      attributes: ['id', 'url', 'username', 'encrypted_password', 'label'],
      where: { userId }
    });
    const userRecord = await User.findOne({
      attributes: ['encryption_key'],
      where: { id: userId }
    });
    if (!userRecord) {
      return res.status(404).json({ message: 'User not found' });
    }
    const matched = await bcrypt.compare(encryptionKey, userRecord.encryption_key);
    if (!matched) {
      return res.status(400).json({ message: 'Incorrect encryption key' });
    }
    const passwordsArr = [];
    for (let i = 0; i < passwords.length; i++) {
      const element = passwords[i];
      element.dataValues.username = decrypt(element.username, encryptionKey);
      element.dataValues.encrypted_password = decrypt(element.encrypted_password, encryptionKey);
      passwordsArr.push(element.dataValues);
    }
    res.status(200).json({ message: 'Success', data: passwordsArr });
  } catch (err) {
    next(err);
  }
});

app.post('/share-password', async (req, res, next) => {
  const userId = req.auth.id;
  const { passwordId, recipientEmail, encryptionKey } = req.body;
  try {
    const password = await Password.findOne({
      where: { id: passwordId, userId }
    });
    if (!password) {
      return res.status(404).json({ message: 'Password not found' });
    }
    const userRecord = await User.findOne({
      attributes: ['encryption_key'],
      where: { id: userId }
    });
    if (!userRecord) {
      return res.status(404).json({ message: 'User not found' });
    }
    const matched = await bcrypt.compare(encryptionKey, userRecord.encryption_key);
    if (!matched) {
      return res.status(400).json({ message: 'Incorrect encryption key' });
    }
    const decryptedPassword = decrypt(password.encrypted_password, encryptionKey);
    // Here you could add logic to send the decrypted password to recipientEmail (e.g., via email service)
    // For now, return a success message with the shared data
    res.status(200).json({ message: 'Password shared successfully', data: {
      id: password.id,
      label: password.label,
      sharedPassword: decryptedPassword
    }});
  } catch (err) {
    next(err);
  }
});

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));