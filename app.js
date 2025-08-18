const express = require('express');
const { Sequelize, DataTypes } = require('sequelize');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const app = express();
app.use(express.json());

const sequelize = new Sequelize(process.env.DATABASE_URL, {
  dialect: 'postgres',
  protocol: 'postgres',
  logging: false,
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

function encrypt(text, key) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(key), iv);
  let encrypted = cipher.update(text);
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  return iv.toString('hex') + ':' + encrypted.toString('hex');
}

app.get('/', (req, res) => { // Ensure this route is active
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
  res.json({ message: 'User created', user: { id: user.id, username, email } }); // Add encryption_key
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
  if (!req.headers.authorization || !req.headers.authorization.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  const token = req.headers.authorization.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findByPk(decoded.id);
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
    res.status(401).json({ error: 'Invalid token' });
  }
});

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));