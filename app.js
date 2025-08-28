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
      rejectUnauthorized: false // Allows self-signed certificates; remove in production if using trusted CA
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
const Password = require('./models/userpassword')

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

    const encKey = crypto.createHash('sha256').update(String(key)).digest('base64').slice(0, 32)

    const cipher = crypto.createCipheriv(algorithm, encKey, iv);

    let crypted = cipher.update(unenrypted_string,'utf-8',"base64") + cipher.final("base64");

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

  try {
  
    const user = await User.findByPk(req.auth.id );
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
    let passwords = await Password.findAll({
        attributes: ['id', 'url', 'username', 'password', 'label', 'weak_encryption'], where: { ownerUserId: userId }
    });
    const userRecord = await User.findOne({
        attributes: ['encryption_key'], where: { id: userId }
    });
    const matched = await bcrypt.compare(encryptionKey, userRecord.encryption_key);
    if (!matched) {
        res.status(400);
        return res.json({message: 'Incorrect encryption key'});
    }
    const passwordsArr = [];
    for (let i = 0; i < passwords.length; i++) {
        const element = passwords[i];
        // await upgradeWeakEncryption(element, userRecord, encryptionKey);
        element.password = decrypt(element.password, encryptionKey);
        element.username = decrypt(element.username, encryptionKey);
        passwordsArr.push(element);
    }
    res.status(200);
    res.json({message: 'Success', data: passwordsArr});
});


async function upgradeWeakEncryption(element, userRecord, encryptionKey) {
    if (element.weak_encryption) {
        const decryptedPassword = decrypt(element.password, userRecord.encryption_key);
        const decryptedUserName = decrypt(element.username, userRecord.encryption_key);
        element.password = encrypt(decryptedPassword, encryptionKey);
        element.username = encrypt(decryptedUserName, encryptionKey);
        element.weak_encryption = false;
        await element.save();
    }
}

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

