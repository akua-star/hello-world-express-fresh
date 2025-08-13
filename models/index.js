import { Sequelize } from 'sequelize';
import User from './user.js';
import UserPassword from './user-password.js';

const sequelize = new Sequelize(process.env.DATABASE_URL, {
  dialect: 'postgres',
  protocol: 'postgres',
  logging: false,
});

const db = {
  User: User(sequelize, Sequelize.DataTypes),
  UserPassword: UserPassword(sequelize, Sequelize.DataTypes),
  sequelize,
};

db.User.hasMany(db.UserPassword, { foreignKey: 'ownerUserId' });
db.UserPassword.belongsTo(db.User, { foreignKey: 'ownerUserId' });

export default db;