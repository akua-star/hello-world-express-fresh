export default (sequelize, DataTypes) => {
  return sequelize.define('User', {
    id: { type: DataTypes.INTEGER, autoIncrement: true, primaryKey: true },
    username: { type: DataTypes.STRING, allowNull: false },
    email: { type: DataTypes.STRING, allowNull: false, unique: true },
    password: { type: DataTypes.STRING, allowNull: false },
    encryption_key: { type: DataTypes.STRING, allowNull: false },
  }, { timestamps: false, tableName: 'users' });
};