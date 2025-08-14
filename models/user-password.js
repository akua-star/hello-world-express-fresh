export default (sequelize, DataTypes) => {
  return sequelize.define('UserPassword', {
    id: { type: DataTypes.INTEGER, autoIncrement: true, primaryKey: true },
    ownerUserId: { type: DataTypes.INTEGER, allowNull: false },
    url: { type: DataTypes.STRING, allowNull: false },
    username: { type: DataTypes.STRING, allowNull: false },
    password: { type: DataTypes.STRING, allowNull: false },
    label: { type: DataTypes.STRING, allowNull: false },
  }, { timestamps: true, tableName: 'users_passwords' });
};