const Sequelize = require('sequelize');
const sequelize = new Sequelize({
  dialect: 'sqlite',
  storage: 'oth.db',
  logging: false
});

const User = sequelize.define('User', {
  email: {
    type: Sequelize.DataTypes.STRING,
    allowNull: false,
    unique: true
  },
  password: {
    type: Sequelize.DataTypes.STRING.BINARY,
    allowNull: false
  }
});

const Permission = sequelize.define('Permission', {
  name: {
    type: Sequelize.DataTypes.STRING
  }
});

User.belongsToMany(Permission, { through: 'UserPermissions' });
Permission.belongsToMany(User, { through: 'UserPermissions' });

function isReady() {
  return sequelize.authenticate()
    .then(() => sequelize.sync())
    .catch(console.log);
}

module.exports = {
  User,
  Permission,
  isReady
};