const bcrypt = require('bcryptjs');
const cryptPassword = async function (next) {
  if (!this.isModified('pin')) {
    next();
  }
  this.pin = await bcrypt.hash(this.pin, 10);
};

module.exports = cryptPassword;
