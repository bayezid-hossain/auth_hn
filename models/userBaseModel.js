const mongoose = require('mongoose');
const validator = require('validator');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cryptPassword = require('../utils/cryptPass');

const UserSchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, 'Please Enter Your Name'],
    maxlength: [30, 'Name cannot exceed 30 characters'],
    minlength: [4, 'Name should have more than 4 characters'],
  },
  phone: {
    type: String,
    required: [true, 'Please Enter Your Phone'],
    maxlength: [
      11,
      'Phone Number cannot exceed 11 digits, exclude +88 if provided',
    ],
    minlength: [11, 'Phone number cannot be less than 11 digits'],
    unique: true,
    validate: {
      validator: function (arr) {
        return !isNaN(arr);
      },
      message: 'Please Enter a valid Phone Number',
    },
  },
  pin: {
    type: String,
    required: [true, 'Please enter your pin'],
    minlength: [4, 'Pin should be minimum 4 digits long'],
    validate: {
      validator: function (arr) {
        return !isNaN(arr);
      },
      message: 'Please enter valid pin (0-9)',
    },
    select: false,
  },
  role: {
    type: String,
    default: 'passenger',
  },
  otp: String,
  otpExpire: Date,
  loggedIn: false,
  approvalStatus: {
    type: String,
    default: 'pending',
  },
});

UserSchema.pre('save', cryptPassword);

//JWT Token

UserSchema.methods.getJWTToken = function () {
  return jwt.sign(
    {
      id: this._id,
    },
    process.env.JWT_SECRET,
    {
      expiresIn: process.env.JWT_Expire,
    }
  );
};

//Compare Password
UserSchema.methods.comparepin = async function (enteredPassword) {
  return await bcrypt.compare(enteredPassword, this.pin);
};

module.exports = mongoose.model('user', UserSchema);
