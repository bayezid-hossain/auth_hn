const mongoose = require('mongoose');
const validator = require('validator');
const baseUserModel = require('./userBaseModel');
const cryptPassword = require('../utils/cryptPass');
const extendSchema = require('mongoose-extend-schema');
const Driver = require('./driverModel');
const busOwnerSchema = extendSchema(baseUserModel.schema, {
  companyName: {
    type: String,
    require: false,
  },
  tradeLicense: {
    type: String,
    required: false,
  },
  TINCertificate: {
    type: String,
    required: false,
  },
  busOwnerImage: {
    type: String,
    required: false,
  },
  NIDFront: {
    type: String,
    required: false,
  },
  NIDBack: {
    type: String,
    required: false,
  },
  drivers: [
    {
      type: mongoose.Schema.ObjectId,
      ref: 'Driver',
    },
  ],
  routes: [
    {
      type: mongoose.Schema.ObjectId,
      ref: 'BusRoute',
    },
  ],
  merchantNumber: {
    type: String,
    require: [false, 'Please Enter Your Bkash Number'],
    maxlength: [
      11,
      'Phone Number cannot exceed 11 digits, exclude +88 if provided',
    ],
    minlength: [11, 'Phone number cannot be less than 11 digits'],
    unique: false,
    validate: [validator.isNumeric, 'Please Enter a valid Bkash Number'],
  },
  role: {
    type: String,
    default: 'passenger',
  },
  merchantType: {
    type: String,
    default: 'bkash',
  },
  email: {
    type: String,
    required: [true, 'Please Enter Your Email'],
    maxlength: [30, 'Email cannot exceed 30 letters'],
    unique: true,
    validate: [validator.isEmail, 'Please enter a valid email'],
  },
});
Object.assign(busOwnerSchema.methods, baseUserModel.schema.methods);

busOwnerSchema.pre('save', cryptPassword);

module.exports = mongoose.model('busOwner', busOwnerSchema);
