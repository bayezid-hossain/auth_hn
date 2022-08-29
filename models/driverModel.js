const mongoose = require('mongoose');
const validator = require('validator');
const baseUserModel = require('./userBaseModel');
const cryptPassword = require('../utils/cryptPass');
const extendSchema = require('mongoose-extend-schema');

const driverSchema = extendSchema(baseUserModel.schema, {
  driverLicense: {
    type: String,
    require: [true, 'Please enter Driver License'],
  },
  NIDBack: {
    type: String,
    require: [
      true,
      "Please provide picture of Front side of your Driver\\'s NID",
    ],
  },
  NIDFront: {
    type: String,
    require: [
      true,
      "Please provide picture of Back side of your Driver\\'s NID",
    ],
  },
  licenseNumber: {
    type: String,
    require: [true, 'Please provide License Number'],
    unique: true,
  },

  phone: {
    type: String,
    required: [true, 'Please Enter Your Phone'],
    maxlength: [
      11,
      'Phone Number cannot exceed 11 digits, exclude +88 if provided',
    ],
    minlength: [11, 'Phone number cannot be less than 11 digits'],
    unique: false,
    validate: {
      validator: function (arr) {
        return !isNaN(arr);
      },
      message: 'Please Enter a valid Phone Number',
    },
  },
  owner: {
    type: mongoose.Schema.ObjectId,
    ref: 'busOwner',
  },
});
Object.assign(driverSchema.methods, baseUserModel.schema.methods);

driverSchema.pre('save', cryptPassword);

module.exports = mongoose.model('Driver', driverSchema);
