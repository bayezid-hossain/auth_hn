const mongoose = require('mongoose');
const validator = require('validator');
const baseUserModel = require('./userBaseModel');
const cryptPassword = require('../utils/cryptPass');
const extendSchema = require('mongoose-extend-schema');

const superUserSchema = extendSchema(
  baseUserModel.schema,
  {
    addedBy: {
      type: String,
      default: 'default',
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
  },
  { collection: 'superuser' }
);
Object.assign(superUserSchema.methods, baseUserModel.schema.methods);

superUserSchema.pre('save', cryptPassword);

module.exports = mongoose.model('SuperUser', superUserSchema);
