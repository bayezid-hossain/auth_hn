const mongoose = require('mongoose');

const busSchema = new mongoose.Schema(
  {
    busLicenseNumber: {
      type: String,
      require: [true, 'Please provide license number'],
    },

    owner: {
      type: mongoose.Schema.ObjectId,
      ref: 'busOwner',
    },
    status: {
      type: String,
      default: 'Pending',
    },
  },
  { collection: 'buses' }
);

module.exports = mongoose.model('Bus', busSchema);
