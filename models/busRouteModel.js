const mongoose = require('mongoose');

const busRouteSchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, 'Please enter Route Name'],
  },
  stations: {
    type: String,
    required: [true, 'Please enter number of Stations'],
  },
  stationList: [
    {
      type: Object,
    },
  ],
  routePermitDoc: {
    type: String,
    default: 'none',
  },
  authorityId: {
    type: mongoose.Schema.ObjectId,
    ref: 'busOwner',
  },
  travelTimings: [
    {
      type: Object,
    },
  ],
  preBookBusSeatNo: {
    type: Number,
  },
  approvalStatus: {
    type: String,
    default: 'pending',
  },
});

module.exports = mongoose.model('BusRoute', busRouteSchema);
