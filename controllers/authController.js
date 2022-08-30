const ErrorHandler = require('../utils/errorhandler');
const catchAsyncErrors = require('../middleware/catchAsyncErrors');
const BusOwner = require('../models/busOwnerModel');
const sendToken = require('../utils/jwtToken');
const { generateOtp, sendOtp } = require('../utils/sendSms');
const Driver = require('../models/driverModel');
const SuperUser = require('../models/superUserModel');
const logger = require('../logger/index');

//Find valid user

function findValidUserType(role) {
  if (role == 'busOwner') return BusOwner;
  else if (role == 'driver') return Driver;
  else if (role == 'admin') return SuperUser;
  return;
}

//login module for bus owner
exports.loginUser = catchAsyncErrors(async (req, res, next, userType) => {
  //checking if user has given pin and phone both
  const profiler = logger.startTimer();
  let User = findValidUserType(req.body.role);
  const { email, phone, pin } = req.body;
  if (!email && !phone) {
    return next(new ErrorHandler('Invalid login information', 400));
  }

  let user = phone
    ? await User.findOne({
        phone,
      }).select('+pin')
    : await User.findOne({ email }).select('+pin');

  if (!user) {
    return next(new ErrorHandler('Invalid login information', 401));
  }
  const ispinMatched = await user.comparepin(pin);

  if (!ispinMatched) {
    logger.log(
      'warning',
      `Invalid pin given for ${
        phone ? 'phone number : ' + phone : 'email : ' + email
      }`
    );
    return next(new ErrorHandler('Invalid login information', 401));
  }
  const otp = generateOtp();
  const update = {
    otp: otp,
    otpExpire: Date.now() + 5 * 60000,
  };

  user = phone
    ? await User.findOneAndUpdate({ phone }, update, {
        new: true,
        runValidators: true,
        useFindAndModify: false,
      }).select('id otp phone name role')
    : await User.findOneAndUpdate({ email }, update, {
        new: true,
        runValidators: true,
        useFindAndModify: false,
      }).select('id otp phone name role'); //sending otp for testing purposes
  //console.log(jk.otp);
  profiler.done({
    message: `User ${user.name} (${user.phone}) requested login otp`,
  });
  sendOtp(user.phone, otp);
  sendToken(user, 200, res);
});

//upload company information name,tin,trade

//verify OTP for busowner
exports.verifyOtp = catchAsyncErrors(async (req, res, next) => {
  const profiler = logger.startTimer();
  if (!req.user) {
    return next(new ErrorHandler('Unauthorized request'));
  }
  const id = req.user.id;
  let User = findValidUserType(req.user.role);
  const user = await User.findOne({
    id: id,
    otpExpire: { $gt: Date.now() },
  });
  if (!user) {
    return next(new ErrorHandler('Otp is invalid or has expired', 400));
  }
  if (req.body.otp !== user.otp) {
    profiler.done({
      message: `Invalid otp tried for ${user.name} (${user.phone}) !`,
      level: 'warning',
    });
    return next(new ErrorHandler('Otp is invalid or has expired', 400));
  }

  user.otp = undefined;
  user.otpExpire = undefined;
  user.loggedIn = true;
  await user.save({ validateBeforeSave: false });

  sendToken(user, 200, res);
  profiler.done({
    message: `User ${user.name} (${user.phone}) logged in!`,
  });
});

exports.logout = catchAsyncErrors(async (req, res, next) => {
  const profiler = logger.startTimer();
  const user = req.user;
  const id = user.id;
  if (user) {
    user.loggedIn = false;
    user.save({ validateBeforeSave: false });
  }

  res.cookie('token', null, {
    expires: new Date(Date.now()),
    httpOnly: true,
  });
  res.status(200).json({
    success: true,
    message: 'Logged out',
  });
  profiler.done({
    message: 'Logged Out',
    level: 'info',
    actionBy: id,
  });
});
