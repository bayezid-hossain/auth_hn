const ErrorHandler = require('../utils/errorhandler');
const catchAsyncErrors = require('../middleware/catchAsyncErrors');
const User = require('../models/busOwnerModel');
const sendToken = require('../utils/jwtToken');
const formidable = require('formidable');
const { isFileValid, deleteFile } = require('../utils/fileOperations');
const { uploadFile } = require('../utils/awsS3');
const { generateOtp, sendOtp } = require('../utils/sendSms');
const path = require('path');
const Driver = require('../models/driverModel');
const BusRoute = require('../models/busRouteModel');
const Bus = require('../models/busModel');
const { v4: uuid } = require('uuid');
// const amqp = require('amqplib');
const axios = require('axios');
const logger = require('../logger/index');
let channel;
//rabbitmq queue creation
// async function connect() {
//   const amqpServer = process.env.RABBITMQ_URL;
//   const connection = await amqp.connect(amqpServer);
//   channel = await connection.createChannel();
//   await channel.assertQueue('ADDEDDRIVER');
// }
// connect();

//Register a busOwner

exports.registerBusOwner = catchAsyncErrors(async (req, res, next) => {
  const { name, phone, pin, email } = req.body;

  const user = await User.create({
    name,
    phone,
    email,
    pin,
    role: 'busOwner',
  });

  logger.warning(` ${user.name} : ${user.phone} (${user._id}) registered!`);
  res.redirect(307, '/api/v1/busowner/login');
  // sendToken(user, 201, res);
});

//login module for bus owner
exports.loginBusOwner = catchAsyncErrors(async (req, res, next) => {
  //checking if user has given pin and phone both
  const profiler = logger.startTimer();
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
      }).select('id otp phone name')
    : await User.findOneAndUpdate({ email }, update, {
        new: true,
        runValidators: true,
        useFindAndModify: false,
      }).select('id otp phone name'); //sending otp for testing purposes
  //console.log(jk.otp);
  profiler.done({
    message: `User ${user.name} (${user.phone}) requested login otp`,
  });
  sendOtp(user.phone, otp);
  sendToken(user, 200, res);
});

//upload company information name,tin,trade

exports.uploadCompanyInfo = catchAsyncErrors(async (req, res, next) => {
  const profiler = logger.startTimer();
  const user = req.user;
  if (
    user.companyName &&
    user.TINCertificate &&
    user.tradeLicense &&
    user.approvalStatus != 'rejected'
  ) {
    profiler.done({
      message: `Authority ${user.id} Information submitted already`,
    });
    return next(new Handler(`Information already submitted`));
  }
  var form = new formidable.IncomingForm();
  form.multiples = true;
  form.maxFileSize = 5 * 1024 * 1024; // 5MB
  form
    .parse(req, async (err, fields, files) => {
      if (err) {
        profiler.done({
          message: error,
          level: 'error',
          actionBy: req.user.id,
        });
        return res.status(400).json({
          status: 'Fail',
          message: 'There was an error parsing the files',
          error: err,
        });
      }
      const file1 = files.TIN;
      const file2 = files.Trade;
      try {
        if (isFileValid(file1) && isFileValid(file2) && fields.companyName) {
          const tinUploadProfiler = logger.startTimer();
          const resultofTINUpload = await uploadFile(file1);
          tinUploadProfiler.done({
            message: `Uploaded TIN of Authority ${user.id}`,
          });
          const tradeUploadProfiler = logger.startTimer();
          const resultofTradeUpload = await uploadFile(file2);
          tradeUploadProfiler.done({
            message: `Uploaded TIN of Authority ${user.id}`,
          });
          user.companyName = fields.companyName;
          user.TINCertificate = resultofTINUpload.Key;
          user.tradeLicense = resultofTradeUpload.Key;
          await user.save({ validateBeforeSave: false });
          //could be efficient [TODO]
          profiler.done({
            message: `Uploaded company informations of Authority ${user.id}`,
          });
          res.status(200).json({
            success: true,
            message: 'Uploaded Successfully',
          });
        } else {
          profiler.done({
            message: `Please upload Valid TIN certificate and Trade License images and Company Name`,
            level: 'error',
          });
          return next(
            new ErrorHandler(
              `Please upload Valid TIN certificate and Trade License images and Company Name`
            )
          );
        }
      } catch (error) {
        profiler.done({
          message: error,
          level: 'error',
          actionBy: req.user.id,
        });
        return next(
          new ErrorHandler(
            `Please upload Valid TIN certificate and Trade License images and Company Name`
          )
        );
      } finally {
        try {
          deleteFile(file1.filepath);
        } catch (error) {}
        try {
          deleteFile(file2.filepath);
        } catch (error) {}
      }
    })
    .on('fileBegin', function (name, file) {
      file.newFilename = uuid();
      file.filepath =
        path.join(__dirname, '../') +
        Date.now() +
        file.newFilename +
        '.' +
        file.mimetype.split('/').pop();
      console.log(file.filepath);
    })
    .on('file', function (name, file) {});
});

//same as company info, instead uploads bus owner info. could merge both functions
//TODO: merge both uploads if necessary

exports.uploadBusOwnerInfo = catchAsyncErrors(async (req, res, next) => {
  const profiler = logger.startTimer();
  const user = req.user;
  if (
    user.merchantNumber &&
    merchantType &&
    user.NIDBack &&
    user.NIDFront &&
    user.busOwnerImage &&
    user.approvalStatus != 'rejected'
  ) {
    return next(new ErrorHandler(`Information already submitted`));
  }
  var form = new formidable.IncomingForm();
  form.multiples = true;
  form.maxFileSize = 5 * 1024 * 1024; // 5MB
  form
    .parse(req, async (err, fields, files) => {
      if (err) {
        profiler.done({
          message: err,
          level: 'error',
          actionBy: user.id,
        });
        return res.status(400).json({
          status: 'Fail',
          message: 'There was an error parsing the files',
          error: err,
        });
      }
      const file1 = files.busOwnerImage;
      const file2 = files.NIDFront;
      const file3 = files.NIDBack;
      try {
        if (
          isFileValid(file1) &&
          isFileValid(file2) &&
          isFileValid(file3) &&
          fields.merchantNumber &&
          fields.merchantType
        ) {
          //could be efficient [TODO]
          const ownerImageProfiler = logger.startTimer();
          const resultOfBusOwnerImageUpload = await uploadFile(file1);
          ownerImageProfiler.done({
            message: `Uploaded Image of Authority ${user.id}`,
          });
          const NIDFrontProfiler = logger.startTimer();

          const resultOfNIDFrontUpload = await uploadFile(file2);
          NIDFrontProfiler.done({
            message: `Uploaded NID Front of Authority ${user.id}`,
          });
          const NIDBackProfiler = logger.startTimer();
          const resultOfNIDBackUpload = await uploadFile(file3);
          NIDBackProfiler.done({
            message: `Uploaded NID Back of Authority ${user.id}`,
          });
          user.busOwnerImage = resultOfBusOwnerImageUpload.Key;
          user.NIDFront = resultOfNIDFrontUpload.Key;
          user.NIDBack = resultOfNIDBackUpload.Key;
          user.merchantNumber = fields.merchantNumber;
          user.merchantType = fields.merchantType;
          await user.save({ validateBeforeSave: false });
          profiler.done({
            message: `Uploaded personal informations of Authority ${user.id}`,
          });
          res.status(200).json({
            success: true,
            message: 'Uploaded Successfully',
          });
        } else {
          //could be efficient [TODO]

          profiler.done({
            message: `Please upload Valid TIN certificate and Trade License images and Company Name`,

            level: 'error',
            actionBy: user.id,
          });
          return next(
            new ErrorHandler(`Please upload Valid Photos and Merchant number`)
          );
        }
      } catch (error) {
        profiler.done({
          message: error,
          level: 'error',
          actionBy: req.user.id,
        });
        return next(
          new ErrorHandler(`Please upload Valid Photos and Merchant number`)
        );
      } finally {
        try {
          deleteFile(file1.filepath);
        } catch (error) {}
        try {
          deleteFile(file2.filepath);
        } catch (error) {}
        try {
          deleteFile(file3.filepath);
        } catch (error) {}
      }
    })
    .on('fileBegin', function (name, file) {
      file.newFilename = uuid();
      file.filepath =
        path.join(__dirname, '../') +
        Date.now() +
        file.newFilename +
        '.' +
        file.mimetype.split('/').pop();
      console.log(file.filepath);
    })
    .on('file', function (name, file) {});
});

//verify OTP for busowner
exports.verifyOtp = catchAsyncErrors(async (req, res, next) => {
  const profiler = logger.startTimer();
  if (!req.user) {
    return next(new ErrorHandler('Unauthorized request'));
  }
  const id = req.user.id;
  const user = await User.findOne({
    id: id,
    otpExpire: { $gt: Date.now() },
  }).populate('drivers routes');
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

//get personal info of logged in user
exports.getUserDetails = catchAsyncErrors(async (req, res, next) => {
  const profiler = logger.startTimer();
  try {
    let user;
    user = await User.findById(req.user.id).populate('drivers routes');

    res.status(200).json({
      success: true,
      user,
    });
    profiler.done({
      message: `User ${req.user.id} checked profile`,
    });
  } catch (error) {
    profiler.done({
      message: error,
      level: 'error',
      actionBy: req.user.id,
    });
  }
});

//add routes
exports.createRoute = catchAsyncErrors(async (req, res, next) => {
  const profiler = logger.startTimer();

  const busOwner = req.user;
  var form = new formidable.IncomingForm();
  form.multiples = true;
  form.maxFileSize = 5 * 1024 * 1024; // 5MB
  form
    .parse(req, async (err, fields, files) => {
      if (err) {
        profiler.done({
          message: error,
          level: 'error',
          actionBy: req.user.id,
        });
        return res.status(400).json({
          status: 'Fail',
          message: 'There was an error parsing the files',
          error: err,
        });
      }
      const file1 = files.routePermit;
      try {
        if (
          isFileValid(file1) &&
          fields.routeName &&
          fields.stations &&
          fields.numberOfStations &&
          fields.type &&
          fields.travelTimings
        ) {
          if (fields.type == 2 && fields.preBookBusSeatNo == undefined) {
            profiler.done({
              message: `Route selected as prebook but no prebook bus seat number provided`,
              level: 'error',
              actionBy: busOwner.id,
            });
            return next(
              new ErrorHandler(
                `Route selected as prebook but no prebook bus seat number provided`
              )
            );
          }
          const stationsObject = JSON.parse(fields.stations);
          const travelTimings = JSON.parse(fields.travelTimings);
          const routePermitProfiler = logger.startTimer();
          const resultOfRoutePermitUpload = await uploadFile(file1);
          routePermitProfiler.done({
            message: `Uploaded Route permit document by Authority ${busOwner.id}`,
          });

          const busRoute = await BusRoute.create({
            name: fields.routeName,
            stations: fields.numberOfStations,
            stationList: stationsObject,
            routePermitDoc: resultOfRoutePermitUpload.Key,
            type: fields.type,
            authorityId: req.user,
            travelTimings: travelTimings,
            preBookBusNo:
              fields.preBookBusNo != undefined ? fields.preBookBusNo : null,
          });
          busOwner.routes.push(busRoute);
          busOwner.save();

          res.status(200).json({
            success: true,
            message: 'Bus Route added Successfully',
          });

          profiler.done({
            message: `Created Route ${busRoute.id} by Authority ${busOwner.id}`,
          });
        } else {
          profiler.done({
            message: `Please upload Valid Route Permit Document`,
            level: 'error',
          });
          return next(
            new ErrorHandler(`Please provide all Informations correctly`)
          );
        }
      } catch (error) {
        profiler.done({
          message: error,
          level: 'error',
          actionBy: req.user.id,
        });
        return next(
          new ErrorHandler('Please provide all Informations correctly')
        );
      } finally {
        try {
          deleteFile(file1.filepath);
        } catch (error) {}
      }
    })
    .on('fileBegin', function (name, file) {
      file.newFilename = uuid();
      file.filepath =
        path.join(__dirname, '../') +
        Date.now() +
        file.newFilename +
        '.' +
        file.mimetype.split('/').pop();
      console.log(file.filepath);
    })
    .on('file', function (name, file) {});
});

//add Driver
exports.addDriver = catchAsyncErrors(async (req, res, next) => {
  const profiler = logger.startTimer();

  var form = new formidable.IncomingForm();
  form.multiples = true;
  form.maxFileSize = 5 * 1024 * 1024; // 5MB
  form
    .parse(req, async (err, fields, files) => {
      if (err) {
        profiler.done({
          message: error,
          level: 'error',
          actionBy: req.user.id,
        });

        return res.status(400).json({
          status: 'Fail',
          message: 'There was an error parsing the files',
          error: err,
        });
      }
      const drivingLicense = files.drivingLicense;
      const NIDBack = files.NIDBack;
      const NIDFront = files.NIDFront;
      try {
        if (
          isFileValid(drivingLicense) &&
          isFileValid(NIDBack) &&
          isFileValid(NIDFront) &&
          fields.driverName &&
          fields.phoneNumber &&
          fields.pin &&
          fields.licenseNumber
        ) {
          const validDriverPayload = {
            driverName: fields.driverName,
            licenseNumber: fields.licenseNumber,
          };

          const driverValidity = await axios
            .post(
              'http://44.202.73.200:8006/api/v1/crosscheck/driver',
              validDriverPayload
            )
            .catch(function (error) {
              profiler.done({
                message: error,
                level: 'error',
                actionBy: req.user.id,
              });
              return next(
                new ErrorHandler('Validation Service not Responding')
              );
            });
          if (driverValidity.data.result == true) {
            const newDriverPayload = {
              name: fields.driverName,
              driverLicense: 'tempURL',
              NIDBack: 'tempURL',
              NIDFront: 'tempURL',
              phone: fields.phoneNumber,
              pin: fields.pin,
              licenseNumber: fields.licenseNumber,
              owner: req.user,
            };

            const newDriver = await axios
              .post(
                'http://44.202.73.200:8003/api/v1/driver/add',
                newDriverPayload
              )
              .catch(function (error) {
                if (error.errno == -111) {
                  profiler.done({
                    message: 'Driver Service Not Responding',
                    level: 'error',
                    actionBy: req.user.id,
                  });
                  return next(
                    new ErrorHandler('Driver Service Not Responding')
                  );
                } else {
                  profiler.done({
                    message: error.response.data.message,
                    level: 'error',
                    actionBy: req.user.id,
                  });

                  return next(new ErrorHandler(error.response.data.message));
                }
              });
            if (newDriver) {
              const driver = await Driver.findById(newDriver.data.user._id);
              const resultofDriverLicenseUpload = await uploadFile(
                drivingLicense
              );

              const resultOfDriverNIDBackUpload = await uploadFile(NIDBack);
              const resultOfDriverNIDFrontUpload = await uploadFile(NIDFront);
              driver.driverLicense = resultofDriverLicenseUpload.Key;
              driver.NIDBack = resultOfDriverNIDBackUpload.Key;
              driver.NIDFront = resultOfDriverNIDFrontUpload.Key;

              await driver.save({ validateBeforeSave: false });
              const owner = req.user;
              owner.drivers.push(driver);
              owner.save();
              res.status(200).json({
                success: true,
                message: 'Driver Account created successfully',
                driver,
              });
              profiler.done({
                message: `Created Driver ${driver.id} by Authority ${owner.id}`,
              });
            }
          } else {
            profiler.done({
              message: driverValidity.data.message,
              level: 'error',
              actionBy: req.user.id,
            });
            res.status(400).json({
              msg: driverValidity.data.message,
            });
          }
        } else {
          profiler.done({
            message: `Please provide all Informations correctly`,
            level: 'error',
            actionBy: req.user.id,
          });
          return next(
            new ErrorHandler(`Please provide all Informations correctly`)
          );
        }
      } catch (error) {
        profiler.done({
          message: error,
          level: 'error',
          actionBy: req.user.id,
        });
        return next(
          new ErrorHandler('Please provide all Informations correctly')
        );
      } finally {
        try {
          deleteFile(drivingLicense.filepath);
          deleteFile(NIDBack.filepath);
          deleteFile(NIDFront.filepath);
        } catch (error) {}
      }
    })
    .on('fileBegin', function (name, file) {
      file.newFilename = uuid();
      file.filepath =
        path.join(__dirname, '../') +
        Date.now() +
        file.newFilename +
        '.' +
        file.mimetype.split('/').pop();
    })
    .on('file', function (name, file) {});
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

exports.getAllDrivers = catchAsyncErrors(async (req, res, next) => {
  const profiler = logger.startTimer();
  const ownerWithDrivers = await User.findById(req.user.id)
    .select('drivers')
    .populate('drivers');

  profiler.done({
    message: `Authority requested its drivers' information `,
    level: 'info',
    actionBy: req.user.id,
  });
  res.status(200).json({
    success: true,
    drivers: ownerWithDrivers.drivers,
  });
});
exports.getAllRoutes = catchAsyncErrors(async (req, res, next) => {
  const profiler = logger.startTimer();
  const ownerWithRoutes = await User.findById(req.user.id)
    .select('routes')
    .populate('routes');

  profiler.done({
    message: `Authority requested its drivers' information `,
    level: 'info',
    actionBy: req.user.id,
  });
  res.status(200).json({
    success: true,
    routes: ownerWithRoutes.routes,
  });
});

exports.addBus = catchAsyncErrors(async (req, res, next) => {
  const profiler = logger.startTimer();

  console.log(req.user.routes.length);
  if (req.user.routes.length == 0) {
    profiler.done({
      message: "Tried to add bus while there's no route added",
      level: 'error',
      actionBy: req.user.id,
    });
    return next(
      new ErrorHandler('Please add at least one route before adding Bus')
    );
  } else {
    var form = new formidable.IncomingForm();
    form.multiples = true;
    form.maxFileSize = 5 * 1024 * 1024; // 5MB
    form
      .parse(req, async (err, fields, files) => {
        if (err) {
          profiler.done({
            message: error,
            level: 'error',
            actionBy: req.user.id,
          });

          return res.status(400).json({
            status: 'Fail',
            message: 'There was an error parsing the files',
            error: err,
          });
        }
        const { busName, busLicenseNumber, engineNumber, seatLayout, routeId } =
          fields;
        const { routePermit, busLicenseDoc } = files;

        try {
          if (
            isFileValid(routePermit) &&
            isFileValid(busLicenseDoc) &&
            busName &&
            busLicenseNumber &&
            engineNumber &&
            seatLayout &&
            routeId
          ) {
            if (checkValidRoute(routeId, req.user.id)) {
            } else {
              profiler.done({
                message: 'Invalid route id' + routeId + ' given ',
                level: 'error',
                actionBy: req.user.id,
              });
            }
            const validBusPayload = {
              busNo: busLicenseNumber,
              engNo: engineNumber,
              ownerName: req.user.name,
            };

            const busValidity = await axios
              .post(
                'http://44.202.73.200:8006/api/v1/crosscheck/bus',
                validBusPayload
              )
              .catch(function (error) {
                profiler.done({
                  message: error,
                  level: 'error',
                  actionBy: req.user.id,
                });
                return next(
                  new ErrorHandler('Validation Service not Responding')
                );
              });
            if (busValidity.data.result == true) {
              const newBusPayload = {
                name: fields.driverName,
                driverLicense: 'tempURL',
                NIDBack: 'tempURL',
                NIDFront: 'tempURL',
                phone: fields.phoneNumber,
                pin: fields.pin,
                licenseNumber: fields.licenseNumber,
                owner: req.user,
              };

              const newBus = await axios
                .post(
                  'http://44.202.73.200:8003/api/v1/driver/add',
                  newBusPayload
                )
                .catch(function (error) {
                  if (error.errno == -111) {
                    profiler.done({
                      message: 'Bus Service Not Responding',
                      level: 'error',
                      actionBy: req.user.id,
                    });
                    return next(new ErrorHandler('Bus Service Not Responding'));
                  } else {
                    profiler.done({
                      message: error.response.data.message,
                      level: 'error',
                      actionBy: req.user.id,
                    });

                    return next(new ErrorHandler(error.response.data.message));
                  }
                });
              if (newBus) {
                const bus = await Bus.findById(newBus.data.user._id);
                const resultOfRoutePermitUpload = await uploadFile(routePermit);

                const resultOfBusLicenseDocUpload = await uploadFile(
                  busLicenseDoc
                );
                bus.routePermit = resultOfRoutePermitUpload.Key;
                bus.busLicense = resultOfBusLicenseDocUpload.Key;

                await bus.save({ validateBeforeSave: false });
                const owner = req.user;
                owner.buses.push(bus);
                owner.save();
                res.status(200).json({
                  success: true,
                  message: 'Driver Account created successfully',
                  bus,
                });
                profiler.done({
                  message: `Created Bus ${bus.id} by Authority ${owner.id}`,
                });
              }
            } else {
              profiler.done({
                message: busValidity.data.message,
                level: 'error',
                actionBy: req.user.id,
              });
              res.status(400).json({
                msg: busValidity.data.message,
              });
            }
          } else {
            profiler.done({
              message: `Please provide all Informations correctly`,
              level: 'error',
              actionBy: req.user.id,
            });
            return next(
              new ErrorHandler(`Please provide all Informations correctly`)
            );
          }
        } catch (error) {
          profiler.done({
            message: error,
            level: 'error',
            actionBy: req.user.id,
          });
          return next(
            new ErrorHandler('Please provide all Informations correctly')
          );
        } finally {
          try {
            deleteFile(routePermit.filepath);
            deleteFile(busLicenseDoc.filepath);
          } catch (error) {}
        }
      })
      .on('fileBegin', function (name, file) {
        file.newFilename = uuid();
        file.filepath =
          path.join(__dirname, '../') +
          Date.now() +
          file.newFilename +
          '.' +
          file.mimetype.split('/').pop();
      })
      .on('file', function (name, file) {});
  }
});

//check valid route
const checkValidRoute = async (routeId, authorityId) => {
  let route = await BusRoute.findById(routeId).select('authorityId');

  if (route && route.authorityId == authorityId) return true;
  else return false;
};
