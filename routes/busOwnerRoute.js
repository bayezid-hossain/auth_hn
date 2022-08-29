const express = require('express');
const {
  registerBusOwner,
  uploadCompanyInfo,
  uploadBusOwnerInfo,
  loginBusOwner,
  verifyOtp,
  getUserDetails,
  createRoute,
  addDriver,
  addBus,
  logout,
  getAllDrivers,
  getAllRoutes,
} = require('../controllers/busOwnerController');
const {
  authorizeRoles,
  approvalStatus,
  isLoggedInUser,
  isAuthenticatedUser,
} = require('../middleware/auth');

const router = express.Router();

router.route('/api/v1/busowner/register').post(registerBusOwner);
router.route('/api/v1/busowner/login').post(loginBusOwner);
router.route('/api/v1/busowner/verify').post(isAuthenticatedUser, verifyOtp);
router.route('/api/v1/busowner/me').get(isLoggedInUser, getUserDetails);
router
  .route('/api/v1/busowner/upload/companyinfo')
  .post(
    isLoggedInUser,
    [approvalStatus('pending'), authorizeRoles('[busOwner]')],
    uploadCompanyInfo
  );

router
  .route('/api/v1/busowner/upload/personalinfo')
  .post(
    isLoggedInUser,
    [approvalStatus('pending'), authorizeRoles('[busOwner]')],
    uploadBusOwnerInfo
  );
router
  .route('/api/v1/busowner/routes/add')
  .post(
    isLoggedInUser,
    [approvalStatus('approved'), authorizeRoles('[busOwner]')],
    createRoute
  );
router
  .route('/api/v1/busowner/registerdriver')
  .post(
    isLoggedInUser,
    [approvalStatus('approved'), authorizeRoles('[busOwner]')],
    addDriver
  );
//router.route('/users/:id').get(authorizeRoles('admin'),fetchUserInformation);

router
  .route('/api/v1/busowner/addbus')
  .post(
    isLoggedInUser,
    [approvalStatus('approved'), authorizeRoles('[busOwner]')],
    addBus
  );
router
  .route('/api/v1/busowner/drivers')
  .get(
    isLoggedInUser,
    [approvalStatus('approved'), authorizeRoles('[busOwner]')],
    getAllDrivers
  );

router
  .route('/api/v1/busowner/routes')
  .get(
    isLoggedInUser,
    [approvalStatus('approved'), authorizeRoles('[busOwner]')],
    getAllRoutes
  );

router.route('/api/v1/busowner/logout').get(isLoggedInUser, logout);
module.exports = router;
