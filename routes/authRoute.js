const express = require('express');
const {
  login,
  verifyOtp,
  logout,
  loginUser,
  registerBusOwner,
} = require('../controllers/authController');
const {
  authorizeRoles,
  approvalStatus,

  isLoggedInUser,
  isAuthenticatedUser,
  setUserType,
} = require('../middleware/auth');

const router = express.Router();

router
  .route('/api/v1/auth/busowner/login')
  .post(setUserType('busOwner'), loginUser);
router
  .route('/api/v1/auth/driver/login')
  .post(setUserType('driver'), loginUser);

router.route('/api/v1/auth/busowner/register').post(registerBusOwner);
router.route('/api/v1/auth/admin/login').post(setUserType('admin'), loginUser);
router.route('/api/v1/auth/verify').post(isAuthenticatedUser, verifyOtp);
router.route('/api/v1/auth/logout').get(isLoggedInUser, logout);
module.exports = router;
