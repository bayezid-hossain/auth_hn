const express = require('express');

const errorMiddleware = require('./middleware/error');
const app = express();
var bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');

app.use(express.json());
app.use(cookieParser());
app.use(
  bodyParser.urlencoded({
    extended: false,
  })
);
app.use(bodyParser.json());
//Route Imports
const authRoute = require('./routes/authRoute');
app.use('', authRoute);

//Middleware for errors
app.use(errorMiddleware);

module.exports = app;
