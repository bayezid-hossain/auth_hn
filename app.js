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
app.get('/hello', (req, res) => {
  res.send('GET Request Called');
});
//Route Imports
const busOwnerRoute = require('./routes/busOwnerRoute');
app.use('', busOwnerRoute);

//Middleware for errors
app.use(errorMiddleware);

module.exports = app;
