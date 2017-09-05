/**
 * File:           app.js
 * Author:         magerx@paxmac.org
 * Last modified:  2017/07/05
 * */

var express = require("express");
var path = require("path");
var favicon = require("serve-favicon");
var logger = require("morgan");
var cookieParser = require("cookie-parser");
var bodyParser = require("body-parser");
var socketIO = require("socket.io");
var routes = require("./routes/index");

var app = express();
var io = socketIO();

app.io = io;

// view engine setup
app.set("views", path.join(__dirname, "views"));
app.set("view engine", "ejs");

app.use(favicon(__dirname + "/static/images/logo.png", options = {}));
app.use(logger("dev"));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended: false}));
app.use(cookieParser());
app.use(express.static("static"));
app.use("/", routes(app.io));

// catch 404 and forward to error handler
app.use(function (req, res, next) {
    var err = new Error("Page Not Found");
    err.status = 404;
    // next(err);
});

// production error handler
app.use(function (err, req, res, next) {
    res.status(err.status);
    res.render("error", {
        message: err.message,
        error: {}
    });
    next(err);
});

module.exports = app;
