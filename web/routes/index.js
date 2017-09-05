/*File:           index.js */
/*Author:         magerx@paxmac.org*/
/*Last modified:  2017/07/05*/

module.exports = function (io) {
    var express = require("express");
    var thinky = require("thinky")();
    var User = require("../models/user");
    var router = express.Router();

    io.on("connection", function (socket) {
        User.changes().then(function (user) {
            user.each(function (error, doc) {
                socket.emit("new-sheep", doc);
            })
        });
    });

    // index
    router.get("/", function (req, res) {
        var list = [],
            r = thinky.r;

        User.orderBy({index: r.desc("id")}).run().then(function (result) {
            for (var i = 0, len = result.length; i < len; i++) {
                list.push(result[i]);
            }
            res.render("index", {lists: list});
        })
    });

    //photo
    router.get("/photo/", function (req, res) {
        var list = [],
            r = thinky.r;

        User.orderBy({index: r.desc("id")}).run().then(function (result) {
            for (var i = 0, len = result.length; i < len; i++) {
                list.push(result[i]);
            }
            res.render("photo", {lists: list});
        })
    });

    return router;
};

