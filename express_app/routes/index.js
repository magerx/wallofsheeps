module.exports = function (io) {
    var express = require('express');
    var thinky = require('thinky')();
    var User = require('../models/user');

    var router = express.Router();

    User.changes().then(function (user) {
        user.each(function (error, doc) {
            io.sockets.emit("new-sheep-catch-event", doc);
        });
    });

    router.get('/', function (req, res, next) {
        var list = [],
            r = thinky.r;

        User.orderBy({index: r.desc("id")}).run().then(function (result) {
            for (var i = 0, len = result.length; i < len; i++) {
                list.push(result[i]);
                //console.log(result[i]);
            }
            res.render('index', {lists: list});
        })
    });

    router.get('/photo/', function (req, res, next) {
        var list = [],
            r = thinky.r;

        User.orderBy({index: r.desc("id")}).run().then(function (result) {
            for (var i = 0, len = result.length; i < len; i++) {
                list.push(result[i]);
                //console.log(result[i]);
            }
            res.render('new_photo', {lists: list});
        })
    });
    return router;
}


// TestCase
// for (var i = 0; i < 10; i++){
//
//     var userinfo = new User({
//         timestamp: String(new Date().getTime()),
//         shost: 'shost',
//         sIP: 'sIP',
//         dIP: 'dIP',
//         sPort: 'sPort',
//         dPort: 'dPort',
//         protocol: 'protocol',
//         login: 'login',
//         password: 'pws'
//     });
//
//     userinfo.save().then(function() {
//         console.log('[-] Save to RethinkDB or not: %s', userinfo.isSaved());
//         console.log('[-] Data id: %s', userinfo.id);
//         console.log(userinfo);
//     });
//
// }
