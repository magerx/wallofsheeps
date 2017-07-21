/**
 * File:           app.js
 * Author:         magerx@paxmac.org
 * Last modified:  2017/07/14
 * */

var winston = require("winston");
var datetime = require("node-datetime");

var logger = new (winston.Logger)({
    transports: [
        new (winston.transports.Console)({
            timestamp: function () {
                var dt = datetime.create();
                return dt.format('Y-m-d H:M:S');
            },
            formatter: function (options) {
                // Return string will be passed to logger.
                return winston.config.colorize(
                    options.level,
                    "[" + options.level.toUpperCase() + "] " + "[" + options.timestamp() + "] " + (options.message ? options.message : ""))
            }
        })
    ]
});

module.exports = logger;
