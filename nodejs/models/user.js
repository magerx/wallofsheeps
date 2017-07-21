/*File:           user.js */
/*Author:         magerx@paxmac.org*/
/*Last modified:  2017/07/05*/

var thinky = require(__dirname + "/util/thinky.js");

var type = thinky.type;

var User = thinky.createModel("User", {
    id: type.string(),
    timestamp: type.string(),
    shost: type.string(),
    sIP: type.string(),
    dIP: type.string(),
    sPort: type.number(),
    dPort: type.number(),
    protocol: type.string(),
    login: type.string(),
    password: type.string(),
    cookies: type.string(),
    domain: type.string(),
    picture: type.string()
});

module.exports = User;
