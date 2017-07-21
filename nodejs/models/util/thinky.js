/*File:           thinkyz.js */
/*Author:         magerx@paxmac.org*/
/*Last modified:  2017/07/05*/

var thinky = require("thinky")({
  // thinky"s options

  // min: the minimum number of connections in the pool, default 50

  // max: the maximum number of connections in the pool, default 1000

  // bufferSize: the minimum number of connections available in the pool,
  // default 50

  // timeoutError: number of milliseconds before reconnecting in case of an
  // error, default 1000

  // timeoutGb: number of milliseconds before removing a connection that has
  // not been used, default 60*60*1000

  // host: host of the RethinkDB server, default "localhost"

  // port: client port of the RethinkDB server, default 28015

  // db: the default database, default "test"

  // authKey: the authentification key to the RethinkDB server, default ""
});

module.exports = thinky;
