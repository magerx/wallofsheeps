/*jslint node: true */
/*jshint esnext: true */

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
        if (userFields.indexOf(keys[i].toLowerCase()) != -1) {
            account = data[keys[i]];
        }
    }

    // for (var i of userFields) {
    //   if (data.hasOwnProperty(i)) {
    //     account = data[i];
    //   }
    // }

    // if (account === null && Object.keys(data).length !== 0) {
    //   console.log('[-] Can not find account pattern.');
    //   console.log('[-] Check querystring in %j', data);
    // }

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
        if (passFields.indexOf(keys[i].toLowerCase()) != -1) {
            password = data[keys[i]];
        }
    }

    // for (var i of passFields) {
    //   if (data.hasOwnProperty(i)) {
    //     password = data[i];
    //   }
    // }

    // if (password === null && Object.keys(data).length !== 0) {
    //   console.log('[-] Can not find password pattern.');
    //   console.log('[-] Check querystring in %j', data);
    // }

    return password;
}

function HTTPDataParser(packet) {
    var linkLayer = packet.payload;
    var networkLayer = packet.payload.payload;
    var tranportLayer = packet.payload.payload.payload;

    var data = tranportLayer.data.toString('ascii');

    // DEBUG usage
    // console.log(data);

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

    // console.log(data);
    var isPOST = data.indexOf('POST');
    var isGET = data.indexOf('GET');

    if (isPOST == 0 || isGET == 0) {
        // HTTP POST request packet
        // HTTP header with content

        var headerContent = data.split('\r\n');

        // console.log(data);

        // console.log(headerContent);

        // get cookie
        var cookies = null;
        var picture = null;
        for (var header in headerContent) {
            if (headerContent[header].indexOf('Cookie:') == 0) {
                cookies = headerContent[header].split(': ')[1];
            }
            else if (headerContent[header].indexOf('Host:') == 0) {
                domain = headerContent[header].split(': ')[1];
            }
        }
        // returns the last element (querystring) and removes it from the array
        if (isPOST == 0) {
            var Content = headerContent.pop();
        }

        else {
            var uri = headerContent[0].split(' ')[1]; // get querystring for get method
            var Content = uri.split('?')[1];

            var pattern = new RegExp("\.(jpg|png|gif|jpeg|bmp)$");

            if (pattern.test(uri.split('?')[0].toLowerCase())) {
                picture = 'http://' + domain + uri;
                request.head(picture, function (error, response) {
                    if (!error && response.statusCode == 200) {
                        picture = picture;
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
    // } else if (isGET > -1) {
    //   // HTTP GET request packet
    //
    // }
    // else {
    //     // Small packets size may be the remaining of last packet.
    //
    //     if (tranportLayer.data_bytes < 200) {
    //         // console.log(data);
    //         // var headerContent = data.split('\r\n');
    //         // var lastContent = headerContent.pop();
    //         // var sheepInfo = qs.parse(lastContent);
    //         // // Because last HTTP POST request packet size is too much larger.
    //         // // It may lead packet been fragmented and querystring will be in
    //         // // next packet. In the next packet size will extremely small
    //         // // and querystring may stay in here.
    //         // var account = GetHTTPLoginAccount(sheepInfo);
    //         // var password = GetHTTPLoginPassword(sheepInfo);
    //         // ConsolePrinter(shost, saddr, daddr, sport, dport, account, password);
    //         // var obj = {};
    //         //
    //         // obj.shost = shost;
    //         // obj.saddr = saddr;
    //         // obj.daddr = daddr;
    //         // obj.sport = sport;
    //         // obj.dport = dport;
    //         // obj.user = account;
    //         // obj.pass = password;
    //         //
    //         // return obj;
    //     }
    //
    // }

}

function GetFTPPOPLoginPass(packet) {
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

    var ftpUserRE = /^USER (.*)$/i;
    var ftpPASSRE = /^PASS (.*)$/i;
    var splitted = data.split('\r\n');

    // Check the first element in splitted has user/pass or not case-insensitive
    var isUSER = splitted[0].toLowerCase().indexOf('user');
    var isPASS = splitted[0].toLowerCase().indexOf('pass');

    if (isUSER > -1) {
        var user = splitted[0].match(ftpUserRE);
        if (user !== null) {
            ConsolePrinter(shost, saddr, daddr, sport, dport, user[1], null, null);
            var objWithUser = {};

            objWithUser.shost = shost;
            objWithUser.srcIP = saddr;
            objWithUser.dstIP = daddr;
            objWithUser.sport = sport;
            objWithUser.dport = dport;
            objWithUser.user = user[1];
            objWithUser.pass = null;

            return objWithUser;
        }
    }

    if (isPASS > -1) {
        var pass = splitted[0].match(ftpPASSRE);
        if (pass !== null) {
            ConsolePrinter(shost, saddr, daddr, sport, dport, null, pass[1]);
            var objWithPass = {};

            objWithPass.shost = shost;
            objWithPass.srcIP = saddr;
            objWithPass.dstIP = daddr;
            objWithPass.sport = sport;
            objWithPass.dport = dport;
            objWithPass.user = null;
            objWithPass.pass = pass[1];

            return objWithPass;
        }
    }

    // Another way to check USER and PASS but I think this is inefficient.
    // if (isUSER > -1 || isPASS > -1) {
    //   var user = splitted[0].match(ftpUserRE);
    //   var pass = splitted[0].match(ftpPASSRE);
    //   if (user !== null) {
    //     ConsolePrinter(shost, saddr, daddr, sport, dport, user[1], null);
    //   }
    //   if (pass !== null) {
    //     ConsolePrinter(shost, saddr, daddr, sport, dport, null, pass[1]);
    //   }
    // }

}

function GetIMAPLoginPass(packet) {
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

    var imapUserPassRE = /^LOGIN (.*) (.*)$/i;

    // console.log(data);
    var splitted = data.split('\r\n');

    // Check the first element in splitted has login or not case-insensitive
    var isLogin = splitted[0].toLowerCase().indexOf('login');

    if (isLogin > -1) {
        var login = splitted[0].match(imapUserPassRE);
        ConsolePrinter(shost, saddr, daddr, sport, dport, login[1], login[2]);

        var obj = {};

        obj.shost = shost;
        obj.srcIP = saddr;
        obj.dstIP = daddr;
        obj.sport = sport;
        obj.dport = dport;
        obj.user = login[1];
        obj.pass = login[2];

        return obj;
    }
}

function ConsolePrinter(shost, srcIP, dstIP, sport, dport, account, password, cookies, domain) {
    if (account !== null) {
        console.log('[%s:%d -> %s:%d] %s Account: %s', srcIP, sport, dstIP, dport, protocol[dport], account, cookies, domain);
    }

    if (password !== null) {
        console.log('[%s:%d -> %s:%d] %s Password: %s', srcIP, sport, dstIP, dport, protocol[dport], password, cookies, domain);
    }
}

function SavetoRethinkDB(beSaved) {
    // If HTTPDataParser can not get cookie and password given null do NOT save
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
    console.log('  _       _____    __    __       ____  ______   _____ __  __________________')
    console.log('| |     / /   |  / /   / /      / __ \\/ ____/  / ___// / / / ____/ ____/ __ \\')
    console.log('| | /| / / /| | / /   / /      / / / / /_      \\__ \\/ /_/ / __/ / __/ / /_/ /')
    console.log('| |/ |/ / ___ |/ /___/ /___   / /_/ / __/     ___/ / __  / /___/ /___/ ____/ ')
    console.log('|__/|__/_/  |_/_____/_____/   \\____/_/       /____/_/ /_/_____/_____/_/      ')
}

function StartCapture() {
    WelcomeMessage()
    if (process.getuid() !== 0) {
        console.log('[*] Please run as root');
        process.exit(1);
    }

    if (!argv.i) {
        console.log('[*] Specify an interface name for capturing.');
        process.exit(1);
    } else {
        var beSaved = {};
        var pcapSession = pcap.createSession(argv.i, 'ip proto \\tcp');

        console.log('[*] Using interface: %s', pcapSession.device_name);

        pcapSession.on('packet', function (rawPacket) {

            var packet = pcap.decode.packet(rawPacket);

            // console.log(packet);

            var tranportLayer = packet.payload.payload.payload;
            var isHTTP = tranportLayer.dport === 80 && tranportLayer.data !== null;
            var isFTP = tranportLayer.dport === 21 && tranportLayer.data !== null;
            var isPOP3 = tranportLayer.dport === 110 && tranportLayer.data !== null;
            var isIMAP = tranportLayer.dport === 143 && tranportLayer.data !== null;

            // For all protocols we interested and also data not null
            if (isHTTP) {
                var HTTPInfoObj = new HTTPDataParser(packet);
                if (argv.s && HTTPInfoObj) {
                    SavetoRethinkDB(HTTPInfoObj);
                }

            } else if (isFTP) {
                var FTPInfoObj = new GetFTPPOPLoginPass(packet);

                if (argv.s && FTPInfoObj) {
                    if (FTPInfoObj.user !== null) {
                        beSaved.shost = FTPInfoObj.shost;
                        beSaved.saddr = FTPInfoObj.saddr;
                        beSaved.daddr = FTPInfoObj.daddr;
                        beSaved.sport = FTPInfoObj.sport;
                        beSaved.dport = FTPInfoObj.dport;
                        beSaved.user = FTPInfoObj.user;
                    }

                    if (FTPInfoObj.pass !== null) {
                        beSaved.shost = FTPInfoObj.shost;
                        beSaved.saddr = FTPInfoObj.saddr;
                        beSaved.daddr = FTPInfoObj.daddr;
                        beSaved.sport = FTPInfoObj.sport;
                        beSaved.dport = FTPInfoObj.dport;
                        beSaved.pass = FTPInfoObj.pass;
                    }

                    if (beSaved.user !== undefined && beSaved.pass !== undefined) {
                        SavetoRethinkDB(beSaved);
                        beSaved = {};
                    }

                }
            } else if (isPOP3) {
                var POP3InfoObj = new GetFTPPOPLoginPass(packet);
                if (argv.s && POP3InfoObj) {
                    if (POP3InfoObj.user !== null) {
                        beSaved.shost = POP3InfoObj.shost;
                        beSaved.saddr = POP3InfoObj.saddr;
                        beSaved.daddr = POP3InfoObj.daddr;
                        beSaved.sport = POP3InfoObj.sport;
                        beSaved.dport = POP3InfoObj.dport;
                        beSaved.user = POP3InfoObj.user;
                    }

                    if (POP3InfoObj.pass !== null) {
                        beSaved.shost = POP3InfoObj.shost;
                        beSaved.saddr = POP3InfoObj.saddr;
                        beSaved.daddr = POP3InfoObj.daddr;
                        beSaved.sport = POP3InfoObj.sport;
                        beSaved.dport = POP3InfoObj.dport;
                        beSaved.pass = POP3InfoObj.pass;
                    }

                    if (beSaved.user !== undefined && beSaved.pass !== undefined) {
                        SavetoRethinkDB(beSaved);
                        beSaved = {};
                    }
                }
            } else if (isIMAP) {
                var IMAPInfoObj = new GetIMAPLoginPass(packet);
                if (argv.s && IMAPInfoObj) {
                    SavetoRethinkDB(IMAPInfoObj);
                }
            }
        });
    }
}

StartCapture();