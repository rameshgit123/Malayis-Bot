/*
 * Copyright 2016-present, Facebook, Inc.
 * All rights reserved.
 *
 * This source code is licensed under the license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

/* jshint node: true, devel: true */
'use strict';

const
  bodyParser = require('body-parser'),
  config = require('config'),
  crypto = require('crypto'),
  express = require('express'),
  https = require('https'),
  request = require('request');
//facebook sdk for get user inforamtion.
var sdk = require('facebook-node-sdk');
var fb = new sdk({
    appId: config.get('AppId'),
    secret: config.get('appSecret')
}).setAccessToken(config.get('pageAccessToken'));

var app = express();
app.set('port', process.env.PORT || 5000);
app.set('view engine', 'ejs');
app.use(bodyParser.json({ verify: verifyRequestSignature }));
app.use(express.static('public'));
var allowCrossDomain = function (req, res, next) {
    res.header("Access-Control-Allow-Origin", "*");
    res.header("Access-Control-Allow-Headers", "X-Requested-With");
    next();
}
app.use(allowCrossDomain);


/*
 * Be sure to setup your config values before running this code. You can 
 * set them using environment variables or modifying the config file in /config.
 *
 */

// App Secret can be retrieved from the App Dashboard
const APP_SECRET = (process.env.MESSENGER_APP_SECRET) ?
  process.env.MESSENGER_APP_SECRET :
  config.get('appSecret');

// Arbitrary value used to validate a webhook
const VALIDATION_TOKEN = (process.env.MESSENGER_VALIDATION_TOKEN) ?
  (process.env.MESSENGER_VALIDATION_TOKEN) :
  config.get('validationToken');

// Generate a page access token for your page from the App Dashboard
const PAGE_ACCESS_TOKEN = (process.env.MESSENGER_PAGE_ACCESS_TOKEN) ?
  (process.env.MESSENGER_PAGE_ACCESS_TOKEN) :
  config.get('pageAccessToken');

// URL where the app is running (include protocol). Used to point to scripts and 
// assets located at this address. 
const SERVER_URL = (process.env.SERVER_URL) ?
  (process.env.SERVER_URL) :
  config.get('serverURL');

if (!(APP_SECRET && VALIDATION_TOKEN && PAGE_ACCESS_TOKEN && SERVER_URL)) {
    console.error("Missing config values");
    process.exit(1);
}


app.get('/sendmessage', function (req, res) {
    sendTextMessage(req.query['senderid'], "Data submited");
    checkstatus(req.query['senderid'], "Webview_Items", req.query['items'], "");
    res.sendStatus(200);
});

/*
 * Use your own validation token. Check that the token used in the Webhook 
 * setup is the same token used here.
 *
 */
app.get('/webhook', function (req, res) {
    if (req.query['hub.mode'] === 'subscribe' &&
        req.query['hub.verify_token'] === VALIDATION_TOKEN) {
        console.log("Validating webhook");
        res.status(200).send(req.query['hub.challenge']);
    } else {
        console.error("Failed validation. Make sure the validation tokens match.");
        res.sendStatus(403);
    }
});


/*
 * All callbacks for Messenger are POST-ed. They will be sent to the same
 * webhook. Be sure to subscribe your app to your page to receive callbacks
 * for your page. 
 * https://developers.facebook.com/docs/messenger-platform/product-overview/setup#subscribe_app
 *
 */
app.post('/webhook', function (req, res) {
    var data = req.body;

    // Make sure this is a page subscription
    if (data.object == 'page') {
        // Iterate over each entry
        // There may be multiple if batched
        data.entry.forEach(function (pageEntry) {
            var pageID = pageEntry.id;
            var timeOfEvent = pageEntry.time;

            // Iterate over each messaging event
            pageEntry.messaging.forEach(function (messagingEvent) {
                if (messagingEvent.optin) {
                    receivedAuthentication(messagingEvent);
                } else if (messagingEvent.message) {
                    receivedMessage(messagingEvent);
                } else if (messagingEvent.delivery) {
                    receivedDeliveryConfirmation(messagingEvent);
                } else if (messagingEvent.postback) {
                    receivedPostback(messagingEvent);
                } else if (messagingEvent.read) {
                    receivedMessageRead(messagingEvent);
                } else if (messagingEvent.account_linking) {
                    receivedAccountLink(messagingEvent);
                } else {
                    console.log("Webhook received unknown messagingEvent: ", messagingEvent);
                }
            });
        });

        // Assume all went well.
        //
        // You must send back a 200, within 20 seconds, to let us know you've 
        // successfully received the callback. Otherwise, the request will time out.
        res.sendStatus(200);
    }
});

/*
 * This path is used for account linking. The account linking call-to-action
 * (sendAccountLinking) is pointed to this URL. 
 * 
 */
app.get('/authorize', function (req, res) {
    var accountLinkingToken = req.query.account_linking_token;
    var redirectURI = req.query.redirect_uri;

    // Authorization Code should be generated per user by the developer. This will 
    // be passed to the Account Linking callback.
    var authCode = "1234567890";

    // Redirect users to this URI on successful login
    var redirectURISuccess = redirectURI + "&authorization_code=" + authCode;

    res.render('authorize', {
        accountLinkingToken: accountLinkingToken,
        redirectURI: redirectURI,
        redirectURISuccess: redirectURISuccess
    });
});

/*
 * Verify that the callback came from Facebook. Using the App Secret from 
 * the App Dashboard, we can verify the signature that is sent with each 
 * callback in the x-hub-signature field, located in the header.
 *
 * https://developers.facebook.com/docs/graph-api/webhooks#setup
 *
 */
function verifyRequestSignature(req, res, buf) {
    var signature = req.headers["x-hub-signature"];

    if (!signature) {
        // For testing, let's log an error. In production, you should throw an 
        // error.
        console.error("Couldn't validate the signature.");
    } else {
        var elements = signature.split('=');
        var method = elements[0];
        var signatureHash = elements[1];

        var expectedHash = crypto.createHmac('sha1', APP_SECRET)
                            .update(buf)
                            .digest('hex');

        if (signatureHash != expectedHash) {
            throw new Error("Couldn't validate the request signature.");
        }
    }
}

/*
 * Authorization Event
 *
 * The value for 'optin.ref' is defined in the entry point. For the "Send to 
 * Messenger" plugin, it is the 'data-ref' field. Read more at 
 * https://developers.facebook.com/docs/messenger-platform/webhook-reference/authentication
 *
 */
function receivedAuthentication(event) {
    var senderID = event.sender.id;
    var recipientID = event.recipient.id;
    var timeOfAuth = event.timestamp;

    // The 'ref' field is set in the 'Send to Messenger' plugin, in the 'data-ref'
    // The developer can set this to an arbitrary value to associate the 
    // authentication callback with the 'Send to Messenger' click event. This is
    // a way to do account linking when the user clicks the 'Send to Messenger' 
    // plugin.
    var passThroughParam = event.optin.ref;

    console.log("Received authentication for user %d and page %d with pass " +
      "through param '%s' at %d", senderID, recipientID, passThroughParam,
      timeOfAuth);

    // When an authentication is received, we'll send a message back to the sender
    // to let them know it was successful.
    sendTextMessage(senderID, "Authentication successful");
}

/*
 * Message Event
 *
 * This event is called when a message is sent to your page. The 'message' 
 * object format can vary depending on the kind of message that was received.
 * Read more at https://developers.facebook.com/docs/messenger-platform/webhook-reference/message-received
 *
 * For this example, we're going to echo any text that we get. If we get some 
 * special keywords ('button', 'generic', 'receipt'), then we'll send back
 * examples of those bubbles to illustrate the special message bubbles we've 
 * created. If we receive a message with an attachment (image, video, audio), 
 * then we'll simply confirm that we've received the attachment.
 * 
 */
function receivedMessage(event) {
    var senderID = event.sender.id;
    var recipientID = event.recipient.id;
    var timeOfMessage = event.timestamp;
    var message = event.message;


    var isEcho = message.is_echo;
    var messageId = message.mid;
    var appId = message.app_id;
    var metadata = message.metadata;

    // You may get a text or attachment but not both
    var messageText = message.text;
    var messageAttachments = message.attachments;
    var quickReply = message.quick_reply;

    if (isEcho) {
        return;
    } else if (quickReply) {
        var quickReplyPayload = quickReply.payload;

        sendTextMessage(senderID, "Quick reply tapped");
        return;
    }

    if (messageText) {       

        checkstatus(senderID, messageText, "text", "");

    } else if (messageAttachments) {
        checkstatus(senderID, "file", messageAttachments[0].type, messageAttachments);
    }
}


/*
 * Delivery Confirmation Event
 *
 * This event is sent to confirm the delivery of a message. Read more about 
 * these fields at https://developers.facebook.com/docs/messenger-platform/webhook-reference/message-delivered
 *
 */
function receivedDeliveryConfirmation(event) {
    var senderID = event.sender.id;
    var recipientID = event.recipient.id;
    var delivery = event.delivery;
    var messageIDs = delivery.mids;
    var watermark = delivery.watermark;
    var sequenceNumber = delivery.seq;

    if (messageIDs) {
        messageIDs.forEach(function (messageID) {

        });
    }

}


/*
 * Postback Event
 *
 * This event is called when a postback is tapped on a Structured Message. 
 * https://developers.facebook.com/docs/messenger-platform/webhook-reference/postback-received
 * 
 */
function receivedPostback(event) {
    var senderID = event.sender.id;
    var recipientID = event.recipient.id;
    var timeOfPostback = event.timestamp;

    // The 'payload' param is a developer-defined field which is set in a postback 
    // button for Structured Messages. 
    var payload = event.postback.payload;



    // When a postback is called, we'll send a message back to the sender to 
    // let them know it was successful
    if (payload == "USER_DEFINED_PAYLOAD") {

        var messageData = {
            recipient: {
                id: senderID
            },
            "message": {
                "attachment": {
                    "type": "template",
                    "payload": {
                        "template_type": "generic",
                        "elements": [{
                            "title": "Select Your Language",
                            "subtitle": "",
                            "buttons": [{
                                "type": "postback",
                                "title": "Melayu",
                                "payload": "Melayu"
                            }, {
                                "type": "postback",
                                "title": "普通话",
                                "payload": "Mandarin"
                            }, {
                                "type": "postback",
                                "title": "English",
                                "payload": "English"
                            }

                            ]
                        }]
                    }
                }
            }
        };
        callSendAPI(messageData);
    }
    else if (payload == "Melayu") {
        checkstatus(senderID, "Melayu_lang", "text", "");
    }
    else if (payload == "Mandarin") {
        checkstatus(senderID, "Mandarin_lang", "text", "");
    }
    else if (payload == "English") {
        checkstatus(senderID, "English_lang", "text", "");
    }
    else if (payload == "Purchased_YES") {
        checkstatus(senderID, "Purchased_YES", "text", "");
    }
    else if (payload == "Purchased_NO") {
        checkstatus(senderID, "Purchased_NO", "text", "");
    }
    else if (payload == "Invoices_YES") {
        checkstatus(senderID, "Invoices_YES", "text", "");
    }
    else if (payload == "Invoices_NO") {
        checkstatus(senderID, "Invoices_NO", "text", "");
    }
    else if (payload == "NOInvoices_YES") {
        checkstatus(senderID, "NOInvoices_YES", "text", "");
    }
    else if (payload == "NOInvoices_NO") {
        checkstatus(senderID, "NOInvoices_NO", "text", "");
    }

}

/*
 * Message Read Event
 *
 * This event is called when a previously-sent message has been read.
 * https://developers.facebook.com/docs/messenger-platform/webhook-reference/message-read
 * 
 */
function receivedMessageRead(event) {
    var senderID = event.sender.id;
    var recipientID = event.recipient.id;

    // All messages before watermark (a timestamp) or sequence have been seen.
    var watermark = event.read.watermark;
    var sequenceNumber = event.read.seq;

    //  console.log("Received message read event for watermark %d and sequence " +
    //    "number %d", watermark, sequenceNumber);
}

/*
 * Account Link Event
 *
 * This event is called when the Link Account or UnLink Account action has been
 * tapped.
 * https://developers.facebook.com/docs/messenger-platform/webhook-reference/account-linking
 * 
 */
function receivedAccountLink(event) {
    var senderID = event.sender.id;
    var recipientID = event.recipient.id;

    var status = event.account_linking.status;
    var authCode = event.account_linking.authorization_code;

    console.log("Received account link event with for user %d with status %s " +
      "and auth code %s ", senderID, status, authCode);
}


/*
 * Send a text message using the Send API.
 *
 */
function sendTextMessage(recipientId, messageText) {
    var messageData = {
        recipient: {
            id: recipientId
        },
        message: {
            text: messageText,
            metadata: "DEVELOPER_DEFINED_METADATA"
        }
    };

    callSendAPI(messageData);
}

//TranslatetoMandarin
function TranslatetoMandarin(p1, p2, p3, p4, callback) {
    request.post({
        //  "rejectUnauthorized": false,
        url: "https://www.googleapis.com/language/translate/v2",
        headers: { "X-HTTP-Method-Override": "GET" },
        form: {
            key: "AIzaSyCwayqygqF9p-4KBf_bP1LM1haaC-cPt_4",
            target: "zh-CN",
            q: "q1=" + p1 + ""
        }
    }, function (error, response, data) {
        if (!error && response.statusCode == 200) {
            // console.log(data);
            var items = JSON.parse(data);
            callback(items.data.translations[0].translatedText.split('=')[1]);
        } else {
            console.log("something went wrong" + error)
        }
    });

}

//TranslatetoMalay
function TranslatetoMalay(p1, p2, p3, p4, callback) {
    request.post({
        //  "rejectUnauthorized": false,
        url: "https://www.googleapis.com/language/translate/v2",
        headers: { "X-HTTP-Method-Override": "GET" },
        form: {
            key: "AIzaSyCwayqygqF9p-4KBf_bP1LM1haaC-cPt_4",
            target: "ms",
            q: "q1=" + p1 + ""
        }
    }, function (error, response, data) {
        if (!error && response.statusCode == 200) {
            // console.log(data);
            var items = JSON.parse(data);
            callback(items.data.translations[0].translatedText.split('=')[1]);
        } else {
            console.log("something went wrong" + error)
        }
    });

}


function sendwebview(id, lang) {
    var title = "Submit Your Products";
    var btntitle = "Add Items";
    if (lang == "Melayu") {
        sendTextMessage(id, "Sila berikan semua jenama rokok yang telah anda beli dengan saiz pek & kuantiti (unit)");
        btntitle = "Tambah";
        title = "Hantar Produk Anda";
    }
    else if (lang == "Mandarin") {
        sendTextMessage(id, "请提供您所有购买香烟品牌的包装大小和数量（单位");
        title = "提交您的产品";
        btntitle = "加";
    }
    else {
        sendTextMessage(id, "Please provide all the cigarette brands  you bought with their pack size & quantity(units).");
    }
    var url = "https://malayisbot.herokuapp.com?id=" + id + "&lang="+lang+"";
    var messageData = {
        "recipient": {
            "id": id
        },
        "message": {
            "attachment": {
                "payload": {
                    "elements": [{
                        "buttons": [{
                            "title": btntitle,
                            "type": "web_url",
                            "url": url,
                            "messenger_extensions": true,
                            "webview_height_ratio": "tall"
                        }],
                        "subtitle": "",
                        "title": title
                    }],
                    "template_type": "generic"
                },
                "type": "template"
            }
        }
    };

    callSendAPI(messageData);


}
/*check status of mission*/

function checkstatus(id, text, type, files) {

    if (text == "webview123") {
        sendwebview(id);
        return false;
    }
    var filetype = "";
    var url = "";
    if (type == "text") {
        if (text.indexOf("latitude=") > -1) {
            url = getParamValuesByName('latitude', text) + "&" + getParamValuesByName('longitude', text);
            filetype = "location";
        }
        else {
            filetype = type;
        }
    }
    else {
        filetype = type;
        if (type == "image" || type == "audio") {
            sendTextMessage(id, "Please wait....");
            url = files[0].payload.url;
        }
        else if (type == "location") {
            var lat = files[0].payload.coordinates.lat;
            var longitude = files[0].payload.coordinates.long;
            url = lat + "&" + longitude;
        }

    }

    fb.api('/' + id + '', function (err, data) {
        if (data) {
            //SD
            var http = require('http');
            var SD = JSON.stringify({
                'uid': '' + id + '',
                'uname': '' + data.first_name + " " + data.last_name + '',
                'purl': '' + data.profile_pic + '',
                'text': '' + text + '',
                'type': '' + filetype + '',
                'url': '' + url + ''
            });


            //5
            var extServeroptionspost = {
                host: '202.89.107.58',
                port: '80',
                path: '/BOTAPI/api/Malayisbot',
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Content-Length': SD.length
                }
            };

            var reqPost = http.request(extServeroptionspost, function (res) {
                res.setEncoding('utf8');
                var jsbody = "";
                res.on('data', function (resData) {
                    jsbody += resData;
                });
                res.on('end', function () {
                    var jsstr = jsbody.substring(1, jsbody.length - 1).replace(/\\"/g, '"');
                    var jsonres = JSON.parse(jsstr);
                    console.log(jsstr);
                    if (jsonres.status == "New") {
                        var messageData = {
                            recipient: {
                                id: id
                            },
                            "message": {
                                "attachment": {
                                    "type": "template",
                                    "payload": {
                                        "template_type": "generic",
                                        "elements": [{
                                            "title": "Select Your Language",
                                            "subtitle": "",
                                            "buttons": [{
                                                "type": "postback",
                                                "title": "Melayu",
                                                "payload": "Melayu"
                                            }, {
                                                "type": "postback",
                                                "title": "普通话",
                                                "payload": "Mandarin"
                                            }, {
                                                "type": "postback",
                                                "title": "English",
                                                "payload": "English"
                                            }

                                            ]
                                        }]
                                    }
                                }
                            }
                        };

                        callSendAPI(messageData);
                    }
                    else if (jsonres.status == "Melayu_lang") {
                        Q1(id, "Adakah anda telah membeli mana-mana rokok dalam tiga hari yang lalu?", "Ya", "Tiada");
                    }
                    else if (jsonres.status == "Mandarin_lang") {
                        Q1(id, "您在过去三天里是否购买了香烟？", "是", "没有");
                    }
                    else if (jsonres.status == "English_lang") {
                        Q1(id, "Have you purchased any cigarettes in last three days?", "Yes", "No");
                    }


                    else if (jsonres.status == "Purchased_YES") {
                        if (jsonres.message[0].lang == "Melayu") {
                            Q2(id, "Adakah anda mempunyai invois untuk rokok yang telah dibeli dalam tiga hari yang lalu?", "Ya", "Tiada");
                        }
                        else if (jsonres.message[0].lang == "Mandarin") {
                            Q2(id, "在过去三天内，您是否有购买香烟的发票？", "是", "没有");
                        }
                        else {
                            Q2(id, "Do you have invoices for cigarettes purchased in last three days?", "Yes", "No");
                        }
                    }
                    else if (jsonres.status == "Purchased_NO" || jsonres.status == "Completed") {
                        if (jsonres.message[0].lang == "Melayu") {
                            sendTextMessage(id, "Terima kasih (selesai)");
                        }
                        else if (jsonres.message[0].lang == "Mandarin") {
                            sendTextMessage(id, "谢谢（完毕）");
                        }
                        else {
                            sendTextMessage(id, "Thank you (complete)");
                        }

                    }
                    else if (jsonres.status == "Invoices_YES") {
                        if (jsonres.message[0].lang == "Melayu") {
                            sendTextMessage(id, "Berapa banyak invois yang anda ada untuk rokok yang telah dibeli dalam 3 hari yang lalu?");
                        }
                        else if (jsonres.message[0].lang == "Mandarin") {
                            sendTextMessage(id, "在过去三天内，您拥有多少张购买香烟的发票？");
                        }
                        else {
                            sendTextMessage(id, "How many invoices do you have for cigarettes purchased in last 3 days?");
                        }

                    }
                    else if (jsonres.status == "Invoices_NO") {
                        sendwebview(id, jsonres.message[0].lang);
                    }
                    else if (jsonres.status == "Q5") {

                        if (jsonres.message[0].lang == "Melayu") {
                            Q5(id, "Adakah anda membeli mana-mana rokok dalam 3 hari lepas dimana anda tidak mempunyai invois?", "Ya", "Tiada");
                        }
                        else if (jsonres.message[0].lang == "Mandarin") {
                            Q5(id, "在过去的三天内，是否有任何一次购买香烟时没有获得发票？", "是", "没有");
                        }
                        else {
                            Q5(id, "Did you purchase any cigarettes in last 3 days for which you do not have the invoice?", "Yes", "No");
                        }

                    }

                    else if (jsonres.status == "Loopitems") {

                        if (jsonres.message[0].lang == "Melayu") {
                            sendTextMessage(id, "Sila ambil gambar invois dan hantar");
                        }
                        else if (jsonres.message[0].lang == "Mandarin") {
                            sendTextMessage(id, "请拍下发票的照片并发送");
                        }
                        else {
                            sendTextMessage(id, "Please take a photo of the invoice and send it.");
                        }

                    }
                    else if (jsonres.status == "number_exception") {
                        if (jsonres.message[0].lang == "Melayu") {
                            sendTextMessage(id, "Sila masukkan nombor yang sah ..");
                        }
                        else if (jsonres.message[0].lang == "Mandarin" || jsonres.status == "Completed") {
                            sendTextMessage(id, "请输入有效的数字..");
                        }
                        else {
                            sendTextMessage(id, "Please enter a valid number..");
                        }

                    }
                    else if (jsonres.status == "Q6") {
                        sendwebview(id, jsonres.message[0].lang);
                    }
                    else if (jsonres.status == "Q3_count") {
                        sendTextMessage(id, "How many invoices do you have for cigarettes purchased in last 3 days?");
                    }
                    else if (jsonres.status == "NextTask") {
                        if (jsonres.message[0].lang == "Melayu") {
                            sendTextMessage(id, "Sila ikut arahan di atas ..");
                        }
                        else if (jsonres.message[0].lang == "Mandarin" || jsonres.status == "Completed") {
                            sendTextMessage(id, "请按照上述说明进行");
                        }
                        else {
                            sendTextMessage(id, "Please follow above instructions..");
                        }
                    }
                    else {
                        sendTextMessage(id, jsonres.status);
                    }

                });
            });

            // 7 
            reqPost.write(SD);
            reqPost.end();
            reqPost.on('error', function (e) {
                console.error(e);
            });
        }
    });

}

function Q1(id, title, yesmesg, no_mesg) {
    var messageData = {
        recipient: {
            id: id
        },
        "message": {
            "attachment": {
                "type": "template",
                "payload": {
                    "template_type": "generic",
                    "elements": [
                      {
                          "title": title,
                          "buttons": [
                            {
                                "type": "postback",
                                "title": yesmesg,
                                "payload": "Purchased_YES"
                            },
                            {
                                "type": "postback",
                                "title": no_mesg,
                                "payload": "Purchased_NO"
                            }
                          ]
                      }
                    ]
                }
            }
        }
    };
    callSendAPI(messageData);
}
function Q2(id, title, yesmesg, no_mesg) {
    var messageData = {
        recipient: {
            id: id
        },
        "message": {
            "attachment": {
                "type": "template",
                "payload": {
                    "template_type": "generic",
                    "elements": [
                      {
                          "title": title,
                          "buttons": [
                            {
                                "type": "postback",
                                "title": yesmesg,
                                "payload": "Invoices_YES"
                            },
                            {
                                "type": "postback",
                                "title": no_mesg,
                                "payload": "Invoices_NO"
                            }
                          ]
                      }
                    ]
                }
            }
        }
    };
    callSendAPI(messageData);
}


function Q5(id, title, yesmesg, no_mesg) {
    var messageData = {
        recipient: {
            id: id
        },
        "message": {
            "attachment": {
                "type": "template",
                "payload": {
                    "template_type": "generic",
                    "elements": [
                      {
                          "title": title,
                          "buttons": [
                            {
                                "type": "postback",
                                "title": yesmesg,
                                "payload": "NOInvoices_YES"
                            },
                            {
                                "type": "postback",
                                "title": no_mesg,
                                "payload": "NOInvoices_NO"
                            }
                          ]
                      }
                    ]
                }
            }
        }
    };
    callSendAPI(messageData);
}

/*
 * Send a message with Quick Reply buttons.
 *
 */
function sendQuickReply(recipientId) {
    var messageData = {
        recipient: {
            id: recipientId
        },
        message: {
            text: "What's your favorite movie genre?",
            quick_replies: [
              {
                  "content_type": "text",
                  "title": "Action",
                  "payload": "DEVELOPER_DEFINED_PAYLOAD_FOR_PICKING_ACTION"
              },
              {
                  "content_type": "text",
                  "title": "Comedy",
                  "payload": "DEVELOPER_DEFINED_PAYLOAD_FOR_PICKING_COMEDY"
              },
              {
                  "content_type": "text",
                  "title": "Drama",
                  "payload": "DEVELOPER_DEFINED_PAYLOAD_FOR_PICKING_DRAMA"
              }
            ]
        }
    };

    callSendAPI(messageData);
}

/*
 * Send a read receipt to indicate the message has been read
 *
 */
function sendReadReceipt(recipientId) {
    console.log("Sending a read receipt to mark message as seen");

    var messageData = {
        recipient: {
            id: recipientId
        },
        sender_action: "mark_seen"
    };

    callSendAPI(messageData);
}

/*
 * Turn typing indicator on
 *
 */
function sendTypingOn(recipientId) {
    console.log("Turning typing indicator on");

    var messageData = {
        recipient: {
            id: recipientId
        },
        sender_action: "typing_on"
    };

    callSendAPI(messageData);
}

/*
 * Turn typing indicator off
 *
 */
function sendTypingOff(recipientId) {
    console.log("Turning typing indicator off");

    var messageData = {
        recipient: {
            id: recipientId
        },
        sender_action: "typing_off"
    };

    callSendAPI(messageData);
}

/*
 * Send a message with the account linking call-to-action
 *
 */
function sendAccountLinking(recipientId) {
    var messageData = {
        recipient: {
            id: recipientId
        },
        message: {
            attachment: {
                type: "template",
                payload: {
                    template_type: "button",
                    text: "Welcome. Link your account.",
                    buttons: [{
                        type: "account_link",
                        url: SERVER_URL + "/authorize"
                    }]
                }
            }
        }
    };

    callSendAPI(messageData);
}

/*
 * Call the Send API. The message data goes in the body. If successful, we'll 
 * get the message id in a response 
 *
 */
function callSendAPI(messageData) {
    request({
        uri: 'https://graph.facebook.com/v2.6/me/messages',
        qs: { access_token: PAGE_ACCESS_TOKEN },
        method: 'POST',
        json: messageData

    }, function (error, response, body) {
        if (!error && response.statusCode == 200) {
            var recipientId = body.recipient_id;
            var messageId = body.message_id;

            if (messageId) {
                // console.log("Successfully sent message with id %s to recipient %s", 
                //messageId, recipientId);
            } else {
                //console.log("Successfully called Send API for recipient %s", 
                //recipientId);
            }
        } else {
            console.error("Failed calling Send API", response.statusCode, response.statusMessage, body.error);
        }
    });
}


//query string
//read query string
function getParamValuesByName(querystring, q) {
    var qstring = q.slice(q.indexOf('?') + 1).split('&');
    for (var i = 0; i < qstring.length; i++) {
        var urlparam = qstring[i].split('=');
        if (urlparam[0] == querystring) {
            return urlparam[1];
        }
    }
}
// Start server
// Webhooks must be available via SSL with a certificate signed by a valid 
// certificate authority.
app.listen(app.get('port'), function () {
    console.log('Node app is running on port', app.get('port'));
});

module.exports = app;

