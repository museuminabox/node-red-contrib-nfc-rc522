/**
 * Copyright 2014-2015 MCQN Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 **/

module.exports = function(RED) {
    "use strict";
    var rfid_rc522 = require("rfid-rc522");
    var fs =  require('fs');
    var ndef = require('ndef');

    if (!fs.existsSync("/dev/ttyAMA0")) { // unlikely if not on a Pi
        throw "Info : Ignoring Raspberry Pi specific node.";
    }

    function RFID(n) {
        RED.nodes.createNode(this,n);
        this.cardPresent = false;
        var node = this;

        rfid_rc522.registerTagCallback(function(action, tagID) {
            if (action === "tagPresented") {
                var msg = {topic:"pi/rfid-presented", payload:tagID};
                node.send(msg);
            } else {
                var msg = {topic:"pi/rfid-removed", payload:tagID};
                node.send(msg);
            }
        });
        // FIXME Add a clear callback function
        //node.on("close", function() {
            //clearInterval(node._interval);
        //});
    }

    function RFIDReadNDEF(n) {
        RED.nodes.createNode(this, n);
        this.name = n.name;
        var node = this;

        this.on("input", function(msg) {
            if (msg != null) {
                rfid_rc522.readFirstNDEFTextRecord(function(error, data) {
                    if (error == 0) {
                        console.log("found record: "+data);
                        msg.topic="pi/rfid-ndef";
                        msg.payload=data.toString();
                        msg.ndef=data;
                        node.send(msg);
                    } else {
                        msg.payload = "No NDEF record found: "+error; 
                        node.error(msg.payload, msg);
                    }
                });
            } else {
                msg.payload = "Missing a msg.payload"; 
                node.error(msg.payload, msg);
            }
        });
    }

    function RFIDWriteNDEF(n) {
        RED.nodes.createNode(this,n);
        this.name = n.name;
        var node = this;

        this.on("input", async function(msg) {
            if (msg != null) {
                if (msg.payload) {
                    // We've got our pre-requisites
                    // Find an RFID tag first
//                    var tag = this.rfid.selectTag();
//                    if (tag) {
//                        // Tag found.
                        // Build up the NDEF records we'll send
                        // FIXME Cope with msg.payload not being an array of objs
                        var ndefRecords = [];
                        var i;
                        for (i = 0; i < msg.payload.length; i++) {
                            if (msg.payload[i].type == "Sp") {
                                // URL record
                                ndefRecords.push(ndef.uriRecord(msg.payload[i].value));
                            } else if (msg.payload[i].type == "T") {
                                // Text record
                                ndefRecords.push(ndef.textRecord(msg.payload[i].value));
                            }
                        }
                        if (ndefRecords.length) {
                            // Prep the NDEF message
                            var ndefMessage = ndef.encodeMessage(ndefRecords);
                            // Prepend the TLV value to put it into a Mifare Classic tag
                            // (Prepend in reverse order as unshift puts a byte at the start of the array)
                            if (ndefMessage.length >= 0xFF) {
                                // 3-byte length version
                                ndefMessage.unshift(ndefMessage.length & 0xff);
                                ndefMessage.unshift(ndefMessage.length >> 8);
                                ndefMessage.unshift(0xff);
                            } else {
                                ndefMessage.unshift(ndefMessage.length);
                            }
                            ndefMessage.unshift(0x03);
                            // Append a terminator block
                            ndefMessage.push(0xfe);
                            ndefMessage.push(0x00);

                            var ndefMsgBuffer = new Buffer(ndefMessage);
                            console.log(ndefMsgBuffer.toString('hex'));

                            // We currently only support tags from the Ultralight family
                            // which includes the NTAG203, etc.

                            // Read in the tag's capability container to 
                            // work out its size
                            var data;
                            try {
                                data = await rfid_rc522.readPageAsync(3);
                            }
                            catch (err) {
                                console.log(err);
                                data = null;
                            }
                            if (data != null) {
                                var page = 4; // skip the first four pages as they hold
                                              // general info on the tag
                                var pageCount = 0xFFFF; // Read until we hit an error
                                // ...unless we know how big this tag is...
                                if (data[2] == 0x12) {
                                    pageCount = 36; // NTAG213, 144-byte
                                } else if (data[2] == 0x3E) {
                                    pageCount = 124; // NTAG215, 496-byte
                                } else if (data[2] == 0x6D) {
                                    pageCount = 218; // NTAG216, 872-byte
                                }
                                // Check if there'll be enough space
                                if (ndefMsgBuffer.length <= (pageCount-page)*4) {
                                    var idx = 0;
                                    var working = true;
                                    while ((idx < ndefMsgBuffer.length) 
                                           && (working)) {
                                        var block = new Buffer(4);
                                        block.fill(0);
                                        ndefMsgBuffer.copy(block, 0, idx, idx+4);
                                        var tries = 0;
                                        working = false; // so we drop into the while loop
                                        while ((tries++ < 5) && (!working)) {
                                            try {
                                                working = await rfid_rc522.writePageAsync(page, block);
                                            }
                                            catch (err) {
                                                console.log(err);
                                                working = false;
                                            }
                                        }
                                        page++;
                                        idx+=4;
                                    }
                                    if (working) {
                                        this.send(msg);
                                    } else {
                                        msg.payload = "Write error";
                                        this.error(msg.payload, msg);
                                    }
                                } else {
                                    msg.payload = "Tag too small!"; 
                                    this.error(msg.payload, msg);
                                }
                            } else {
                                msg.payload = "Couldn't read capability container of RFID tag"; 
                                this.error(msg.payload, msg);
                            }
                        } else {
                            msg.payload = "Unrecognised tag type: "+tag.tagType; 
                            this.error(msg.payload, msg);
                        }
//                    } else {
//                        // Failed to find a tag
//                        msg.payload = "No RFID tag found"; 
//                        this.error(msg.payload, msg);
//                    }
                } else {
                    msg.payload = "Missing either a msg.block or a msg.payload"; 
                    this.error(msg.payload, msg);
                }
            }
        });
    }

    RED.nodes.registerType("rpi-rc522-rfid in",RFID);
    RED.nodes.registerType("rpi-rc522-rfid read-ndef",RFIDReadNDEF);
    RED.nodes.registerType("rpi-rc522-rfid write-ndef",RFIDWriteNDEF);
}
