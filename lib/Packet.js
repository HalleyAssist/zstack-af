/* jshint node: true */
'use strict';

var DChunks = require('dissolve-chunks'),
    ru = DChunks.Rule;

var FoundPayload = require('./packet/Foundation'),
    FuncPayload = require('./packet/Functional');

var zcl = {};

zcl.Functional = FuncPayload

const zclPayloadObject = function(frameCntl, clusterId, cmd){
    if (frameCntl.frameType === 0) {
        return new FoundPayload(cmd);
    } else if (frameCntl.frameType === 1) {
        if (!clusterId)
            throw new TypeError('clusterId should be given.');

        return new FuncPayload(clusterId, frameCntl.direction, cmd);
    }
}

zcl.parse = function (zclBuf, clusterId) {
    var zclFrame = new ZclFrame();

    if (!Buffer.isBuffer(zclBuf)) throw new TypeError('zclBuf should be a buffer.');

    const data = zclFrame.parse(zclBuf)

    // data = { frameCntl: { frameType, manufSpec, direction, disDefaultRsp }, manufCode, seqNum, cmdId, payload }

    var zclObj = zclPayloadObject(data.frameCntl, clusterId, data.cmdId);
    data.cmdId = zclObj.cmd;    // make sure data.cmdId will be string

    const payload = zclObj.parse(data.payload)
    data.payload = payload;
    return data
};

zcl.frame = function (frameCntl, manufCode, seqNum, cmd, zclPayload, clusterId) {
    // frameCntl: Object, manufCode: Number, seqNum: Number, cmd: String | Number, zclPayload: Object | Array, clusterId: String | Number
    var zclObj,
        zclFrame = new ZclFrame();

    if (typeof frameCntl !== 'object' || Array.isArray(frameCntl)) throw new TypeError('frameCntl should be an object');
    if (typeof zclPayload !== 'object' || zclPayload === null) throw new TypeError('zclPayload should be an object or an array');
    
    var payload
    if(zclPayload instanceof Buffer){
        payload = zclPayload
    } else{
        zclObj = zclPayloadObject(frameCntl, clusterId, cmd);
        payload = zclObj.frame(zclPayload)
    }

    return zclFrame.frame(frameCntl, manufCode, seqNum, zclObj.cmdId, payload);
};

zcl.header = function (buf) {
    if (!Buffer.isBuffer(buf)) throw new TypeError('header should be a buffer.');

    var i = 0,
        headByte = buf.readUInt8(0),
        header = {
            frameCntl: {
                frameType: (headByte & 0x03),
                manufSpec: ((headByte >> 2) & 0x01),
                direction: ((headByte >> 3) & 0x01),
                disDefaultRsp: ((headByte >> 4) & 0x01)
            },
            manufCode: null,
            seqNum: null,
            cmdId: null
        };

    i += 1; // first byte, frameCntl, has parsed

    if (header.frameCntl.manufSpec === 1) {
        header.manufCode = buf.readUInt16LE(i);
        i += 2;
    } else if (header.frameCntl.manufSpec === 0) {
        header.manufCode = null;
    }

    header.seqNum = buf.readUInt8(i);
    i += 1;
    header.cmdId = buf.readUInt8(i);

    if (header.frameCntl.frameType < 0x02 && header.cmdId < 0x80)
        return header;
};

/*************************************************************************************************/
/*** ZclFrame Class                                                                            ***/
/*************************************************************************************************/
function ZclFrame() {}

ZclFrame.prototype.parse = function (buf) {
    const parser = (new DChunks()).join(ru.zclFrame(buf.length)).compile({once: true});

    const result = parser.process(buf);
    if(result.length) return result[0]
};

ZclFrame.prototype.frame = function (frameCntl, manufCode, seqNum, cmdId, payload) {
    if (!isNumber(manufCode)) throw new TypeError('manufCode should be a number');
    if (!isNumber(seqNum)) throw new TypeError('seqNum should be a number');

    const frameCntlOctet = (frameCntl.frameType & 0x03) | ((frameCntl.manufSpec << 2) & 0x04) | ((frameCntl.direction << 3) & 0x08) | ((frameCntl.disDefaultRsp << 4) & 0x10);

    const dataBuf = Buffer.allocUnsafeSlow((frameCntl.manufSpec === 1?5:3) + payload.length);
    dataBuf[0] = frameCntlOctet;
    if(frameCntl.manufSpec === 1){
        dataBuf.writeUInt16LE(manufCode, 1);
        dataBuf[3] = seqNum;
        dataBuf[4] = cmdId;
        payload.copy(dataBuf, 5);
        return dataBuf
    }
    
    dataBuf[1] = seqNum;
    dataBuf[2] = cmdId;
    payload.copy(dataBuf, 3);
    return dataBuf
};

/*************************************************************************************************/
/*** Add Parsing Rules to DChunks                                                              ***/
/*************************************************************************************************/
ru.clause('zclFrame', function (bufLen) {
    var manufSpec;

    this.uint8('frameCntl').tap(function () {
        var filedValue = this.vars.frameCntl;
        
        this.vars.frameCntl = {
            frameType: (filedValue & 0x03),
            manufSpec: (filedValue & 0x04) >> 2,
            direction: (filedValue & 0x08) >> 3,
            disDefaultRsp: (filedValue & 0x10) >> 4,
        };
        manufSpec = this.vars.frameCntl.manufSpec;
    }).tap(function () {
        if (!manufSpec)
            this.vars.manufCode = 0;
        else
            this.uint16('manufCode');
    }).tap(function () {
        this.uint8('seqNum').uint8('cmdId');
    }).tap(function () {
        if (!manufSpec)
            this.buffer('payload', bufLen - 3);
        else
            this.buffer('payload', bufLen - 5);
    });
});

function isNumber(param) {
    var isValid = true;

    if (typeof param !== 'number') {
        isValid = false;
    } else if (typeof param === 'number') {
        isValid = !isNaN(param);
    }

    return isValid;
}


module.exports = zcl;