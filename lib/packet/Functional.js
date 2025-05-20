/* jshint node: true */
'use strict';

let Concentrate = require('concentrate'),
    DChunks = require('dissolve-chunks'),
    ru = DChunks.Rule,
    zclId = require('zcl-id');

let zclmeta = require('./ZclMeta');

let parsedBufLen = 0;

/*************************************************************************************************/
/*** FuncPayload Class                                                                         ***/
/*************************************************************************************************/
class FuncPayload {
    constructor(clusterId, direction, cmd){
        let cluster = zclId.cluster(clusterId)
        if (!cluster)
            throw new Error('Unrecognized cluster');

        this.cluster = cluster ? cluster.key : clusterId;
        this.command = zclmeta.functional.getCommand(this.cluster, direction, cmd);

        if (!this.command)
            throw new Error(`Unrecognized command (${this.cluster}, ${direction}, ${cmd})`)

        this.meta = zclmeta.functional.get(this.cluster, this.cmd);
        if(!this.meta)
            throw new Error(`No metadata for (${this.cluster}, ${direction}, ${this.cmd})`);

        direction = zclmeta.Direction.get(this.meta.dir)
        this.direction = direction.key
        if (!this.direction)
            throw new Error('Unrecognized direction');
    }

    get cmd() {
        return this.command.key
    }

    get cmdId() {
        return this.command.value
    }

    parse (zclBuf) {
        let knownBufLen = this.meta.knownBufLen;
        if(knownBufLen) parsedBufLen = knownBufLen

        let params = this.meta.params
        if(params.constructor.name === 'Map'){
            params = {default:params}
        }
        let ex
        for(const i in params){
            const p = params[i]
            let r
            try {
                r = FuncPayload.parseFrame(zclBuf, p)
            }catch(_ex){
                ex = _ex
                continue
            }
            if(r) return r
        }

        if(ex) throw ex
        return undefined
    }

    frame (args) { // args can be an array or a value-object if given
        let params = this.meta.params
        const reqParams = []  // [ { name, type, value }, ... ]

        if (params) {
            if(params.constructor.name !== 'Map'){
                //is multirsp
                if(!args._name) throw new Error("A frame name must be provided (_name)")
                if(!params[args._name]) throw new Error("Unknown frame name")
                params = params[args._name]
            }

            for(const [name,type] of params){
                if(args[name] === undefined) throw new Error(`The argument object is missing ${name}`)
                reqParams.push({name, type, value: args[name]})
            }
        }

        return FuncPayload.buildFrame(reqParams)
    }
}


FuncPayload.parseFrame = function (zclBuf, params){
    if (!params) throw new Error('Response parameter definitions not found.')

    const chunkRules = []
    for(const [name, type] of params){
        let rule = ru[type];
        if (!rule) throw new Error('Parsing rule for ' + type + ' is not found.')
        rule = rule(name, zclBuf.length)
        chunkRules.push(rule)
    }

    
    if (chunkRules.length === 0) {
        return {}
    }

    const parser = (new DChunks()).join(chunkRules).compile({ once: true });

    let ret = parser.process(zclBuf)

    if(ret.length != 1) throw new Error(`Parsing error ${ret.length} results parsed`)
    return ret[0]
}

FuncPayload.buildFrame = function (args){
    let dataBuf = Concentrate();

    args.forEach(function (arg, _idx) { // arg: { name, type, value }
        let type = arg.type,
            val = arg.value,
            idxarr,
            k = 0;

        switch (type) {
            case 'int8':
            case 'uint8':
            case 'int16':
            case 'uint16':
            case 'int32':
            case 'uint32':
            case 'floatle':
                dataBuf = dataBuf[type](val);
                break;
            case 'preLenUint8':
            case 'preLenUint16':
            case 'preLenUint32':
                type = type.slice(6).toLowerCase();
                dataBuf = dataBuf[type](val);
                break;
            case 'buffer':
                dataBuf = dataBuf.buffer(new Buffer(val));
                break;
            case 'longaddr':       // string '00124b00019c2ee9'
                let msb = parseInt(val.slice(0,8), 16),
                    lsb = parseInt(val.slice(8), 16);

                dataBuf = dataBuf.uint32le(lsb).uint32le(msb);
                break;
            case 'stringPreLen':
                if (typeof val !== 'string') {
                    throw new Error('The value for ' + val + ' must be an string.');
                }
                dataBuf = dataBuf.uint8(val.length).string(val, 'utf8');
                break;
            case "data32":
                val = new Buffer(32)
                Buffer.from(val).copy(val)
                dataBuf = dataBuf.buffer(val, 'utf8');
            break;
            case 'dynUint8':
            case 'dynUint16':
            case 'dynUint32':      // [ x, y, z, ... ]
                type = type.slice(3).toLowerCase();
                for (idxarr = 0; idxarr < val.length; idxarr += 1) {
                    dataBuf = dataBuf[type](val[idxarr]);
                }
                break;
            case 'dynUint24':      // [ x, y, z, ... ]
                for (idxarr = 0; idxarr < val.length; idxarr += 1) {
                    let value = val[idxarr],
                        msb24 = (value & 0xff0000) >> 16,
                        mid24 = (value & 0xff00) >> 8,
                        lsb24 = (value & 0xff) ;
                    dataBuf = dataBuf.uint8(lsb24).uint8(mid24).uint8(msb24);
                }
                break;
            case 'locationbuffer': // [ '0x00124b00019c2ee9', int16, int16, int16, int8, uint8, ... ]
                for (idxarr = 0; idxarr < (val.length) / 6; idxarr += 1) {
                    let msbaddr = parseInt(val[k].slice(0,8), 16),
                        lsbaddr = parseInt(val[k].slice(8), 16);
                    dataBuf = dataBuf.uint32le(lsbaddr).uint32le(msbaddr).int16(val[k+1]).int16(val[k+2])
                            .int16(val[k+3]).int8(val[k+4]).uint8(val[k+5]);
                k += 6;
                }
                break;
            case 'zonebuffer':     // [ uint8, uint16, ... ]
                for (idxarr = 0; idxarr < (val.length) / 2; idxarr+= 1) {
                    dataBuf = dataBuf.uint8(val[k]).uint16le(val[k+1]);
                k += 2;
                }
                break;
            case 'extfieldsets':   // [ { clstId, len, extField }, ... ]
                for (idxarr = 0; idxarr < val.length; idxarr += 1) {
                    dataBuf = dataBuf.uint16le(val[idxarr].clstId).uint8(val[idxarr].len).buffer(new Buffer(val[idxarr].extField));
                }
                break;
            default:
                throw new Error('Unknown Data Type');
        }
    });

    return dataBuf.result();
}

/*************************************************************************************************/
/*** Add Parsing Rules to DChunks                                                              ***/
/*************************************************************************************************/
let rules1 = ['preLenUint8', 'preLenUint16', 'preLenUint32'],
    rules2 = ['dynUint8', 'dynUint16', 'dynUint24', 'dynUint32', 'zonebuffer', 'extfieldsets', 'locationbuffer'];

rules1.forEach(function (ruName) {
    ru.clause(ruName, function (name) {
        if (ruName === 'preLenUint8') {
            this.uint8(name);
        } else if (ruName === 'preLenUint16') {
            this.uint16(name);
        } else if (ruName === 'preLenUint32') {
            this.uint32(name);
        }

        this.tap(function () {
            this.vars.preLenNum = this.vars[name];
        });
    });
});

rules2.forEach(function (ruName) {
    ru.clause(ruName, function (name, bufLen) {
        this.tap(function () {
            let length;
            if (ruName === 'extfieldsets') {
                length = bufLen - parsedBufLen;
            } else if(this.vars.preLenNum !== undefined) {
                if (ruName === 'zonebuffer') {
                    length = this.vars.preLenNum * 3;
                } else if (ruName === 'locationbuffer') {
                    length = this.vars.preLenNum * 16;
                } else {
                    length = this.vars.preLenNum * (parseInt(ruName.slice(7)) / 8);
                }
            }else{
                length = bufLen - parsedBufLen
            }

            this.buffer(name, length).tap(function () {
                let buf = this.vars[name];                
                this.vars[name] = buf2Arr(buf, ruName);
                delete this.vars.preLenNum;
            });
        });
    });
});

ru.clause('longaddr', function (name) {
    this.buffer(name, 8).tap(function () {
        let addrBuf = this.vars[name];
        this.vars[name] = addrBuf2Str(addrBuf);
    });
});

ru.clause('data32', function (name) {
    this.buffer(name, 32)
});

ru.clause('stringPreLen', function (name) {
    this.uint8('len').tap(function () {
        this.string(name, this.vars.len);
        parsedBufLen += this.vars.len;
        delete this.vars.len;
    });
});

function addrBuf2Str(buf) {
    let bufLen = buf.length,
        val,
        strChunk = '';

    for (let i = 0; i < bufLen; i += 1) {
        val = buf.readUInt8(bufLen - i - 1);
        if (val <= 15) {
            strChunk += '0' + val.toString(16);
        } else {
            strChunk += val.toString(16);
        }
    }

    return strChunk;
}

function buf2Arr(buf, type) {
    let i,
        arr = [];

    switch (type) {
        case 'dynUint8':
            for (i = 0; i < buf.length; i += 1) {
                arr.push(buf.readUInt8(i));
            }
            break;
        case 'dynUint16':
            for (i = 0; i < buf.length; i += 2) {
                arr.push(buf.readUInt16LE(i));
            }
            break;
        case 'dynUint24':
            for (i = 0; i < buf.length; i += 3) {
                let lsb = buf.readUInt16LE(i),
                    msb = buf.readUInt8(i + 2),
                    val = (msb << 16) + lsb;
                arr.push(val);
            }
            break;
        case 'dynUint32':
            for (i = 0; i < buf.length; i += 4) {
                arr.push(buf.readUInt32LE(i));
            }
            break;
        case 'zonebuffer':
            for (i = 0; i < buf.length; i += 3) {
                arr.push(buf.readUInt8(i), buf.readUInt16LE(i + 1));
            }
            break;
        case 'extfieldsets':
            let extFieldLen;
            for (i = 0; i < buf.length; i += extFieldLen) {
                let obj = {};
            
                obj.clstId = buf.readUInt16LE(i);
                obj.len = extFieldLen = buf.readUInt8(i+2);
                obj.extField = [];
                i += 3;
                for (let j = 0; j < obj.len; j+=1) {
                    obj.extField.push(buf.readUInt8(i + j));
                }
                arr.push(obj);
            }
            break;
        case 'locationbuffer':
            for (i = 0; i < buf.length; i += 16) {
                let addr = addrBuf2Str(buf.slice(i, i+8));
                arr.push(addr, buf.readInt16LE(i + 8), buf.readInt16LE(i + 10), buf.readInt16LE(i + 12), buf.readInt8(i + 14), buf.readUInt8(i + 15));
            }
            break;
        default:
            break;
    }

    return arr;
}

module.exports = FuncPayload;
