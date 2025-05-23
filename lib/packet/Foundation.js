/* jshint node: true */
'use strict';

let Concentrate = require('concentrate'),
    DChunks = require('dissolve-chunks'),
    ru = DChunks.Rule,
    zclId = require('zcl-id');

let zclmeta = require('./ZclMeta');

let parsedBufLen = 0;

/*************************************************************************************************/
/*** FoundPayload Class                                                                        ***/
/*************************************************************************************************/


class FoundPayload {
    constructor(cmd){
        this.command = zclId.foundation(cmd);
        if (!this.command)
            throw new Error(`Unrecognized command (${cmd})`)

        this.meta = zclmeta.foundation.get(this.cmd)
        if(!this.meta)
            throw new Error(`No metadata for (${this.cmd})`)
    }

    get cmd() {
        return this.command.key
    }

    get cmdId() {
        return this.command.value
    }

    _getBuf (arg, dataBuf) {
        switch (this.cmd) {
            case 'readRsp':
                dataBuf = dataBuf.uint16le(arg.attrId).uint8(arg.status);
    
                if (arg.status === 0) {
                    dataBuf = dataBuf.uint8(arg.dataType).buffer(getChunkBuf('multi', arg));
                }
                break;
    
            case 'writeRsp':
                dataBuf = dataBuf.uint8(arg.status);
                if (arg.status !== 0)
                    dataBuf = dataBuf.uint16le(arg.attrId);
                break;
    
            case 'configReport':
                dataBuf = dataBuf.uint8(arg.direction).uint16le(arg.attrId);
                if (arg.direction === 0) {
                    dataBuf = dataBuf.uint8(arg.dataType).uint16le(arg.minRepIntval).uint16le(arg.maxRepIntval);
                    const analogOrDigital = isDataAnalogDigital(arg.dataType);
                    if (analogOrDigital === 'ANALOG') {
                        dataBuf = dataBuf.buffer(getDataTypeBuf(getDataType(arg.dataType), arg.repChange));
                    }
                } else if (arg.direction === 1) {
                    dataBuf = dataBuf.uint16le(arg.timeout);
                }
                break;
    
            case 'configReportRsp':
                dataBuf = dataBuf.uint8(arg.status);
                if (arg.status !== 0)
                    dataBuf = dataBuf.uint8(arg.direction).uint16le(arg.attrId);
                break;
    
            case 'readReportConfigRsp':
                dataBuf = dataBuf.uint8(arg.status);
                if (arg.status === 0) {
                    return (new FoundPayload('configReport'))._getBuf(arg, dataBuf);
                }
                return dataBuf.uint8(arg.direction).uint16le(arg.attrId);
    
            default:
                for(const [paramName, paramType] of this.meta.params){
                    if (arg[paramName] === undefined)
                    throw new Error('Payload of commnad: ' + this.cmd + ' must have ' + paramName + ' property.');
    
                    if (paramType === 'variable') {
                        dataBuf = dataBuf.buffer(getDataTypeBuf(getDataType(arg.dataType), arg.attrData));
                    } else if (paramType === 'selector') {
                        dataBuf = dataBuf.buffer(getChunkBuf('selector', arg.selector));
                    } else if (paramType === 'multi') {
                        dataBuf = dataBuf.buffer(getChunkBuf('multi', arg));
                    } else {
                        dataBuf = dataBuf[paramType](arg[paramName]);
                    }
                }
                break;
        }
        return dataBuf;
    }

    parse (zBuf) {
        let result = [], r, discComplete
        switch (this.cmd) {
            case 'defaultRsp':
            case 'discover':
                result = this._getObj(zBuf);
                return (result.data && result.data.length) ? result.data[0] : {};

            case 'discoverRsp':
                discComplete = zBuf.readUInt8(0)

                zBuf = zBuf.slice(1);
                parsedBufLen += 1;
                break;
        }

        do {
            r = this._getObj(zBuf)
            if (r.data)
                for(const i of r.data) result.push(i);
            zBuf = r.leftBuf
        } while(zBuf && zBuf.length)

        if(this.cmd === 'discoverRsp'){
            return {discComplete, attrInfos: result}
        }
        return result
    }

    _getObj (buf) {
        let chunkRules = [],
            parser,
            knownBufLen = zclmeta.foundation.get(this.cmd).knownBufLen,
            result = {
                data: null,
                leftBuf: null
            };
    
        if (buf.length === 0) {
            result.leftBuf = new Buffer(0);
            return result
        }
    
        parsedBufLen = 0;
    
        parsedBufLen += knownBufLen;
        for(const [name, type] of this.meta.params){
            chunkRules.push(ru[type]([name]));
        }
    
        parser = (new DChunks()).join(chunkRules).compile();
    
        const results = parser.process(buf)
        result.data = results;
        result.leftBuf = parser.remainingBuffer
        return result
    }

    frame (payload) { // args can be an array or a value-object if given
        let dataBuf = Concentrate();

        switch (this.cmd) {
            case 'defaultRsp':
            case 'discover':
                if ((typeof payload !== 'object') || Array.isArray(payload))
                    throw new TypeError('Payload arguments of ' + this.cmd + ' command should be an object');

                dataBuf = this._getBuf(payload, dataBuf);
                break;

            case 'discoverRsp':
                if ((typeof payload !== 'object') || Array.isArray(payload))
                    throw new TypeError('Payload arguments of ' + this.cmd + ' command should be an object');

                dataBuf = dataBuf.uint8(payload.discComplete);
                for(const argObj of payload.attrInfos){
                    this._getBuf(argObj, dataBuf)
                }
                break;

            default:
                if (!Array.isArray(payload))
                    throw new TypeError('Payload arguments of ' + this.cmd + ' command should be an array');

                for(const argObj of payload){
                    this._getBuf(argObj, dataBuf)
                }
                break;
        }

        return dataBuf.result();
    }

    parsedBufLen(){
        return parsedBufLen
    }
}


/*************************************************************************************************/
/*** Private Functions                                                                         ***/
/*************************************************************************************************/
function getChunkBuf (rule, arg) {
    let dataBuf = Concentrate(),
        type,
        i = 0;

    switch (rule) {
        case 'multi':
            type = zclId.dataType(arg.dataType).key;
            if (type === 'array' || type === 'set' || type === 'bag') {
                dataBuf = dataBuf.buffer(getChunkBuf('attrVal', arg.attrData));
            } else if (type === 'struct') {
                dataBuf = dataBuf.buffer(getChunkBuf('attrValStruct', arg.attrData));
            } else {
                dataBuf = dataBuf.buffer(getDataTypeBuf(getDataType(arg.dataType), arg.attrData));
            }
            return dataBuf.result();

        case 'attrVal': 
            dataBuf = dataBuf.uint8(arg.elmType).uint16(arg.numElms);
            for (i = 0; i < arg.numElms; i += 1) {
                dataBuf = dataBuf.buffer(getDataTypeBuf(getDataType(arg.elmType), arg.elmVals[i]));
            }
            return dataBuf.result();

        case 'attrValStruct': 
            dataBuf = dataBuf.uint16(arg.numElms);
            for (i = 0; i < arg.numElms; i += 1) {
                dataBuf = dataBuf.buffer(getChunkBuf('attrValStructNip', arg.structElms[i]));
            }
            return dataBuf.result();

        case 'attrValStructNip': 
            dataBuf = dataBuf.uint8(arg.elmType).buffer(getDataTypeBuf(getDataType(arg.elmType), arg.elmVal));
            return dataBuf.result();

        case 'selector':
            dataBuf = dataBuf.uint8(arg.indicator);

            for (i = 0; i < arg.indicator; i += 1) {
                dataBuf = dataBuf.uint16le(arg.indexes[i]);
            }
            return dataBuf.result();
    }
}

function ensureDataTypeString(dataType) {
    let dataTypeStr;

    if (typeof dataType === 'number') {
        dataTypeStr = zclId.dataType(dataType).key;
    } else if (typeof dataType === 'object' && dataType.key !== undefined) {
        dataTypeStr = dataType.key;
    } else if (typeof dataType === 'string') {
        dataTypeStr = dataType;
    }
    return dataTypeStr;
}

function getDataType(dataType) {
    let type = ensureDataTypeString(dataType),
        newDataType;

    switch (type) {
        case 'data8':
        case 'boolean':
        case 'bitmap8':
        case 'uint8':
        case 'enum8':
            newDataType = 'uint8';
            parsedBufLen += 1;
            break;
        case 'int8':
            newDataType = 'int8';
            parsedBufLen += 1;
            break;
        case 'data16':
        case 'bitmap16':
        case 'uint16':
        case 'enum16':
        case 'clusterId':
        case 'attrId':
            newDataType = 'uint16';
            parsedBufLen += 2;
            break;
        case 'int16':
            newDataType = 'int16';
            parsedBufLen += 2;
            break;
        case 'semiPrec':
            // TODO
            break;
        case 'data24':
        case 'bitmap24':
        case 'uint24':
            newDataType = 'uint24';
            parsedBufLen += 3;
            break;
        case 'int24':
            newDataType = 'int24';
            parsedBufLen += 3;
            break;
        case 'data32':
        case 'bitmap32':
        case 'uint32':
        case 'tod':
        case 'date':
        case 'utc':
        case 'bacOid':
            newDataType = 'uint32';
            parsedBufLen += 4;
            break;
        case 'int32':
            newDataType = 'int32';
            parsedBufLen += 4;
            break;
        case 'singlePrec':
            newDataType = 'floatle';
            parsedBufLen += 4;
            break;
        case 'doubleprec':
            newDataType = 'doublele';
            parsedBufLen += 8;
            break;
        case 'uint40':
        case 'bitmap40':
        case 'data40':
            newDataType = 'uint40';
            parsedBufLen += 5;
            break;
        case 'uint48':
        case 'bitmap48':
        case 'data48':
            newDataType = 'uint48';
            parsedBufLen += 6;
            break;
        case 'uint56':
        case 'bitmap56':
        case 'data56':
            newDataType = 'uint56';
            parsedBufLen += 7;
            break;
        case 'uint64':
        case 'bitmap64':
        case 'data64':
        case 'ieeeAddr':
            newDataType = 'uint64';
            parsedBufLen += 8;  
            break;
        case 'int40':
            newDataType = 'int40';
            parsedBufLen += 5;
            break;
        case 'int48':
            newDataType = 'int48';
            parsedBufLen += 6;
            break;
        case 'int56':
            newDataType = 'int56';
            parsedBufLen += 7;
            break;
        case 'int64':
            newDataType = 'int64';
            parsedBufLen += 8;
            break;
        case 'octetStr':
        case 'charStr':
            newDataType = 'strPreLenUint8';
            break;
        case 'longOctetStr':
        case 'longCharStr':
            newDataType = 'strPreLenUint16';
            break;
        case 'struct':
            newDataType = 'attrValStruct';
            break;
        case 'noData':
        case 'unknown':
            break;
        case 'secKey':
            newDataType = 'secKey';
            parsedBufLen += 16;
            break;
    }
    return newDataType;
}

function getDataTypeBuf (type, value) {
    let dataBuf = Concentrate(),
        string,
        strLen;

    switch (type) {
        case 'uint8':
        case 'int8':
        case 'uint16':
        case 'int16':
        case 'uint32':
        case 'int32':
        case 'floatle':
        case 'doublele':
            dataBuf = dataBuf[type](value);
            break;
        case 'uint24':
            dataBuf = dataBuf.uint32le(value).result().slice(0, 3);
            break;
        case 'int24':
            dataBuf = dataBuf.int32le(value).result().slice(0, 3);
            break;
        case 'uint40':
            if (Array.isArray(value) && value.length === 2) {
                if (value[0] > 255) {
                    throw new Error('The value[0] for UINT40/BITMAP40/DATA40 must be smaller than 255.');
                }
                dataBuf = dataBuf.uint32le(value[1]).uint8(value[0]);
            } else {
                throw new Error('The value for UINT40/BITMAP40/DATA40 must be orgnized in an 2-element number array.');
            }
            break;
        case 'int40':
            //TODO
            break;
        case 'uint48':
            if (Array.isArray(value) && value.length === 2) {
                if (value[0] > 65535) {
                    throw new Error('The value[0] for UINT48/BITMAP48/DATA48 must be smaller than 65535.');
                }
                dataBuf = dataBuf.uint32le(value[1]).uint16le(value[0]);
            } else {
                throw new Error('The value for UINT48/BITMAP48/DATA48 must be orgnized in an 2-element number array.');
            }
            break;
        case 'int48':
            //TODO
            break;
        case 'uint56':
            if (Array.isArray(value) && value.length === 2) {
                if (value[0] > 16777215) {
                    throw new Error('The value[0] for UINT56/BITMAP56/DATA56 must be smaller than 16777215.');
                }
                dataBuf = dataBuf.uint32le(value[1]).uint32le(value[0]).result().slice(0, 7);
            } else {
                throw new Error('The value for UINT56/BITMAP56/DATA56 must be orgnized in an 2-element number array.');
            }
            break;
        case 'int56':
            //TODO
            break;
        case 'uint64':
            dataBuf = dataBuf.uint32le(parseInt(value.slice(8), 16)).uint32le(parseInt(value.slice(0,8), 16));
            break;
        case 'strPreLenUint8':
            if (typeof value !== 'string') {
                throw new Error('The value for ' + type + ' must be an string.');
            }
            string = value;
            strLen = string.length;
            dataBuf = dataBuf.uint8(strLen).string(value, 'utf8');
            break;
        case 'strPreLenUint16':
            if (typeof value === 'string') {
				string = value;
				strLen = string.length;
				dataBuf = dataBuf.uint16(strLen).string(value, 'ucs2');
			}else if(Object.prototype.toString.call( value ) === '[object Array]' ) {
				strLen = value.length;
				dataBuf = dataBuf.uint16(strLen);
				
				for( let i=0; i<strLen; i++ ){
					dataBuf.uint8(value[i]);
				}
			}else{
				console.log('Type ' + typeof(value) + ' is unacceptable')
                throw new Error('The value for ' + type + ' must be an string.');
            }
            
            break;
    }
    if (dataBuf instanceof Concentrate) {
        return dataBuf.result();
    } else if (dataBuf instanceof Buffer) {
        return dataBuf;
    }
}

function isDataAnalogDigital(dataType) {
    let type = zclId.dataType(ensureDataTypeString(dataType)).value,
        analogDigital;

    if ((type > 0x07 && type < 0x20) ||  //GENERAL_DATA, LOGICAL, BITMAP
        (type > 0x2f && type < 0x38) ||  //ENUM
        (type > 0x3f && type < 0x58) ||  //STRING, ORDER_SEQ, COLLECTION
        (type > 0xe7 && type < 0xff))    //IDENTIFIER, MISC
    {
        analogDigital = 'DIGITAL';
    } else if (
        (type > 0x1f && type < 0x30) ||  //UNSIGNED_INT, SIGNED_INT
        (type > 0x37 && type < 0x40) ||  //FLOAT
        (type > 0xdf && type < 0xe8))    //TIME
    {
        analogDigital = 'ANALOG';
    }

    return analogDigital;
}

/*************************************************************************************************/
/*** Add Parsing Rules to DChunks                                                              ***/
/*************************************************************************************************/
ru.clause('uint24', function (name) {
    this.uint16('lsb').uint8('msb').tap(function () {
        let value;
        value = (this.vars.msb * 65536) + this.vars.lsb;
        this.vars[name] = value;
        delete this.vars.lsb;
        delete this.vars.msb;
    });
});

ru.clause('int24', function (name) {
    this.uint16('lsb').uint8('msb').tap(function () {
        let value,
            sign = (this.vars.msb & 0x80) >> 7;
        value = ((this.vars.msb & 0x7F) * 65536) + this.vars.lsb;
        if (sign) this.vars[name] = -(0x7FFFFF - value + 1);
        else this.vars[name] = value;
        delete this.vars.lsb;
        delete this.vars.msb;
    });
});

ru.clause('uint40', function (name) {
    this.uint32('lsb').uint8('msb').tap(function () {
        let value = [];
        value.push(this.vars.msb);
        value.push(this.vars.lsb);
        this.vars[name] = value;
        delete this.vars.lsb;
        delete this.vars.msb;
    });
});

//ru.clause('int40', function (name) { /*TODO*/ });

ru.clause('uint48', function (name) {
    this.uint32('lsb').uint16('msb').tap(function () {
        let value = [];
        value.push(this.vars.msb);
        value.push(this.vars.lsb);
        this.vars[name] = value;
        delete this.vars.lsb;
        delete this.vars.msb;
    });
});

//ru.clause('int48', function (name) { /*TODO*/ });

ru.clause('uint56', function (name) {
    this.uint32('lsb').uint16('xsb').uint8('msb').tap(function () {
        let value = [];
        value.push(this.vars.msb);
        value.push(this.vars.xsb);
        value.push(this.vars.lsb);
        this.vars[name] = value;
        delete this.vars.lsb;
        delete this.vars.xsb;
        delete this.vars.msb;
    });
});

//ru.clause('int56', function (name) { /*TODO*/ });

ru.clause('uint64', function (name) {
    this.buffer(name, 8).tap(function () {
        this.vars[name] = buf2Str(this.vars[name]);
    });
});

ru.clause('strPreLenUint8', function (name) {
    parsedBufLen += 1;
    this.uint8('len').tap(function () {
        parsedBufLen += this.vars.len;
        this.string(name, this.vars.len);
        delete this.vars.len;
    });
});

ru.clause('strPreLenUint16', function (name) {
    parsedBufLen += 2;
    this.uint16('len').tap(function () {
        parsedBufLen += this.vars.len;
        this.string(name, this.vars.len);
        delete this.vars.len;
    });
});

ru.clause('secKey', function (name) {
    this.buffer(name, 16).tap(function () {
        this.vars[name] = bufToArray(this.vars[name]);
    });
});

ru.clause('variable', function (name, dataTypeParam) {
    if (!dataTypeParam) dataTypeParam = 'dataType';

    this.tap(function () {
        let dataType = getDataType(this.vars[dataTypeParam]);
        ru[dataType](name)(this);
    });
});

ru.clause('attrVal', function () {
    let count = 0;

    parsedBufLen += 3;
    this.uint8('elmType').uint16('numElms').tap(function () {
        if (!this.vars.numElms) {
            this.vars.elmVals = [];
        } else {
            this.loop('elmVals', function (end) {
                ru.variable('data', 'elmType')(this);

                count += 1;
                if (count === this.vars.numElms) end();
            }).tap(function () {
                let tempArr = [];
                this.vars.elmVals.forEach(function (elmVal) {
                    if (elmVal.data) tempArr.push(elmVal.data);
                });
                this.vars.elmVals = tempArr;
            });
        }
    });
});

ru.clause('attrValStruct', function () {
    let count = 0;

    parsedBufLen += 2;
    this.uint16('numElms').tap(function () {
        if (!this.vars.numElms) {
            this.vars.structElms = [];
        } else {
            this.loop('structElms', function (end) {
                parsedBufLen += 1;
                this.uint8('elmType').tap(function () {
                    ru.variable('elmVal', 'elmType')(this);
                });

                count += 1;
                if (count === this.vars.numElms) end(); 
            }).tap(function () {
                this.vars.structElms.forEach(function (structElm) {
                    delete structElm.__proto__;
                });
            });
        }
    });
});

ru.clause('selector', function () {
    let count = 0;

    parsedBufLen += 1;
    this.tap('selector', function () {
        this.uint8('indicator').tap(function () {
            if (!this.vars.indicator) {
                this.indexes = [];
            } else {
                this.loop('indexes', function (end) {
                    parsedBufLen += 2;
                    this.uint16();

                    count += 1;
                    if (count === this.vars.indicator) end(); 
                }).tap(function () {
                    let tempArr = [];
                    this.vars.indexes.forEach(function (index) {
                        tempArr.push(index.undefined);
                    });
                    this.vars.indexes = tempArr;
                });
            }
        });
    }).tap(function () {
        delete this.vars.selector.__proto__;
    });
});

ru.clause('multi', function (name) {
    let flag = 0;

    this.tap(name, function () {
        let type = zclId.dataType(this.vars.dataType).key

        if (type === 'array' || type === 'set' || type === 'bag') {
            ru.attrVal()(this);
        } else if (type === 'struct') {
            ru.attrValStruct()(this);
        } else {
            flag = 1;
            ru.variable(name)(this);
        }
    }).tap(function () {
        delete this.vars[name].__proto__;
        if (flag) this.vars[name] = this.vars[name][name];
    });
});

ru.clause('readRsp', function () {
    this.tap(function () {
        if (this.vars.status === 0) {
            parsedBufLen += 1;
            this.uint8('dataType').tap(function () {
                ru.multi('attrData')(this);
            });
        }
    });
});

ru.clause('writeRsp', function () {
    this.uint8('status').tap(function () {
        if (this.vars.status === 0) {
            parsedBufLen += 1;
        } else {
            parsedBufLen += 3;
            this.uint16('attrId');
        }
    });
});


ru.clause('configReport', function () {
    this.tap(function () {
        if (this.vars.direction === 0) {
            parsedBufLen += 5;
            this.uint8('dataType').uint16('minRepIntval').uint16('maxRepIntval').tap(function () {
                let analogOrDigital = isDataAnalogDigital(this.vars.dataType);
                if (analogOrDigital === 'ANALOG') ru.variable('repChange')(this);
            });
        } else {
            parsedBufLen += 2;
            this.uint16('timeout');
        }
    });
});

ru.clause('configReportRsp', function () {
    this.uint8('status').tap(function () {
        if (this.vars.status === 0) {
            parsedBufLen += 1;
        } else {
            parsedBufLen += 4;
            this.uint8('direction').uint16('attrId');
        }
    });
});

ru.clause('readReportConfigRsp', function () {
    this.tap(function () {
        if (this.vars.status === 0) {
            ru.configReport()(this);
        }
    });
});

function buf2Str(buf) {
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

function bufToArray(buf) {
    let i,
        arr = [];

    for (i = 0; i < buf.length; i += 1) {
        arr.push(buf.readUInt8(i));
    }

    return arr;
}

module.exports = FoundPayload;
