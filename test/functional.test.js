let expect = require('chai').expect,
    Chance = require('chance'),
    chance = new Chance(),
    zclId = require('zcl-id');

let zclmeta = require('../lib/packet/ZclMeta'),
    FuncClass = require('../lib/packet/Functional');

let clusterIds = [],
    k;

for (k in zclId._common.clusterId) {
    clusterIds.push(k);
}

describe('Functional Cmd framer and parser Check', function() {
    clusterIds.forEach(function (cluster) {
        let cInfo = zclId._getCluster(cluster),
            cmdIds = [];

        if (!cInfo || !cInfo.cmd) return;

        cInfo.cmd.enums.forEach(function (cmdObj) {
            cmdIds.push(cmdObj.key);
        });

        cmdIds.forEach(function (cmd) {
            let funcObj,
                payload

            let meta = zclmeta.functional.get(cluster, cmd)
            if(!meta){
                console.log(`Unable to find metadata for ${cluster}, ${cmd}`)
                return
            }
            
            if (!meta.params || typeof meta.params == 'object') return;
            const reqArgs = {}
            if(!Array.isArray(meta.params)) {
                throw new Error(`Expected meta.params of ${cluster}, ${cmd} to be an array, got ${typeof meta.params}`)
            }

            for(const e of meta.params){
                reqArgs[e[0]] = randomArg(e[1])
            }

            funcObj = new FuncClass(cluster, 0, cmd);
            payload = funcObj.frame(reqArgs);

            const result = funcObj.parse(payload)
            it(funcObj.cmd + ' frame() and parse() check', function () {
                expect(result).to.eql(reqArgs);
            });
        });
    });
});

describe('Functional CmdRsp framer and parser Check', function() {
    clusterIds.forEach(function (cluster) {
        let cInfo = zclId._getCluster(cluster),
            cmdRspIds = [];

        if (!cInfo || !cInfo.cmdRsp) return;

        cInfo.cmdRsp.enums.forEach(function (cmdObj) {
            cmdRspIds.push(cmdObj.key);
        });

        cmdRspIds.forEach(function (cmdRsp) {
            let funcObj,
                payload

            let meta = zclmeta.functional.get(cluster, cmdRsp);
            if(!meta){
                console.log(`Unable to find metadata for ${cluster}, ${cmdRsp}`)
                return
            }

            if (!meta.params || typeof meta.params == 'object') return;
            const reqArgs = {}
            for(const e of meta.params){
                reqArgs[e[0]] = randomArg(e[1])
            }

            funcObj = new FuncClass(cluster, 1, cmdRsp);
            payload = funcObj.frame(reqArgs);

            const result = funcObj.parse(payload)
            it(funcObj.cmd + ' frame() and parse() check', function () {
                expect(result).to.eql(reqArgs);
            });
        });
    });
});

function randomArg(type) {
    let testBuf,
        testArr,
        k;

    switch (type) {
        case 'uint8':
            return chance.integer({min: 0, max: 255});
        case 'uint16':
            return chance.integer({min: 0, max: 65535});
        case 'uint32':
            return chance.integer({min: 0, max: 4294967295});
        case 'int8' :
            return chance.integer({min: -128, max: 127});
        case 'int16' :
            return chance.integer({min: -32768, max: 32767});
        case 'int32' :
            return chance.integer({min: -2147483648, max: 2147483647});
        case 'floatle':
            return chance.floating({min: 0, max: 4294967295});
        case 'longaddr':
            return '00124b00019c2ee9';
        case 'stringPreLen':
            let stringLen = chance.integer({min: 0, max: 255});
            return chance.string({length: stringLen});
        case 'preLenUint8':
        case 'preLenUint16':
        case 'preLenUint32':
            return 10;
        case 'dynUint8':
        case 'dynUint16':
        case 'dynUint24':
        case 'dynUint32':
            testArr = [];
            for (k = 0; k < 10; k += 1) {
                if (type === 'dynUint8')
                    testArr[k] = chance.integer({min: 0, max: 255});
                else if (type === 'dynUint16')
                    testArr[k] = chance.integer({min: 0, max: 65535});
                else if (type === 'dynUint24')
                    testArr[k] = chance.integer({min: 0, max: 16777215});
                else if (type === 'dynUint32')
                    testArr[k] = chance.integer({min: 0, max: 4294967295});
            }
            return testArr;
        case 'locationbuffer':
            testBuf = new Buffer(16);
            for (k = 0; k < 16; k += 1) {
                testBuf[k] = chance.integer({min: 0, max: 255});
            }
            return testBuf;
        case 'zonebuffer': 
            testArr = [];
            for (k = 0; k < 20; k += 2) {
                testArr[k] = chance.integer({min: 0, max: 255});
                testArr[k + 1] = chance.integer({min: 0, max: 65535});
            }
            return testArr;
        case 'extfieldsets':
            return [ { clstId: 0x0006, len: 0x3, extField: [0x01, 0x02, 0x03]}, { clstId: 0x0009, len: 0x5, extField: [0x05, 0x04, 0x03, 0x02, 0x01]} ];
        default:
            break;
    }

    return;
}
