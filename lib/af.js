/* jshint node: true */
'use strict';

var EventEmitter = require('events');

var Q = require('q'),
    _ = require('busyman'),
    Areq = require('areq'),
    zclId = require('zcl-id'),
    proving = require('proving'),
    assert = require('assert'),
    common = require('zstack-common')

var zcl = require('zcl-packet'),
    zutils = common.utils,
    ZSC = common.constants,
    seqNumber = 0,
	debug = require('debug')("zigbee-shepherd:af");

function format_af_error(errText, statusCode){
    var ret = errText + statusCode

    if (statusCode === 0xcd || statusCode === 'NWK_NO_ROUTE')
        ret += ". No network route. Please confirm that the device has (re)joined the network."
    else if (statusCode === 0xe9 || statusCode === 'MAC_NO_ACK')
        ret += ". MAC no ack."
    else if (statusCode === 0xb7 || statusCode === 'APS_NO_ACK')                // ZApsNoAck period is 20 secs
        ret += ". APS no ack."
    else if (statusCode === 0xf0 || statusCode === 'MAC_TRANSACTION_EXPIRED')   // ZMacTransactionExpired is 8 secs
        ret += ". MAC transaction expired."

    return ret
}


class Af extends EventEmitter {
    constructor(controller){
        super()
        this._areq = new Areq(this, 60000);
        /*
        controller must provide:
         - nextTransId
         - request
         - _indirect_send
        */
        this._controller = controller
        this._seq = 0
        this.indirectTimeout = 50000
        this.resendTimeout = 30000
        this.maxTransactions = 250
    }

    emit(eventName, ...args){
        super.emit(eventName, ...args)
        super.emit("all", {eventName, args})
    }

    nextZclSeqNum() {
        seqNumber += 1; // seqNumber is a private var on the top of this module
        if (seqNumber > 255 || seqNumber < 0 )
            seqNumber = 0;
    
        this._seq = seqNumber;
        return seqNumber;
    }

    // 4 types of message: dataConfirm, reflectError, incomingMsg, incomingMsgExt, zclIncomingMsg
    dispatchIncomingMsg(targetEp, remoteEp, type, msg) {
        let dispatchTo,     // which callback on targetEp
            zclHeader
            
        switch (type) {
            case 'dataConfirm':
                // msg: { status, endpoint, transid }
                this.emit('AF:dataConfirm:' + msg.endpoint + ':' + msg.transid, msg);  // sender(loEp) is listening, see send() and sendExt()
                dispatchTo = targetEp.onAfDataConfirm;
                break;
            case 'reflectError':
                // msg: { status, endpoint, transid, dstaddrmode, dstaddr }
                this.emit('AF:reflectError:' + msg.endpoint + ':' + msg.transid, msg);
                dispatchTo = targetEp.onAfReflectError;
                break;
            case 'incomingMsgExt':
            case 'incomingMsg':
                // msg: { groupid, clusterid, srcaddr, srcendpoint, dstendpoint, wasbroadcast, linkquality, securityuse, timestamp, transseqnumber, len, data }
                zclHeader = zcl.header(msg.data);       // a zcl packet maybe, pre-parse it to get the header
                dispatchTo = (type === "incomingMsg") ? targetEp.onAfIncomingMsg : targetEp.onAfIncomingMsgExt;
                break;
            case 'zclIncomingMsg':
                // msg.data is now msg.zclMsg
                const frameType = msg.zclMsg.frameCntl.frameType;

                this.emit('ZCL:incomingMsg:'+ msg.dstendpoint + ':' + msg.zclMsg.seqNum, msg);

                // { groupid, clusterid, srcaddr, srcendpoint, dstendpoint, wasbroadcast, linkquality, securityuse, timestamp, transseqnumber, zclMsg }
                if (targetEp.isLocal()) {
                    // to local app ep, receive zcl command or zcl command response. see zclFoudation() and zclFunctional()
                    if (!targetEp.isDelegator())
                        this.emit('ZCL:incomingMsg:' + msg.srcaddr + ':' + msg.srcendpoint + ':' + msg.dstendpoint + ':' + msg.zclMsg.seqNum, msg);
                } else {           
                    this.emit('ZCL:incomingMsg:' + msg.srcaddr + ':' + msg.srcendpoint + ':' + msg.dstendpoint + ':' + msg.zclMsg.seqNum, msg);
                    this.emit('ZCL:incomingMsg:' + msg.srcaddr + ':' + msg.srcendpoint + ':' + msg.zclMsg.seqNum, msg);

                    // Necessary, some IAS devices don't respect endpoints
                    if(msg.zclMsg.cmdId === 'statusChangeNotification' && frameType === 1 && msg.zclMsg.payload){   
                        this.emit('ind:statusChange', targetEp, msg.clusterid, msg.zclMsg.payload, msg);
                    } 
                }
                            
                if (frameType === 0 && msg.zclMsg.cmdId === 'report')
                    this.emit('ind:reported', targetEp, msg.clusterid, msg.zclMsg.payload);

                if (frameType === 0)         // foundation
                    dispatchTo = targetEp.onZclFoundation;
                else if (frameType === 1)    // functional
                    dispatchTo = targetEp.onZclFunctional;
                break;
        }

        if (typeof dispatchTo == "function") {
            dispatchTo.call(targetEp, msg, remoteEp);
        }

        if (type === 'zclIncomingMsg')  // no need for further parsing
            return;

        // further parse for ZCL packet from incomingMsg and incomingMsgExt
        if (zclHeader) {  // if (zclHeader && targetEp.isZclSupported()) {
            const zclIncomingParsedMsgEmitter = (err, zclData) => {
                if (!err) {
                    var parsedMsg = _.cloneDeep(msg);
                    parsedMsg.zclMsg = zclData;

                    this.emit('ZCL:incomingMsg', parsedMsg);
                }
            }

            // after zcl packet parsed, re-emit it
            if (zclHeader.frameCntl.frameType === 0) {          // foundation
                zcl.parse(msg.data, zclIncomingParsedMsgEmitter);
            } else if (zclHeader.frameCntl.frameType === 1) {   // functional
                zcl.parse(msg.data, msg.clusterid, zclIncomingParsedMsgEmitter);
            }
        }
    }
    makeAfParamsExt(loEp, addrMode, dstAddrOrGrpId, cId, rawPayload, opt) {
        opt = opt || {};    // opt = { options, radius, dstEpId, dstPanId }
    
        proving.number(cId, 'cId should be a number.');
    
        proving.defined(loEp, 'loEp should be defined');
    
        if (opt.hasOwnProperty('options'))
            proving.number(opt.options, 'opt.options should be a number.');
    
        if (opt.hasOwnProperty('radius'))
            proving.number(opt.radius, 'opt.radius should be a number.');
    
        var afOptions = ZSC.AF.options.DISCV_ROUTE,
            afParamsExt = {
                dstaddrmode: addrMode,
                dstaddr: zutils.toLongAddrString(dstAddrOrGrpId),
                destendpoint: 0xFF,
                dstpanid: opt.hasOwnProperty('dstPanId') ? opt.dstPanId : 0,
                srcendpoint: loEp.getEpId(),
                clusterid: cId,
                transid: this._controller ? this._controller.nextTransId() : null,
                options: opt.hasOwnProperty('options') ? opt.options : afOptions,
                radius: opt.hasOwnProperty('radius') ? opt.radius : ZSC.AF_DEFAULT_RADIUS,
                len: rawPayload.length,
                data: rawPayload
            };
    
        switch (addrMode) {
            case ZSC.AF.addressMode.ADDR_NOT_PRESENT:
                break;
            case ZSC.AF.addressMode.ADDR_GROUP:
                afParamsExt.destendpoint = 0xFF;
                break;
            case ZSC.AF.addressMode.ADDR_16BIT:
            case ZSC.AF.addressMode.ADDR_64BIT:
                afParamsExt.destendpoint = opt.hasOwnProperty('dstEpId') ? opt.dstEpId : 0xFF;
                afParamsExt.options = opt.hasOwnProperty('options') ? opt.options : afOptions | ZSC.AF.options.ACK_REQUEST;
                break;
            case ZSC.AF.addressMode.ADDR_BROADCAST:
                afParamsExt.destendpoint = 0xFF;
                afParamsExt.dstaddr = zutils.toLongAddrString(0xFFFF);
                break;
            default:
                afParamsExt = null;
                break;
        }
    
        return afParamsExt;
    }

    
    async send (srcEp, dstEp, cId, rawPayload, opt) {
        // srcEp maybe a local app ep, or a remote ep
        var deferred = Q.defer(),
            controller = this._controller,
            areq = this._areq,
            areqTimeout,
            afParams,
            afEventCnf,
            apsAck = false

        if (typeof cId === "string") {
            var cIdItem = zclId.cluster(cId);
            if (cIdItem === undefined) {
                deferred.reject(new Error('Invalid cluster id: ' + cId + '.'));
                return deferred.promise
            } else {
                cId = cIdItem.value;
            }
        }

        if (!Buffer.isBuffer(rawPayload))
            throw new TypeError('Af rawPayload should be a buffer.');

        opt = opt || {};

        if (opt.hasOwnProperty('timeout'))
            proving.number(opt.timeout, 'opt.timeout should be a number.');

        areqTimeout = opt.hasOwnProperty('timeout') ? opt.timeout : this.indirectTimeout;


        afParams = this.makeAfParams(srcEp, dstEp, cId, rawPayload, opt);
        afEventCnf = 'AF:dataConfirm:' + srcEp.getEpId() + ':' + afParams.transid;
        apsAck = afParams.options & ZSC.AF.options.ACK_REQUEST;

        var search = 0
        while (areq.isEventPending(afEventCnf) && search++ < this.maxTransactions) {
            afParams.transid = controller.nextTransId();
            afEventCnf = 'AF:dataConfirm:' + srcEp.getEpId() + ':' + afParams.transid;
        }
        if(search == this.maxTransactions){
            throw new Error("Too many transactions pending")
        }

        var indirecter, lastError

        areq.register(afEventCnf, deferred, function (cnf) {
            var errText = 'AF:dataRequest fails, status code: ';

            if (cnf.status === 0 || cnf.status === 'SUCCESS') {  // success
                this.emit('ind:dataConfirm', dstEp, afParams);
                areq.resolve(afEventCnf, cnf);
            } else {
                lastError = new Error(format_af_error(errText, cnf.status))
                
                if(cnf.status == 183 || cnf.status == 240 || cnf.status == 205){
                    indirecter.handleTimeout()
                } else if(cnf.status != 205){
                    areq.reject(afEventCnf, lastError)
                }
            }
        }, areqTimeout, false);
        
        indirecter = controller._indirect_send(dstEp.getNwkAddr(), function _sendBasic(){
            controller.request('AF', 'dataRequest', afParams).then(function (rsp) {
                areq.setTimeout(afEventCnf, areqTimeout)
                if (rsp.status !== 0 && rsp.status !== 'SUCCESS' )  // unsuccessful
                    areq.reject(afEventCnf, new Error('AF:dataRequest failed, status code: ' + rsp.status + '.'));
                else if (!apsAck)
                    areq.resolve(afEventCnf, rsp);
            }).catch(function (err) {
                areq.reject(afEventCnf, err);
            })
        }, deferred.promise)

        return deferred.promise.catch(function(e){
            if(e.code == 'ETIMEDOUT' && lastError){
                throw lastError
            }
            throw e
        })
    };

    async sendExt (srcEp, addrMode, dstAddrOrGrpId, cId, rawPayload, opt) {
        // srcEp must be a local ep
        var deferred = Q.defer(),
            controller = this._controller,
            areq = this._areq,
            areqTimeout,
            afParamsExt,
            afEventCnf,
            apsAck = false,
            senderEp = srcEp;

        assert (srcEp.isEndpoint && srcEp.isEndpoint(false), 'srcEp should be an instance of Endpoint class.')
        proving.number(addrMode, 'Af addrMode should be a number.');

        if (addrMode === ZSC.AF.addressMode.ADDR_16BIT || addrMode === ZSC.AF.addressMode.ADDR_GROUP)
            proving.number(dstAddrOrGrpId, 'Af dstAddrOrGrpId should be a number for netwrok address or group id.');
        else if (addrMode === ZSC.AF.addressMode.ADDR_64BIT)
            proving.string(dstAddrOrGrpId, 'Af dstAddrOrGrpId should be a string for long address.');

        if (typeof cId === 'string') {
            var cIdItem = zclId.cluster(cId);
            if (cIdItem === undefined) {
                deferred.reject(new Error('Invalid cluster id: ' + cId + '.'));
                return deferred.promise
            } else {
                cId = cIdItem.value;
            }
        }

        if (!Buffer.isBuffer(rawPayload))
            throw new TypeError('Af rawPayload should be a buffer.');

        opt = opt || {};

        if (opt.hasOwnProperty('timeout'))
            proving.number(opt.timeout, 'opt.timeout should be a number.');

        areqTimeout = opt.hasOwnProperty('timeout') ? opt.timeout : undefined;

        if (!senderEp.isLocal()) {
            deferred.reject(new Error('Only a local endpoint can groupcast, broadcast, and send extend message.'));
            return deferred.promise
        }

        afParamsExt = this.makeAfParamsExt(senderEp, addrMode, dstAddrOrGrpId, cId, rawPayload, opt);

        if (!afParamsExt) {
            deferred.reject(new Error('Unknown address mode. Cannot send.'));
            return deferred.promise
        }

        var indirecter, lastError

        if (addrMode === ZSC.AF.addressMode.ADDR_GROUP || addrMode === ZSC.AF.addressMode.ADDR_BROADCAST) {
            // no ack
            indirecter = controller._indirect_send(dstAddrOrGrpId, function _sendExt(){
                controller.request('AF', 'dataRequestExt', afParamsExt).then(function (rsp) {
                    if (rsp.status !== 0 && rsp.status !== 'SUCCESS')   // unsuccessful
                        deferred.reject(new Error('AF:dataExtend request failed, status code: ' + rsp.status + '.'));
                    else
                        deferred.resolve(rsp);  // Broadcast (or Groupcast) has no AREQ confirm back, just resolve this transaction.
                }).catch(function (err) {
                    deferred.reject(err);
                })
            }, deferred.promise)
        } else {
            afEventCnf = 'AF:dataConfirm:' + senderEp.getEpId() + ':' + afParamsExt.transid;
            apsAck = afParamsExt.options & ZSC.AF.options.ACK_REQUEST;

            var search = 0
            while (areq.isEventPending(afEventCnf) && search++ < this.maxTransactions) {
                afParamsExt.transid = controller.nextTransId();
                afEventCnf = 'AF:dataConfirm:' + senderEp.getEpId() + ':' + afParamsExt.transid;
            }
            if(search == this.maxTransactions){
                throw new Error("Too many transactions pending")
            }

            areq.register(afEventCnf, deferred, function (cnf) {
                var errText = 'AF:dataRequest fails, status code: ';
                if (cnf.status === 0 || cnf.status === 'SUCCESS') {  // success
                    areq.resolve(afEventCnf, cnf);
                } else {
                    lastError = new Error(format_af_error(errText, cnf.status))

                    if(cnf.status == 183 || cnf.status == 240){
                        indirecter.handleTimeout()
                    } else if(cnf.status != 205){
                        areq.reject(afEventCnf, lastError)
                    }
                }
            }, areqTimeout, false);

            indirecter = controller._indirect_send(dstAddrOrGrpId, function _sendExt(){
                controller.request('AF', 'dataRequestExt', afParamsExt).then(function (rsp) {
                    areq.setTimeout(afEventCnf, areqTimeout)
                    if (rsp.status !== 0 && rsp.status !== 'SUCCESS')   // unsuccessful
                        areq.reject(afEventCnf, new Error('AF:dataRequestExt failed, status code: ' + rsp.status + '.'));
                    else if (!apsAck)
                        areq.resolve(afEventCnf, rsp);
                }).catch(function (err) {
                    areq.reject(afEventCnf, err);
                })
            }, deferred.promise)
        }
        
        return deferred.promise.catch(function(e){
            if(e.code == 'ETIMEDOUT' && lastError){
                throw lastError
            }
            throw e
        })
    };

    async zclFoundation (srcEp, dstEp, cId, cmd, zclData, cfg) {
        var deferred = Q.defer(),
            areq = this._areq,
            dir = (srcEp === dstEp) ? 0 : 1,    // 0: client-to-server, 1: server-to-client
            manufCode = 0,
            frameCntl,
            seqNum,
            zclBuffer,
            mandatoryEvent;

            cfg = cfg || {};

        proving.stringOrNumber(cmd, 'cmd should be a number or a string.');
        proving.object(cfg, 'cfg should be a plain object if given.');

        frameCntl = {
            frameType: 0,       // command acts across the entire profile (foundation)
            manufSpec: cfg.hasOwnProperty('manufSpec') ? cfg.manufSpec : 0,
            direction: cfg.hasOwnProperty('direction') ? cfg.direction : dir,
            disDefaultRsp: cfg.hasOwnProperty('disDefaultRsp') ? cfg.disDefaultRsp : 0  // enable deafult response command
        };

        if (frameCntl.manufSpec === 1)
            manufCode = dstEp.getManufCode();

        // .frame(frameCntl, manufCode, seqNum, cmd, zclPayload[, clusterId])
        seqNum = cfg.hasOwnProperty('seqNum') ? cfg.seqNum : this.nextZclSeqNum();

        try {
            zclBuffer = zcl.frame(frameCntl, manufCode, seqNum, cmd, zclData);
        } catch (e) {
            if (e.message === 'Unrecognized command') {
                deferred.reject(e);
                return deferred.promise;
            } else {
                throw e;
            }
        }

        if (frameCntl.direction === 0) {    // client-to-server, thus require getting the feedback response

            if (srcEp === dstEp)    // from remote to remote itself
                mandatoryEvent = 'ZCL:incomingMsg:' + dstEp.getNwkAddr() + ':' + dstEp.getEpId() + ':' + seqNum;
            else                    // from local ep to remote ep
                mandatoryEvent = 'ZCL:incomingMsg:' + dstEp.getNwkAddr() + ':' + dstEp.getEpId() + ':' + srcEp.getEpId() + ':' + seqNum;

            areq.register(mandatoryEvent, deferred, function (msg) {
                // { groupid, clusterid, srcaddr, srcendpoint, dstendpoint, wasbroadcast, linkquality, securityuse, timestamp, transseqnumber, zclMsg }
                areq.resolve(mandatoryEvent, msg.zclMsg);
            });
        }

        var afOptions = cfg.hasOwnProperty('afOptions') ? cfg.afOptions : {}

        this.send(srcEp, dstEp, cId, zclBuffer, afOptions).catch(function (err) {
            if (mandatoryEvent && areq.isEventPending(mandatoryEvent))
                areq.reject(mandatoryEvent, err);
            else
                deferred.reject(err);
        }).then(function (rsp) {
            if (!mandatoryEvent)
                deferred.resolve(rsp);
        });

        return deferred.promise.catch((err)=>{
            if(err.code == "ETIMEDOUT"){
                err.message = "zclFoundation("+cmd+":"+seqNum+") " + err.message
            }
            throw err
        })
    }

    async zclFunctional (srcEp, dstEp, cId, cmd, zclData, cfg) {
        var deferred = Q.defer(),
            areq = this._areq,
            dir = (srcEp === dstEp) ? 0 : 1,    // 0: client-to-server, 1: server-to-client
            manufCode = 0,
            seqNum,
            frameCntl,
            zclBuffer,
            mandatoryEvent;

        assert (srcEp.isEndpoint && srcEp.isEndpoint(false), 'srcEp should be an instance of Endpoint class.')

        assert (dstEp.isEndpoint && dstEp.isEndpoint(true), 'dstEp should be an instance of Endpoint class.')

        if (typeof zclData !== 'object' || zclData === null)
            throw new TypeError(`zclData should be an object or an array (was ${typeof zclData})`);

        proving.stringOrNumber(cId, 'cId should be a number or a string.');
        proving.stringOrNumber(cmd, 'cmd should be a number or a string.');
        proving.object(cfg, 'cfg should be a plain object if given.');

        frameCntl = {
            frameType: 1,       // functional command frame
            manufSpec: cfg.hasOwnProperty('manufSpec') ? cfg.manufSpec : 0,
            direction: cfg.hasOwnProperty('direction') ? cfg.direction : dir,
            disDefaultRsp: cfg.hasOwnProperty('disDefaultRsp') ? cfg.disDefaultRsp : 0  // enable deafult response command
        };

        if (frameCntl.manufSpec === 1)
            manufCode = dstEp.getManufCode();

        // .frame(frameCntl, manufCode, seqNum, cmd, zclPayload[, clusterId])
        seqNum = cfg.hasOwnProperty('seqNum') ? cfg.seqNum : this.nextZclSeqNum();

        try {
            zclBuffer = zcl.frame(frameCntl, manufCode, seqNum, cmd, zclData, cId);
        } catch (e) {
            if (e.message === 'Unrecognized command' || e.message === 'Unrecognized cluster') {
                deferred.reject(e);
                return deferred.promise
            } else {
                deferred.reject(e);
                return deferred.promise
            }
        }

        if (frameCntl.direction === 0) {    // client-to-server, thus require getting the feedback response

            if (srcEp === dstEp)    // from remote to remote itself
                mandatoryEvent = 'ZCL:incomingMsg:' + dstEp.getNwkAddr() + ':' + dstEp.getEpId() + ':' + seqNum;
            else                    // from local ep to remote ep
                mandatoryEvent = 'ZCL:incomingMsg:' + dstEp.getNwkAddr() + ':' + dstEp.getEpId() + ':' + srcEp.getEpId() + ':' + seqNum;
            
            areq.register(mandatoryEvent, deferred, function (msg) {
                // { groupid, clusterid, srcaddr, srcendpoint, dstendpoint, wasbroadcast, linkquality, securityuse, timestamp, transseqnumber, zclMsg }
                areq.resolve(mandatoryEvent, msg.zclMsg);
            });
        }

        var afOptions = cfg.hasOwnProperty('afOptions') ? cfg.afOptions : {}

        // send(srcEp, dstEp, cId, rawPayload, opt)
        this.send(srcEp, dstEp, cId, zclBuffer, afOptions).catch(function (err) {
            if (mandatoryEvent && areq.isEventPending(mandatoryEvent))
                areq.reject(mandatoryEvent, err);
            else
                deferred.reject(err);
        }).then(function (rsp) {
            if (!mandatoryEvent)
                deferred.resolve(rsp);
        });

        return deferred.promise.catch((err)=>{
            if(err.code == "ETIMEDOUT"){
                err.message = "zclFunctional("+cmd+":"+seqNum+") " + err.message
            }
            throw err
        })
    };

    /*************************************************************************************************/
    /*** ZCL Cluster and Attribute Requests                                                        ***/
    /*************************************************************************************************/
    async zclClustersReq (dstEp, eventEmitter, interested) {    // callback(err, clusters)
    // clusters: {
    //    genBasic: { dir: 1, attrs: { x1: 0, x2: 3, ... } },   // dir => 0: 'unknown', 1: 'in', 2: 'out'
    //    fooClstr: { dir: 1, attrs: { x1: 0, x2: 3, ... } },
    //    ...
    // }

        var epId;
        try {
            epId = dstEp.getEpId();
        } catch (err){
            epId = null;
        }

        var clusters = {},
            clusterList = dstEp.getClusterList(),       // [ 1, 2, 3, 4, 5 ]
            inClusterList = dstEp.getInClusterList(),   // [ 1, 2, 3 ]
            outClusterList = dstEp.getOutClusterList(); // [ 1, 3, 4, 5 ]
            // clusterAttrsRsps = [];  // { attr1: x }, ...

        var i = 0;
        var error

        clusterList = filterInterestedCluster(clusterList)
        var totalLength = clusterList.length

        function cIdToString(cId){
            var cIdString = zclId.cluster(cId);
            return cIdString ? cIdString.key : cId;
        }

        const mappingFunc = cId => {
            var cIdString = cIdToString(cId)

            const handleAttributes = (attrs, error) => {
                i++;
                if (eventEmitter instanceof EventEmitter && !error) {
                    eventEmitter.emit('ind:interview', {
                        endpoint: {
                            current: epId,
                            cluster: {
                                total: totalLength,
                                current: i,
                                id: cId,
                                attrs: attrs,
                                error: error
                            }
                        }
                    });
                }

                if(typeof clusters[cIdString] == "undefined"){
                    clusters[cIdString] = {}
                }
                clusters[cIdString].i = i;
                clusters[cIdString].dir = inClusterList.includes(cId) ? (clusters[cIdString].dir | 0x01) : clusters[cIdString].dir;
                clusters[cIdString].dir = outClusterList.includes(cId) ? (clusters[cIdString].dir | 0x02) : clusters[cIdString].dir;
                clusters[cIdString].attrs = attrs;
                clusters[cIdString].id = cId;
                if(error) clusters[cIdString].error = error.toString();
            };

            return this.zclClusterAttrsReq(dstEp, cId, valueInterestedCluster(cId)).then(handleAttributes).catch(function(err){
                debug("An error occured when scanning ep: " + err);
                error = err
                handleAttributes({}, err);
            });
        };

        function filterInterestedCluster(clusterList){
            if(interested === true || typeof interested === "undefined") return clusterList
            var ret = []
            for(var i in clusterList){
                var cId = cIdToString(clusterList[i])
                var cInterest = interested[cId]
                if(typeof cInterest === "undefined") continue
                ret.push(cId)
            }
            return ret
        }

        function valueInterestedCluster(clusterId){
            if(interested === true || typeof interested === "undefined") return true
            if(interested[cIdToString(clusterId)]) return true
            return false
        }

        if(!clusterList.length){
            return Q(clusters) /* empty */
        }

        var first = clusterList.shift()
        
        return mappingFunc(first)
            .then(() => {
                return Q.all(clusterList.map(mappingFunc))
            })
            .then(() => {
                var completedAny, remainingErrors, itCount = 0
                const buildSlowChain = () => {
                    completedAny = remainingErrors = false
                    var slowChain = Q(0)
                    for(const cId in clusters){
                        const cluster = clusters[cId]
                        if(cluster.error){
                            slowChain = slowChain.then(()=>{
                                return this.zclClusterAttrsReq(dstEp, cluster.id, valueInterestedCluster(cId)).then(function(attrs){
                                    cluster.attrs = attrs
                                    cluster.error = undefined
                                    completedAny = true
                                }, function(err){
                                    cluster.error = err
                                    remainingErrors = true
                                }).then(function(){
                                    if (!cluster.error && eventEmitter instanceof EventEmitter) {
                                        eventEmitter.emit('ind:interview', {
                                            endpoint: {
                                                current: epId,
                                                cluster: {
                                                    total: totalLength,
                                                    current: cluster.i,
                                                    id: cluster.id,
                                                    attrs: cluster.attrs,
                                                    error: cluster.error
                                                }
                                            }
                                        });
                                    }
                                })
                            })
                        }
                    }
                    return slowChain
                }
                const recursiveSlowChain = () => {
                    itCount ++
                    debug("Executing slow chain iteration %d for %s", itCount, dstEp.getIeeeAddr())
                    return buildSlowChain().then(()=>{
                        if(completedAny && remainingErrors){
                            return recursiveSlowChain()
                        }else{
                            /* Give up */
                            for(const cId in clusters){
                                const cluster = clusters[cId]
                                if(cluster.error){
                                    if (eventEmitter instanceof EventEmitter) {
                                        eventEmitter.emit('ind:interview', {
                                            endpoint: {
                                                current: epId,
                                                cluster: {
                                                    total: totalLength,
                                                    current: cluster.i,
                                                    id: cluster.id,
                                                    attrs: cluster.attrs,
                                                    error: cluster.error
                                                }
                                            }
                                        });
                                    }
                                }
                            }
                        }
                    })
                }
                return recursiveSlowChain()
            })
            .then(() => {
                if(clusters.genBasic && Object.keys(clusters.genBasic.attrs).length == 0){
                    throw new Error("Unable to read genBasic, likely communication error");
                }
                return clusters
            })
    }

    async zclClusterAttrsReq (dstEp, cId, interestedValue) {
        return await this._zclClusterAttrsReq(dstEp, cId, interestedValue, this._controller.limitConcurrency)
    }
    async _zclClusterAttrsReq (dstEp, cId, interestedValue, limit) {
        assert (dstEp.isEndpoint && dstEp.isEndpoint(true), 'dstEp should be an instance of Endpoint class.')
            
        proving.stringOrNumber(cId, 'cId should be a number or a string.');

        if(!limit){
            limit = fn=>fn()
        }

        const attrIds = await limit(()=>this.zclClusterAttrIdsReq(dstEp, cId), dstEp.getIeeeAddr())(true)
        var attributes = []
        if(interestedValue === false){
            for(let i = 0; i<attrIds.length; i++){
                attributes.push({
                    attrId:attrIds[i],
                    attrData: null
                })
            }
        }else{    
            let readReq = [],
                attrsReqs = [],
                attrIdsLen = attrIds.length;

            for(const attrId in attrIds){
                readReq.push({ attrId });

                if (readReq.length === 5 || readReq.length === attrIdsLen) {
                    var req = _.cloneDeep(readReq);
                    attrsReqs.push(async () => {
                        /* Process in groups of 5 */
                        try {
                            const readStatusRecsRsp = await limit(()=>this.zclFoundation(dstEp, dstEp, cId, 'read', req), dstEp.getIeeeAddr())(true)
                            Array.prototype.push.apply(attributes,readStatusRecsRsp.payload);
                        } catch(err){
                            /* A failure occured - process in single reads */
                            debug("Failed to read chunk, processing individually")

                            var singleChain = Q(0)
                            req.forEach(function(r){
                                singleChain = singleChain.then(async () => {
                                    try {
                                        const readStatusRecsRsp = await limit(()=>this.zclFoundation(dstEp, dstEp, cId, 'read', [r]), dstEp.getIeeeAddr())(true)
                                        Array.prototype.push.apply(attributes,readStatusRecsRsp.payload);
                                    } catch(err){
                                        debug("An error occured when reading cluster: %s attr: %s. Error: %s", cId, r.attrId, err);
                                    }
                                });
                            })
                            return singleChain
                        }
                    });
                    attrIdsLen -= 5;
                    readReq = [];
                }
            }

            await Q.all(attrsReqs.map(c=>c()))
        }
        
        let attrs = {};
        for(const rec of attributes) {  // { attrId, status, dataType, attrData }
            var attrIdString = zclId.attr(cId, rec.attrId);

            attrIdString = attrIdString ? attrIdString.key : rec.attrId;

            attrs[attrIdString] = null;

            if (rec.status === 0)
                attrs[attrIdString] = rec.attrData;
        }
        
        return attrs;
    }

    zclClusterAttrIdsReq (dstEp, cId) {
        var deferred = Q.defer(),
            attrsToRead = [];

        assert (dstEp.isEndpoint && dstEp.isEndpoint(true), 'dstEp should be an instance of Endpoint class.')
            
        proving.stringOrNumber(cId, 'cId should be a number or a string.');

        const discAttrs =  async (startAttrId, defer) =>  {
            try {
                const discoverRsp = await this.zclFoundation(dstEp, dstEp, cId, 'discover', {
                    startAttrId: startAttrId,
                    maxAttrIds: 240
                })
            
                // discoverRsp.payload: { discComplete, attrInfos: [ { attrId, dataType }, ... ] }
                var payload = discoverRsp.payload,
                    discComplete = payload.discComplete,
                    attrInfos = payload.attrInfos,
                    nextReqIndex;

                for(const info of attrInfos) {
                    if (attrsToRead.includes(info.attrId))
                        attrsToRead.push(info.attrId);
                };

                if (discComplete === 0) {
                    nextReqIndex = attrInfos[attrInfos.length - 1].attrId + 1;
                    discAttrs(nextReqIndex, defer);
                } else {
                    defer.resolve(attrsToRead);
                }
            } catch(err){
                defer.reject(err)
            }
        }

        discAttrs(0, deferred);

        return deferred.promise
    }


    /*************************************************************************************************/
    /*** Private Functions                                                                         ***/
    /*************************************************************************************************/

    makeAfParams(loEp, dstEp, cId, rawPayload, opt) {
        opt = opt || {};    // opt = { options, radius }

        proving.number(cId, 'cId should be a number.');

        if (opt.hasOwnProperty('options'))
            proving.number(opt.options, 'opt.options should be a number.');

        if (opt.hasOwnProperty('radius'))
            proving.number(opt.radius, 'opt.radius should be a number.');

        let afOptions = ZSC.AF.options.DISCV_ROUTE    // ACK_REQUEST (0x10), DISCV_ROUTE (0x20)
        if(!zutils.isBroadcast(dstEp.getNwkAddr())){
            afOptions |= ZSC.AF.options.ACK_REQUEST
        }
        return {
            dstaddr: dstEp.getNwkAddr(),
            destendpoint: dstEp.getEpId(),
            srcendpoint: loEp.getEpId(),
            clusterid: cId,
            transid: this._controller ? this._controller.nextTransId() : null,
            options: opt.hasOwnProperty('options') ? opt.options : afOptions,
            radius: opt.hasOwnProperty('radius') ? opt.radius : ZSC.AF_DEFAULT_RADIUS,
            len: rawPayload.length,
            data: rawPayload
        };
    }
}

Af.msgHandlers = [
    { evt: 'AF:dataConfirm', hdlr: 'dataConfirm' },
    { evt: 'AF:reflectError', hdlr: 'reflectError' },
    { evt: 'AF:incomingMsg', hdlr: 'incomingMsg' },
    { evt: 'AF:incomingMsgExt', hdlr: 'incomingMsgExt' },
    { evt: 'ZCL:incomingMsg', hdlr: 'zclIncomingMsg' }
];

/*************************************************************************************************/
/*** module.exports                                                                            ***/
/*************************************************************************************************/

module.exports = Af