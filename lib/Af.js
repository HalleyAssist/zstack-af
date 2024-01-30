/* jshint node: true */
'use strict';

const EventEmitter = require('eventemitter2'),
    Q = require('@halleyassist/q-lite'),
    zclId = require('zcl-id'),
    proving = require('proving'),
    assert = require('assert'),
    CcZnp = require('cc-znp'),
    Qos = require('./Qos'),
    Debug = require('debug')

var zcl = require('./Packet'),
    zutils = CcZnp.utils,
    ZSC = CcZnp.constants,
    debug = Debug("zstack-af"),
    zclDebug = Debug("zstack-af:ZCL");

function format_af_error(errText, statusCode) {
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

const AreqTimeout = 60000


function cIdToString(cId) {
    var cIdString = zclId.cluster(cId);
    return cIdString ? cIdString.key : cId;
}


class Af extends EventEmitter {
    constructor(controller, qos = null) {
        super()
        /*
        controller must provide:
         - nextTransId
         - request
         - _indirect_send
        */
        this._controller = controller
        
        // 0..250 random number to start seq with
        this._seq = Math.floor(Math.random() * 250)

        this.indirectTimeout = 70000
        this.resendTimeout = 8100
        this.maxTransactions = 250
        this.qos = qos || new Qos()
    }

    emit(eventName, ...args) {
        super.emit(eventName, ...args)
        super.emit("all", { eventName, args })
    }

    nextZclSeqNum() {
        this._seq ++; // seqNumber is a private var on the top of this module
        if (this._seq >= 253 || this._seq < 0) this._seq = 0;
        return this._seq;
    }

    // 4 types of message: dataConfirm, reflectError, incomingMsg, incomingMsgExt
    dispatchIncomingMsg(targetEp, remoteEp, type, msg) {
        let dispatchTo     // which callback on targetEp


        assert(targetEp, 'targetEp should be given.');
        assert(targetEp.isEndpoint && targetEp.isEndpoint(), "targetEp should be Endpoint")

        if (!targetEp.isLocal()) {
            debug("Received message that's not for us, skipping")
            return
        }

        switch (type) {
            case 'dataConfirm':
                // msg: { status, endpoint, trans }
                this.emit('AF:dataConfirm:' + msg.endpoint + ':' + msg.trans, msg);  // sender(srcEp) is listening, see send() and sendExt()
                dispatchTo = targetEp.onAfDataConfirm;
                break;
            case 'reflectError':
                // msg: { status, endpoint, trans, dstaddrmode, dstaddr }
                this.emit('AF:reflectError:' + msg.endpoint + ':' + msg.trans, msg);
                dispatchTo = targetEp.onAfReflectError;
                break;
            case 'incomingMsgExt':
            case 'incomingMsg':
                assert(remoteEp, 'remoteEp should be given.');
                // msg: { groupid, clusterid, srcaddr, srcendpoint, dstendpoint, wasbroadcast, linkquality, securityuse, timestamp, transseqnumber, len, data }

                // todo: just isZcl
                dispatchTo = (type === "incomingMsg") ? targetEp.onAfIncomingMsg : targetEp.onAfIncomingMsgExt;
                break;
        }

        if (dispatchTo) {
            dispatchTo.call(targetEp, msg, remoteEp);
        }

        if(type !== 'incomingMsgExt' && type !== 'incomingMsg') return

        let zclData

        // after zcl packet parsed, re-emit it
        try {
            zclData = zcl.parse(msg.data, msg.clusterid);
        } catch (ex) {
            const zclHeader = zcl.header(msg.data);
            debug(`Error parsing ZCL ${zclHeader.frameType ? 'functional' : 'foundation'} packet: ${ex}`);
            return
        }

        const frameType = zclData.frameCntl.frameType;
        if(zclDebug.enabled){
            zclDebug(`0x${msg.srcaddr.toString(16)}:${msg.srcendpoint}->0x00:${msg.dstendpoint} (${zclData.seqNum}) ${msg.clusterid} ${frameType === 0 ? 'foundation' : 'functional'}(${zclData.cmdId}) ${JSON.stringify(zclData.payload)}`);
        }

        const evt = {zclData, msg}
        this.emit('ZCL:incomingMsg', evt);

        if(zclData.frameCntl.direction === 1) {
            let prefix = 'ZCL:'+((frameType === 0 && zclData.cmdId !== 'defaultRsp') ? 'foundation' : 'functional')+':'
            
            // for broadcast responses only
            this.emit(prefix + msg.dstendpoint + ':' + zclData.seqNum, evt);

            prefix += msg.srcaddr.toString(16) + ':' + msg.srcendpoint + ':'

            // { groupid, clusterid, srcaddr, srcendpoint, dstendpoint, wasbroadcast, linkquality, securityuse, timestamp, transseqnumber, zclMsg }
            this.emit(prefix + msg.dstendpoint + ':' + zclData.seqNum, evt);

            this.emit(prefix + zclData.seqNum, evt);
        }
    
        if (frameType === 0 && zclData.cmdId === 'report')
            this.emit('ind:reported', { ep: remoteEp, cId: msg.clusterid, attrs: zclData.payload });

        let zApp = targetEp.zive
        if(zApp){
            if (frameType === 0 && zApp.foundationHandler)         // foundation
                zApp.foundationHandler(msg, zclData, remoteEp)
            else if (frameType === 1 && zApp.functionalHandler)    // functional
                zApp.functionalHandler(msg, zclData, remoteEp)
            return
        } else {
            // Necessary, some IAS devices don't respect endpoints
            if (zclData.cmdId === 'statusChangeNotification' && frameType === 1 && zclData.payload) {
                this.emit('ind:statusChange', { ep: remoteEp, cId: msg.clusterid, zclData: zclData, msg });
            }
        }
    }
    makeAfParamsExt(srcEp, addrMode, dstAddrOrGrpId, cId, rawPayload, opt) {
        opt = opt || {};    // opt = { options, radius, dstEpId, dstPanId }

        proving.number(cId, 'cId should be a number.');

        proving.defined(srcEp, 'srcEp should be defined');

        if (opt.options !== undefined)
            proving.number(opt.options, 'opt.options should be a number.');

        if (opt.radius !== undefined)
            proving.number(opt.radius, 'opt.radius should be a number.');

        var afOptions = 0,
            afParamsExt = {
                dstaddrmode: addrMode,
                dstaddr: zutils.toLongAddrString(dstAddrOrGrpId),
                dstep: 0xFF,
                dstpan: opt.dstPanId !== undefined ? opt.dstPanId : 0,
                srcep: srcEp.getEpId(),
                cluster: cId,
                trans: this._controller ? this._controller.nextTransId() : null,
                options: opt.options !== undefined ? opt.options : afOptions,
                radius: opt.radius !== undefined ? opt.radius : ZSC.AF_DEFAULT_RADIUS,
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
                afParamsExt.destendpoint = opt.dstEpId !== undefined ? opt.dstEpId : 0xFF;
                afParamsExt.options = opt.options !== undefined ? opt.options : afOptions | ZSC.AF.options.ACK_REQUEST;
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


    async send(srcEp, dstEp, cId, rawPayload, opt = {}) {
        // srcEp maybe a local app ep, or a remote ep
        if (!srcEp) srcEp = this._controller.getCoord().getDelegator()
        let controller = this._controller,
            areqTimeout,
            afParams,
            afEventCnf

        if (!srcEp) throw new Error("srcEp must be provided")
        if (!dstEp) throw new Error("dstEp must be provided")

        if (typeof cId === "string") {
            var cIdItem = zclId.cluster(cId);
            if (cIdItem === undefined) throw new Error('Invalid cluster id: ' + cId + '.')

            cId = cIdItem.value
        }

        if (!Buffer.isBuffer(rawPayload))
            throw new TypeError('Af rawPayload should be a buffer.');

        if (opt.timeout !== undefined)
            proving.number(opt.timeout, 'opt.timeout should be a number.');

        areqTimeout = opt.timeout !== undefined ? opt.timeout : this.indirectTimeout;


        // dataConfirm event
        afParams = this.makeAfParams(srcEp, dstEp, cId, rawPayload, opt);
        afEventCnf = 'AF:dataConfirm:' + srcEp.getEpId() + ':' + afParams.trans
        let search = 0
        while (this.listeners(afEventCnf).length && search++ < this.maxTransactions) {
            afParams.trans = controller.nextTransId();
            afEventCnf = 'AF:dataConfirm:' + srcEp.getEpId() + ':' + afParams.trans;
        }
        if (search >= this.maxTransactions) {
            throw new Error("Too many transactions pending")
        }

        const dstAddr = dstEp.nwkAddr
        const isBroadcast = zutils.isBroadcast(dstAddr)
        let lastError, shouldIndirect = controller.shouldSendIndrect(dstAddr) && !isBroadcast


        function areqC(){
            const ret = Q.defer()
            ret._cancels = new Set()
            ret.cancel = function(){
                for(const c in this._cancels){
                    c.cancel()
                }
                this._cancels = new Set()
            }
            ret.promise.catch(() => { })
            return ret
        }

        let shouldResend = false
        let signalTimeout = Q.defer()
        try {
            let areqCancelable = areqC()

            const startAreq = async (attempt) => {
                let cnf

                do {
                    /* resend without src rtg */
                    cnf = await areqCancelable.promise
                    areqCancelable = areqC()
                    cnf = cnf[0]
                    if (cnf.status === 0 || cnf.status === 'SUCCESS') {  // success
                        this.emit('ind:dataConfirm', { dstEp, afParams });
                        return cnf
                    } else if(cnf.status == 205) { // ZNwkNoRoute
                        await controller.request('NWK', 'rtg', { nwkaddr: dstAddr })
                        await Q.delay(((Math.random()/4) + 0.75) * 16000)
                        await controller.request('NWK', 'rtg', { nwkaddr: dstAddr })
                        if(attempt > 1) {
                            shouldResend = false
                        }
                    }

                    if (shouldResend) {
                        shouldResend = false
                        await afSend()
                    }
                } while (shouldResend)

                lastError = new Error(format_af_error('AF:dataRequest fails, status code: ', cnf.status))
                if (shouldIndirect) {
                    if (cnf.status == ZSC.cmdStatus.APS_NO_ACK || cnf.status == ZSC.cmdStatus.MAC_TRANSACTION_EXPIRED) { // || cnf.status == 205
                        signalTimeout.resolve("resend")
                    }
                    if (cnf.status != 205) {
                        throw lastError
                    }
                } else {
                    throw lastError
                }
            }

            const afSend = async (canSrcRtg) => {
                let rsp
                if (!isBroadcast && dstEp.getSrcRtg && canSrcRtg) {
                    const srcRtg = dstEp.getSrcRtg()
                    if (srcRtg) {
                        let options = afParams.options | 0
                        
                        // Prevent route discovery, and hence prevents an overload of route requests
                        // But also reduces deliverability for downstream routers as a flag is set on the packet
                        // We could probably work around this by sending a route request first or by using a custom flag
                        // But for now disabled
                        //options |= ZSC.AF.options.SUPRESS_ROUTE_DISC
                        
                        if(srcRtg.length === 0 && dstEp.isRouter()){
                            options |= ZSC.AF.options.SKIP_ROUTING
                        }
                        const newAfParams = Object.assign(Af.buildAfSrcRtg(srcRtg), afParams, { options })
                        do {
                            let wf = this.waitFor(afEventCnf, areqTimeout)
                            wf.catch(()=>{})
                            areqCancelable._cancels.add(wf)


                            try {
                                rsp = await controller.request('AF', 'dataRequestSrcRtg', newAfParams) // status code handled by catch
                            } catch(ex){
                                if(ex.status == 178) { // ZApsTableFull
                                    wf.cancel()
                                    areqCancelable._cancels.delete(wf)
                                    await Q.delay((Math.random() + 0.5) * 16000)

                                    // in case the src rtg changed
                                    const srcRtg = dstEp.getSrcRtg()
                                    if(!srcRtg) break;
                                    Object.assign(newAfParams, Af.buildAfSrcRtg(srcRtg))

                                    continue
                                } else {
                                    throw ex
                                }
                            }      
                            wf.then(areqCancelable.resolve, areqCancelable.reject) 
                            break
                        } while(true) // ZApsTableFull
                        shouldResend = true
                    }
                }
                if (!rsp) {
                    do {
                        let wf = this.waitFor(afEventCnf, areqTimeout)
                        wf.catch(()=>{})
                        areqCancelable._cancels.add(wf)
                        try {
                            rsp = await controller.request('AF', 'dataRequest', afParams) // status code handled by catch
                        } catch(ex){
                            if(ex.status == 178) { // ZApsTableFull
                                wf.cancel()
                                areqCancelable._cancels.delete(wf)
                                await Q.delay((Math.random() + 0.5) * 16000)
                                continue
                            }
                            throw ex
                        }
                        wf.then(areqCancelable.resolve, areqCancelable.reject)
                        break
                    } while(true) // ZApsTableFull
                    
                }
            }

            const indirectSendFn = async (attempt, canSrcRtg) => {
                try {
                    await afSend(canSrcRtg)
                    return await startAreq(attempt)
                } catch (ex) {
                    areqCancelable.cancel()
                    throw ex
                }
            }

            if (!shouldIndirect) {
                await indirectSendFn()
            }
            return await controller.indirectSend(indirectSendFn, { signalTimeout, indirectTimeout: this.indirectTimeout, dstAddr, retries: opt.retries })
        } finally {
            signalTimeout.resolve(null)
        }
    }

    static async areqCancel(areq){
        const a = areq.catch(ex => {
            if (!ex || ex.message !== "canceled") throw ex
        })
        areq.cancel()
        await a
    }

    async _zclFoundation(srcEp, dstEp, cId, cmd, zclData, cfg) {
        var areq,
            manufCode = 0,
            frameCntl,
            seqNum,
            zclBuffer,
            mandatoryEvent;

        cfg = cfg || {};

        if (!srcEp) {
            srcEp = this._controller.getCoord().getDelegator()
            if (!srcEp) {
                debug('No srcEp specified, and no delegator found')
                return
            }
        }

        assert(srcEp, 'srcEp should be given.');
        assert(dstEp, 'dstEp should be given.');
        assert(srcEp.isEndpoint && srcEp.isEndpoint(true), 'srcEp should be an instance of Endpoint class.')
        assert(dstEp.isEndpoint && dstEp.isEndpoint(), 'dstEp should be an instance of Endpoint class.')

        proving.stringOrNumber(cmd, 'cmd should be a number or a string.');
        proving.object(cfg, 'cfg should be a plain object if given.');

        frameCntl = {
            frameType: 0,       // command acts across the entire profile (foundation)
            manufSpec: cfg.manufSpec !== undefined ? cfg.manufSpec : 0,
            direction: cfg.direction !== undefined ? cfg.direction : 0, // 0: client-to-server, 1: server-to-client
            disDefaultRsp: cfg.disDefaultRsp !== undefined ? cfg.disDefaultRsp : 0  // enable default response command
        };

        if (frameCntl.manufSpec === 1)
            manufCode = dstEp.getManufCode();

        // .frame(frameCntl, manufCode, seqNum, cmd, zclPayload[, clusterId])
        seqNum = cfg.seqNum !== undefined ? cfg.seqNum : this.nextZclSeqNum();
        
        if(dstEp._logger) dstEp._logger(`zclFoundation(${cmd}:${seqNum}) ${JSON.stringify(zclData)}`)

        zclBuffer = zcl.frame(frameCntl, manufCode, seqNum, cmd, zclData);

        if (frameCntl.direction === 0 && !cfg.response) {    // client-to-server, thus require getting the feedback response

            const nwkAddr = dstEp.nwkAddr
            assert(typeof nwkAddr === 'number')
            if (srcEp === dstEp)    // from remote to remote itself
                mandatoryEvent = 'ZCL:foundation:' + nwkAddr.toString(16) + ':' + dstEp.getEpId() + ':' + seqNum;
            else                    // from local ep to remote ep
                mandatoryEvent = 'ZCL:foundation:' + nwkAddr.toString(16) + ':' + dstEp.getEpId() + ':' + srcEp.getEpId() + ':' + seqNum;

            areq = this.waitFor(mandatoryEvent)
        }

        var afOptions = cfg.afOptions !== undefined ? cfg.afOptions : {}

        let rsp
        try {
            rsp = await this.send(srcEp, dstEp, cId, zclBuffer, afOptions)
        } catch (err) {
            if (areq) {
                await Af.areqCancel(areq)
            }
            if (err.code == "ETIMEDOUT") {
                err.message = "zclFoundation(" + cmd + ":" + seqNum + ") " + err.message
            }
            throw err
        }

        if (!mandatoryEvent) {
            return rsp
        }

        try {
            rsp = await Q.timeout(areq, AreqTimeout)
        } catch (err) {
            if (err.code == "ETIMEDOUT") {
                if (areq) {
                    await Af.areqCancel(areq)
                }
                err.message = "zclFoundation(" + cmd + ":" + seqNum + ") " + err.message
            }
            throw err
        }

        return rsp[0].zclData
    }

    async _zclFunctional(srcEp, dstEp, cId, cmd, zclData, cfg) {
        var areq,
            manufCode = 0,
            seqNum,
            frameCntl,
            zclBuffer,
            mandatoryEvent;

        if (!srcEp) {
            srcEp = this._controller.getCoord().getDelegator()
            if (!srcEp) {
                debug('No srcEp specified, and no delegator found')
                return
            }
        }

        assert(srcEp, 'srcEp should be given.');
        assert(dstEp, 'dstEp should be given.');
        assert(srcEp.isEndpoint && srcEp.isEndpoint(true), 'srcEp should be an instance of Endpoint class.')
        assert(dstEp.isEndpoint && dstEp.isEndpoint(), 'dstEp should be an instance of Endpoint class.')

        if (typeof zclData !== 'object' || zclData === null)
            throw new TypeError(`zclData should be an object or an array (was ${typeof zclData})`);

        proving.stringOrNumber(cId, 'cId should be a number or a string.');
        proving.stringOrNumber(cmd, 'cmd should be a number or a string.');
        proving.object(cfg, 'cfg should be a plain object if given.');

        frameCntl = {
            frameType: 1,       // functional command frame
            manufSpec: cfg.manufSpec !== undefined ? cfg.manufSpec : 0,
            direction: cfg.direction !== undefined ? cfg.direction : 0, // 0: client-to-server, 1: server-to-client
            disDefaultRsp: cfg.disDefaultRsp !== undefined ? cfg.disDefaultRsp : 0  // enable deafult response command
        };

        if (frameCntl.manufSpec === 1)
            manufCode = dstEp.getManufCode();

        // .frame(frameCntl, manufCode, seqNum, cmd, zclPayload[, clusterId])
        seqNum = cfg.seqNum !== undefined ? cfg.seqNum : this.nextZclSeqNum();
        
        if(dstEp._logger) dstEp._logger(`zclFunctional(${cmd}:${seqNum}) ${JSON.stringify(zclData)}`)

        zclBuffer = zcl.frame(frameCntl, manufCode, seqNum, cmd, zclData, cId);

        if (frameCntl.direction === 0 && !cfg.response) {    // client-to-server, thus require getting the feedback response

            if (srcEp === dstEp)    // from remote to remote itself
                mandatoryEvent = 'ZCL:functional:' + dstEp.nwkAddr.toString(16) + ':' + dstEp.getEpId() + ':' + seqNum;
            else                    // from local ep to remote ep
                mandatoryEvent = 'ZCL:functional:' + dstEp.nwkAddr.toString(16) + ':' + dstEp.getEpId() + ':' + srcEp.getEpId() + ':' + seqNum;


            areq = this.waitFor(mandatoryEvent)
        }

        var afOptions = cfg.afOptions !== undefined ? cfg.afOptions : {}

        let rsp
        try {
            rsp = await this.send(srcEp, dstEp, cId, zclBuffer, afOptions)
        } catch (err) {
            if (areq) {
                await Af.areqCancel(areq)
            }
            if (err.code == "ETIMEDOUT") {
                err.message = "zclFunctional(" + cmd + ":" + seqNum + ") " + err.message
            }
            throw err
        }

        if (!areq) {
            return rsp
        }

        try {
            rsp = await Q.timeout(areq, AreqTimeout)
        } catch (err) {
            if (err.code == "ETIMEDOUT") {
                if (areq) {
                    await Af.areqCancel(areq)
                }
                err.message = "zclFunctional(" + cmd + ":" + seqNum + ") " + err.message
            }
            throw err
        }

        return rsp[0].zclData
    }

    async zclFoundation(srcEp, dstEp, cId, cmd, zclData, cfg) {
        if (cfg && (cfg.skipQos || cfg.response)) {
            return await this._zclFoundation(srcEp, dstEp, cId, cmd, zclData, cfg)
        }
        return await this.qos.execute(async () => {
            return await this._zclFoundation(srcEp, dstEp, cId, cmd, zclData, cfg)
        }, dstEp.nwkAddr)
    }

    async zclFunctional(srcEp, dstEp, cId, cmd, zclData, cfg) {
        if (cfg && (cfg.skipQos || cfg.response)) {
            return await this._zclFunctional(srcEp, dstEp, cId, cmd, zclData, cfg)
        }
        return await this.qos.execute(async () => {
            return await this._zclFunctional(srcEp, dstEp, cId, cmd, zclData, cfg)
        }, dstEp.nwkAddr)
    }

    _epInterestedDirectionalClusterMap(dstEp, interested) {
        const clusters = {}
        for (const c of dstEp.getInClusterList()) {
            clusters[cIdToString(c)] = { id: c, dir: 0x01 }
        }
        for (const cId of dstEp.getOutClusterList()) {
            const c = cIdToString(cId)
            if (!clusters[c]) clusters[c] = { id: c, dir: 0 }
            clusters[c].dir = clusters[c].dir | 0x02
        }
        if (typeof interested === 'object') {
            for (const c in clusters) {
                if (interested[c] === undefined) delete clusters[c]
            }
        }
        return clusters
    }

    /*************************************************************************************************/
    /*** ZCL Cluster and Attribute Requests                                                        ***/
    /*************************************************************************************************/
    async zclClustersReq(srcEp, dstEp, eventEmitter, interested) {    // callback(err, clusters)
        if (!srcEp) srcEp = this._controller.getCoord().getDelegator()
        // clusters: {
        //    genBasic: { dir: 1, attrs: { x1: 0, x2: 3, ... } },   // dir => 0: 'unknown', 1: 'in', 2: 'out'
        //    fooClstr: { dir: 1, attrs: { x1: 0, x2: 3, ... } },
        //    ...
        // }

        const epId = dstEp.getEpId();

        const clusters = this._epInterestedDirectionalClusterMap(dstEp, interested)       // [ 1=>0x1,4=>0x2|0x1 ]

        let i = 0
        const totalLength = Object.keys(clusters).length

        for (const cId in clusters) {
            let attrs = {}, error
            const valueInterested = (interested === true || interested === undefined || interested[cId])
            try {
                attrs = await this.zclClusterAttrsReq(srcEp, dstEp, cId, valueInterested)
            } catch (ex) {
                error = ex
            }
            i++;
            if (eventEmitter instanceof EventEmitter && !error) {
                eventEmitter.emit('ind:interview', {
                    endpoint: {
                        current: epId,
                        cluster: {
                            total: totalLength,
                            current: i,
                            id: cId,
                            attrs,
                            error
                        }
                    }
                });
            }

            Object.assign(clusters[cId], { i, attrs, error })
        }

        // clusters genBasic will exist if we are interested in genBasic (else we must already have it)
        // 
        if (clusters.genBasic) {
            if (clusters.genBasic.error) {
                throw new Error("Unable to read genBasic, " + clusters.genBasic.error)
            } else if (Object.keys(clusters.genBasic.attrs).length == 0) {
                throw new Error("Unable to read genBasic, likely communication error");
            }
        }


        return clusters
    }

    /** 
    Get all attributes values for a given cluster

    interestedValue = false - return only the structure with null values
    
     */
    async zclClusterAttrsReq(srcEp, dstEp, cId, interestedValue) {
        if (!srcEp) srcEp = this._controller.getCoord().getDelegator()
        return await this._zclClusterAttrsReq(srcEp, dstEp, cId, interestedValue)
    }
    async _zclClusterAttrsReq(srcEp, dstEp, cId, interestedValue) {
        if (!srcEp) srcEp = this._controller.getCoord().getDelegator()
        assert(dstEp.isEndpoint && dstEp.isEndpoint(), 'dstEp should be an instance of Endpoint class.')
        proving.stringOrNumber(cId, 'cId should be a number or a string.');

        const attrIds = await this.zclClusterAttrIdsReq(srcEp, dstEp, cId)
        var attributes = []
        if (interestedValue === false) {
            for (let i = 0; i < attrIds.length; i++) {
                attributes.push({
                    attrId: attrIds[i],
                    attrData: null
                })
            }
        } else {
            attributes = await this.zclReadAllAttributes(srcEp, dstEp, cId, attrIds)
        }

        return this._mapAttributes(cId, attributes);
    }

    async zclReadAllAttributes(srcEp, dstEp, cId, attrIds) {
        if (!srcEp) srcEp = this._controller.getCoord().getDelegator()
        const ret = []

        let readReq = []

        const handleRequest = async () => {
            /* Process in groups of 5 */
            try {
                const readStatusRecsRsp = await Q.timeout(this.zclFoundation(srcEp, dstEp, cId, 'read', readReq), 30000)
                Array.prototype.push.apply(ret, readStatusRecsRsp.payload);
            } catch (err) {
                if (err.code == "ETIMEDOUT") {
                    debug(`A timeout occured when reading attributes from cluster: ${cId}. Error: ${err}`);
                } else {
                    /* A failure occured - process in single reads */
                    for (const r of readReq) {
                        try {
                            const readStatusRecsRsp = await Q.timeout(this.zclFoundation(srcEp, dstEp, cId, 'read', [r]), 15000)
                            Array.prototype.push.apply(ret, readStatusRecsRsp.payload);
                        } catch (err) {
                            debug(`An error occured when reading cluster: ${cId} attr: ${r.attrId}. Error: ${err}`);
                        }
                    }
                }
            }
        }

        for (const attrId of attrIds) {
            readReq.push({ attrId });

            if (readReq.length === 5) {
                await handleRequest()
                readReq = []
            }
        }
        if (readReq.length) {
            await handleRequest()
        }

        return ret
    }

    _mapAttributes(cId, attributes) {
        let attrs = {};
        for (const rec of attributes) {  // { attrId, status, dataType, attrData }
            var attrIdString = zclId.attr(cId, rec.attrId);

            attrIdString = attrIdString ? attrIdString.key : rec.attrId;

            attrs[attrIdString] = null;

            if (rec.status === 0)
                attrs[attrIdString] = rec.attrData;
        }
        return attrs
    }

    /*
    Discover all attributeIds for a given cluster
    */
    async zclClusterAttrIdsReq(srcEp, dstEp, cId) {
        if (!srcEp) srcEp = this._controller.getCoord().getDelegator()

        assert(srcEp.isEndpoint && srcEp.isEndpoint(true), 'srcEp should be an instance of Endpoint class.')
        assert(dstEp.isEndpoint && dstEp.isEndpoint(), 'dstEp should be an instance of Endpoint class.')

        proving.stringOrNumber(cId, 'cId should be a number or a string.');

        const attrsToRead = [];
        let startAttrId = 0
        do {
            const discoverRsp = await this.zclFoundation(srcEp, dstEp, cId, 'discover', {
                startAttrId,
                maxAttrIds: 240
            })

            const attrInfos = discoverRsp.payload.attrInfos
            for (const info of attrInfos) {
                if (!attrsToRead.includes(info.attrId))
                    attrsToRead.push(info.attrId);
            }

            if (discoverRsp.payload.discComplete === 0) {
                startAttrId = attrInfos[attrInfos.length - 1].attrId + 1;
            } else {
                startAttrId = false
            }
        } while (startAttrId)

        return attrsToRead
    }


    /*************************************************************************************************/
    /*** Private Functions                                                                         ***/
    /*************************************************************************************************/

    makeAfParams(srcEp, dstEp, cId, rawPayload, opt) {
        if (!srcEp) srcEp = this._controller.getCoord().getDelegator()
        opt = opt || {};    // opt = { options, radius }

        proving.number(cId, 'cId should be a number.');

        if (opt.options !== undefined)
            proving.number(opt.options, 'opt.options should be a number.');

        if (opt.radius !== undefined)
            proving.number(opt.radius, 'opt.radius should be a number.');

        let afOptions = 0
        if (!zutils.isBroadcast(dstEp.nwkAddr)) {
            afOptions = ZSC.AF.options.ACK_REQUEST
        }

        return {
            dstaddr: dstEp.nwkAddr,
            dstep: dstEp.getEpId(),
            srcep: srcEp.getEpId(),
            cluster: cId,
            trans: this._controller ? this._controller.nextTransId() : null,
            options: opt.options !== undefined ? opt.options : afOptions,
            radius: opt.radius !== undefined ? opt.radius : ZSC.AF_DEFAULT_RADIUS,
            len: rawPayload.length,
            data: rawPayload
        };
    }

    static parseRelayList(rl) {
        const ret = []
        for (let i = 0; i < rl.length; i += 2) {
            ret.push(rl.readUInt16LE(i))
        }
        return ret
    }

    static buildAfSrcRtg(srcRtg) {
        /*const buffer = Buffer.alloc(srcRtg.length * 2)
        for(let i = 0; i<srcRtg.length; i++) {
            buffer.writeUInt16LE(srcRtg[i], i*2)
        }*/
        return { relaycount: srcRtg.length, relaylist: srcRtg }
    }
}

Af.msgHandlers = [
    { evt: 'AF:dataConfirm', hdlr: 'dataConfirm' },
    { evt: 'AF:reflectError', hdlr: 'reflectError' },
    { evt: 'AF:incomingMsg', hdlr: 'incomingMsg' },
    { evt: 'AF:incomingMsgExt', hdlr: 'incomingMsgExt' }
];

/*************************************************************************************************/
/*** module.exports                                                                            ***/
/*************************************************************************************************/

module.exports = Af
