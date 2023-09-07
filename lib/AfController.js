const EventEmitter = require('eventemitter2')
const Q = require('@halleyassist/q-lite')
const debug = require('debug')("zigbee-shepherd:afc")

class AfController extends EventEmitter {
    constructor(){
        super()
        this.setMaxListeners(100)
        this._trans = 0
    }

    eventListenerCount(){
        const events = this.eventNames()
        const ret = {}
        for(const name of events){
            ret[name] = this.listenerCount(name)
        }
        return ret
    }

    nextTransId () {  // zigbee transection id
        if (++this._trans > 255)
            this._trans = 1;
        return this._trans;
    }

    /* overriden by controllers doing indirect control */
    /* eslint-disable no-unused-vars */ 
    shouldSendIndrect(dstAddr){ 
        return false
    }
    /* eslint-enable no-unused-vars */ 

    registerResend(dstAddr, interestedCodes = [6, 0x10, 0x11, 0xb2]){
        const afResendEvt = 'ZDO:networkStatus:' + dstAddr.toString(16)
        let sendTime = Date.now()
        const deferred = Q.defer()
        let done = false

        const handleResend = data=>{
            if(done) return
            if(interestedCodes.includes(data.code) && (Date.now() - sendTime) > 6500){
                debug("possible indirect expiration, resending (status: 0x%s)", data.code.toString(16))
                done = true
                deferred.resolve(data.code)
            }
            
            this.removeListener(...eventArgs)
            this.once(...eventArgs)
        }

        const eventArgs = [afResendEvt, handleResend] // declaration gets hoisted, handleResend can reference it
        
        this.once(...eventArgs);

        const cleanup = ()=>{
            this.removeListener(...eventArgs)
            deferred.resolve(null)
        }

        return {cleanup, promise: deferred.promise}
    }
    async indirectSend(sendFn, cfg){
        const shouldIndirect = this.shouldSendIndrect(cfg.dstAddr)
        let retries = cfg.retries || 4
        if(!shouldIndirect || retries <= 1){
            retries = 1;
        }
    
        let workPromise

        // Loop retries times
        for(let i = 1; i<=retries; i++){
            let resend
            try {
                let attemptStart = Date.now()
                // Return immediately without retry if we can (racey)

                // Perform send
                if(i != 1) {
                    debug(`Doing indirect send attempt #${i}/${retries}`)
                }
            
                workPromise = sendFn()
                
                // It's a race for who can return first
                const promises = [Q.delay(cfg.indirectTimeout), workPromise]
                if(cfg.signalTimeout){
                    promises.push(cfg.signalTimeout.promise)
                }
                if(shouldIndirect){
                    resend = this.registerResend(cfg.dstAddr)
                    promises.push(resend.promise)
                }
                const result = await Q.cancelledRace(promises)

                // Handle results for any of the promises that might have returned
                if(result === 'signalResend'){
                    cfg.signalTimeout = Q.defer()
                    await await Q.cancelledRace([Q.delay(5000), workPromise]) // Wait at-least 5 seconds after a module error
                }
                else if(typeof result === 'number') {
                    if(result != 6 && i != retries) {
                        const waitTime = 3500 - (Date.now() - attemptStart)
                        if(waitTime > 0) await await Q.cancelledRace([Q.delay(waitTime), workPromise])
                    }
                }
                else if(result !== undefined) {
                    // should be the same as result
                    return await workPromise
                }
            } finally {
                if(resend) resend.cleanup()
            }
        }
        return await workPromise
    }
    async indirectRequestSend(cfg, ...args){
        return await this.indirectSend(async () => {
            // status code handled by catch
            return await Q.timeout(this.request(...args), cfg.completeTimeout)
        }, cfg)
    }
}
module.exports = AfController