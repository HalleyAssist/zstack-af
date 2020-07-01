const EventEmitter = require('events')

class AfController extends EventEmitter {
    constructor(){
        super()
        this.setMaxListeners(30)
        this._trans = 0
    }

    nextTransId () {  // zigbee transection id
        if (++this._trans > 255)
            this._trans = 1;
        return this._trans;
    }


    shouldSendIndrect(dstAddr){ 
        return false
    }
    registerResend(dstAddr, interestedCodes = [6, 0x10, 0x11, 0xb2]){
        const afResendEvt = 'ZDO:networkStatus:' + dstAddr
        let sendTime = Date.now()
        const deferred = Q.defer()
        let done = false

        function handleResend(){
            if(done) reutrn
            if(interestedCodes.includes(data.code) && (Date.now() - sendTime) > 6500){
                debug.shepherd("possible indirect expiration, resending (status: 0x%s)", data.code.toString(16))
                done = true
                deferred.resolve(data.code)
            }
            
            this.once(...eventArgs);
        }

        const eventArgs = [afResendEvt, handleResend]
        
        this.once(...eventArgs);

        function cleanup(){
            this.removeListener(...eventArgs)
        }

        return {cleanup, promise: deferred.promise}
    }
    async indirectSend(workPromise, sendFn, cfg){
        const shouldIndirect = this.shouldSendIndrect(cfg.dstAddr)
        const retries = cfg.retries || 4
        if(!shouldIndirect || retries <= 1){
            retries = 1;
        }
        
        // Loop retries times
        try {
            for(let i = 1; i<=retries; i++){
                let attemptStart = Date.now()
                // Return immediately without retry if we can (racey)
                if(Q.isFulfilled(workPromise)){
                    return await workPromise
                }

                // Perform send
                await sendFn()
                
                // It's a race for who can return first
                const promises = [Q.delay(cfg.indirectTimeout), workPromise]
                if(cfg.signalTimeout){
                    promises.push(cfg.signalTimeout.promise)
                }
                if(shouldIndirect){
                    promises.push(this.registerResend(cfg.dstAddr))
                }
                const result = await Promise.race(promises)

                // Handle results for any of the promises that might have returned
                if(result === 'signalResend'){
                    cfg.signalTimeout = Q.defer()
                    await Promise.race([Q.delay(5000), workPromise]) // Wait at-least 5 seconds after a module error
                }
                else if(typeof result === 'number') {
                    if(result != 6 && i != retries) {
                        const waitTime = 3500 - (Date.now() - attemptStart)
                        if(waitTime > 0) await Promise.race([Q.delay(waitTime), workPromise])
                    }
                }
                else if(result !== undefined) {
                    // should be the same as result
                    return await workPromise
                }
            }
        } finally {
            if(cfg.signalTimeout) cfg.signalTimeout.cleanup()
        }

        // Return last error instead of timeout (if known)
        try {
             return await workPromise
        } catch(code){
            if(e.code == 'ETIMEDOUT' && lastError){
                throw lastError
            }
            throw e
        }
    }
    async indirectRequestSend(cfg, ...args){
        const deferred = Q.defer()
        const send = async () => {
            this.request(...args).then(deferred.resolve, deferred.reject) // status code handled by catch
        }
        const completion = deferred.promise.timeout(cfg.completeTimeout)

        return await this.indirectSend(completion, send, cfg)
    }
}
module.exports = AfController