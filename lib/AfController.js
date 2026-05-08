const EventEmitter = require('./EventEmitterWithWaitFor')
const Q = require('@halleyassist/q-lite')
const debug = require('debug')("zstack-af:controller")

class AfController extends EventEmitter {
    /**
     */
    constructor(){
        super()
        this.setMaxListeners(100)
        this._trans = 0
    }

    /**
        * @returns {any}
     */
    eventListenerCount(){
        const events = this.eventNames()
        const ret = {}
        for(const name of events){
            ret[name] = this.listenerCount(name)
        }
        return ret
    }

    /**
     * @returns {number}
     */
    nextTransId () {  // zigbee transection id
        if (++this._trans > 255)
            this._trans = 1;
        return this._trans;
    }

    /* overriden by controllers doing indirect control */
    /* eslint-disable no-unused-vars */ 
    /**
     * @param {number} dstAddr
     * @returns {boolean}
     */
    shouldSendIndrect(dstAddr){ 
        return false
    }
    /* eslint-enable no-unused-vars */ 

    /**
     * @param {(attempt: number, canSrcRtg: boolean) => Promise<unknown>} sendFn
     * @param {import('./types').IndirectSendConfig} cfg
    * @returns {Promise<any>}
     */
    async indirectSend(sendFn, cfg){
        const shouldIndirect = this.shouldSendIndrect(cfg.dstAddr)
        let retries = cfg.retries || 4
        if(!shouldIndirect || retries <= 1){
            retries = 1;
        }
    
        let workPromise, canSrcRtg = true

        // Loop retries times
        for(let i = 1; i<=retries; i++){
            // Return immediately without retry if we can (racey)

            // Perform send
            if(i != 1) {
                debug(`Doing indirect send attempt ${i}/${retries}`)
            }
        
            workPromise = sendFn(i, canSrcRtg)
            
            // It's a race for who can return first
            const promises = [Q.delay(cfg.indirectTimeout), workPromise]
            if(cfg.signalTimeout){
                promises.push(cfg.signalTimeout.promise)
            }
            const result = await Q.cancelledRace(promises)

            // Handle results for any of the promises that might have returned
            if(result === 'resend'){
                // signalTimeout and signalResend can do these
                await Q.cancelledRace([Q.delay(5000), workPromise]) // Wait at-least 5 seconds after a module error
                canSrcRtg = false
            }
            else if(result !== undefined) {
                // should be the same as result
                return await workPromise
            } else {
                canSrcRtg = false
            }
        }
        return await workPromise
    }

    /**
     * @param {import('./types').IndirectSendConfig} cfg
     * @param {...unknown} args
    * @returns {Promise<any>}
     */
    async indirectRequestSend(cfg, ...args){
        return await this.indirectSend(async () => {
            // status code handled by catch
            return await Q.timeout((/** @type {any} */ (this)).request(...args), cfg.completeTimeout)
        }, cfg)
    }
}
module.exports = AfController