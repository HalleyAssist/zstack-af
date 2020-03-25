const Q = require('q'),
      EventEmitter = require('events'),
      debug = require('debug')('zigbee-shepherd:afController')

class AfController extends EventEmitter {
    constructor(){
        super()
        this.setMaxListeners(30)
        this._transId = 0
    }

    nextTransId () {  // zigbee transection id
        if (++this._transId > 255)
            this._transId = 1;
        return this._transId;
    }

    _indirect_send (dstAddr, _send, promise){
        var sendTime, deferred = Q.defer()
        var self = this, afResendEvt = 'ZDO:networkStatus:' + dstAddr
        var ret, initialTime = Date.now()
        var eventArgs

        function setupEvent(){
            self.removeListener(...eventArgs)
            self.once(...eventArgs);
        }

        function handleResend(data){
            if(promise && promise.isPending && !promise.isPending()) {
                ret.isDone = true
                return
            }
            if(data.code != 6) {
                setupEvent()
            } else if((Date.now() - sendTime) > 6500){
                debug("possible indirect expiration, resending (status: 0x%s)", data.code.toString(16))
                send();
            }else{
                setupEvent()
            }
        }
        eventArgs = [afResendEvt, handleResend]

        function handleTimeout(){   
            if(promise && promise.isPending && !promise.isPending()) {
                ret.isDone = true
                return false
            }
            if((Date.now() - initialTime) < self._shepherd.af.resendTimeout){
                debug("possible indirect expiration due to timeout, resending")
                send()
                return true
            }
            return false
        }

        async function send(){
            sendTime = Date.now()
            setupEvent()
            var ret
            try {
                ret = await _send();
            }catch(ex){
                return deferred.reject(ex)
            }
            deferred.resolve(ret)
        }

        function done(){
            ret.isDone = true
            
            self.removeListener(...eventArgs)
        }

        send()

        ret = {evt: afResendEvt, result: deferred.promise, done: done, isDone: false, handleTimeout: handleTimeout}
        return ret
    }

    indirect_send (dstAddr, _send, promise){
        var ret = this._indirect_send(dstAddr, _send, promise)

        ret.result.finally(function(){
            ret.done()
        }).catch(function(){});

        return ret.result
    }
}
module.exports = AfController