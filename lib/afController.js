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
        const r = _send() || {}
        r.handleTimeout = ()=>{}
        return r;
    }
}
module.exports = AfController