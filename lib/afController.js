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

    _indirect_send (dstAddr, _send, promise){
        const r = _send() || {}
        r.handleTimeout = ()=>false
        return r;
    }
}
module.exports = AfController