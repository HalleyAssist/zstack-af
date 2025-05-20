/* jshint node: true */
'use strict';

let Enum = require('light-enum'),
    zclId = require('zcl-id'),
    zclMeta = require('./defs/meta.json')

function loadZclMeta(){
    const zclDefs = require('./defs/defs.json');

    return {
        foundation: {},
        functional: {},
        Direction: new Enum(zclDefs.Direction),
        ParamType: new Enum(zclDefs.ParamType)
    }
}

let zclmeta = loadZclMeta();

function prepareParams(){
    const EmptyMap = new Map()
    const dict = {}
    function prepareParam(params){
        let p = EmptyMap
        if(!Array.isArray(params)){
            p = {}
            for(const k in params){
                p[k] = prepareParam(params[k])
            }
            return p
        }
        if(params.length) p = new Map(params)
        const key = JSON.stringify([...p])
        if(dict[key]) return dict[key]
        for(const e of p){    
            const t = zclmeta.ParamType.get(e[1])
            if(t) p.set(e[0], t.key)
        }
        dict[key] = p
        return p
    }

    for(let cmd in zclMeta.foundation){
        cmd = zclMeta.foundation[cmd]
        cmd.params = prepareParam(cmd.params)
    }
    for(let subsys in zclMeta.functional){
        subsys = zclMeta.functional[subsys]
        for(let cmd in subsys){
            cmd = subsys[cmd]
            cmd.params = prepareParam(cmd.params)
        }
    }
}
prepareParams()

zclmeta.foundation.get = function (cmd) {
    let meta = zclMeta.foundation;
    return meta ? meta[cmd] : undefined;
};

zclmeta.functional.get = function (cluster, cmd) {
    let meta = zclMeta.functional[cluster];
    return meta ? meta[cmd] : undefined;
    // return: {
    //  dir,
    //  params: [ { name: type }, ... ]
    // }
};

zclmeta.functional.getCommand = function (cluster, dir, cmd) {
    if (dir === 0)         // client to server, cmd
        return zclId.functional(cluster, cmd);
    else if (dir === 1)    // server to client, cmdRsp
        return zclId.getCmdRsp(cluster, cmd);
};

zclmeta.functional.getDirection = function (cluster, cmd) {
    let meta = this.get(cluster, cmd);
    if (meta)
        meta = zclmeta.Direction.get(meta.dir);

    return meta ? meta.key : undefined;        // return: "Client To Server", "Server To Client"
};

module.exports = zclmeta;
