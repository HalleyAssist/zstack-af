/* jshint node: true */
'use strict';

let Enum = require('light-enum'),
    zclId = require('zcl-id'),
    zclMeta = require('./defs/meta.json')

/**
 * @returns {any}
 */
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

/**
 * @returns {void}
 */
function prepareParams(){
    const EmptyMap = new Map()
    const dict = {}
    /**
        * @param {any} params
        * @returns {any}
     */
    function prepareParam(params){
        let p = /** @type {any} */ (EmptyMap)
        if(!Array.isArray(params)){
            p = {}
            for(let k in params){
                p[k] = prepareParam(params[k])
            }
            return p
        }

        if(params.length) {
            p = new Map()
            for(let i = 0; i < params.length; i+=2){
                p.set(params[i], params[i+1])
            }
        }
        
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
        const foundationCmd = /** @type {any} */ (zclMeta.foundation[cmd])
        foundationCmd.params = prepareParam(foundationCmd.params)
    }
    for(let subsys in zclMeta.functional){
        const functionalSubsys = /** @type {any} */ (zclMeta.functional[subsys])
        for(let cmd in functionalSubsys){
            const functionalCmd = /** @type {any} */ (functionalSubsys[cmd])
            if(Array.isArray(functionalCmd.params)){
                functionalCmd.params = prepareParam(functionalCmd.params)
            } else {
                for(let k in functionalCmd.params){
                    functionalCmd.params[k] = prepareParam(functionalCmd.params[k])
                }
            }
        }
    }
}
prepareParams()

/**
 * @param {string} cmd
 * @returns {any}
 */
zclmeta.foundation.get = function (cmd) {
    let meta = zclMeta.foundation;
    return meta ? meta[cmd] : undefined;
};

/**
 * @param {any} cluster
 * @param {any} cmd
 * @returns {any}
 */
zclmeta.functional.get = function (cluster, cmd) {
    let meta = zclMeta.functional[cluster];
    return meta ? meta[cmd] : undefined;
    // return: {
    //  dir,
    //  params: [ { name: type }, ... ]
    // }
};

/**
 * @param {any} cluster
 * @param {number} dir
 * @param {any} cmd
 * @returns {any}
 */
zclmeta.functional.getCommand = function (cluster, dir, cmd) {
    if (dir === 0)         // client to server, cmd
        return zclId.functional(cluster, cmd);
    else if (dir === 1)    // server to client, cmdRsp
        return zclId.getCmdRsp(cluster, cmd);
};

/**
 * @param {any} cluster
 * @param {any} cmd
 * @returns {any}
 */
zclmeta.functional.getDirection = function (cluster, cmd) {
    let meta = this.get(cluster, cmd);
    if (meta)
        meta = zclmeta.Direction.get(meta.dir);

    return meta ? meta.key : undefined;        // return: "Client To Server", "Server To Client"
};

module.exports = zclmeta;
