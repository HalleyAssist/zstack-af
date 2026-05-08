class AfQos {
    /**
     * @template T
     * @param {() => Promise<T>|T} fn
     * @param {...any} _args
     * @returns {Promise<T>}
     */
    async execute(fn, ..._args){
        return await fn()
    }
}

module.exports = AfQos;