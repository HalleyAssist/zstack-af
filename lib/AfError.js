class AfError extends Error {
    /**
     * @param {number|string} code
     */
    constructor(code){
        super(`rsp error: ${code}`)
        this.code = code
    }
}
module.exports = AfError