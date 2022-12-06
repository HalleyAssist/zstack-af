class AfError extends Error {
    constructor(code){
        super(`rsp error: ${code}`)
        this.code = code
    }
}
module.exports = AfError