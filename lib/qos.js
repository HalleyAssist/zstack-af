class AfQos {
    async execute(fn){
        return await fn()
    }
}

module.exports = AfQos;