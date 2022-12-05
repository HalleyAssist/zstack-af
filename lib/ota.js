const Functional = require('./packet/functional')

const OTAFileIdentifier = 200208670 // 0x0BEEF11E

const OtaFormat = new Map()
OtaFormat.set("identifier", "uint32")// 4
OtaFormat.set("headerVersion", "uint16") // 2
OtaFormat.set("headerLength", "uint16") // 2
OtaFormat.set("headerFieldControl", "uint16") // 2
OtaFormat.set("manufacturerCode", "uint16") // 2
OtaFormat.set("imageType", "uint16") // 2
OtaFormat.set("fileVersion", "uint32") // 4
OtaFormat.set("zigbeeStackVersion", "uint16") // 2
OtaFormat.set("headerString", "data32") // 32
OtaFormat.set("imageSize", "uint32") // 4

class Ota {
    static async readOtaHeader (fd) {
        const buf = Buffer.alloc(64);
        const fileStat = await fd.stat()
        await fd.read(buf, 0, 64, 0)
        const header = Functional.parseFrame(buf, OtaFormat)

        if(!header){
            throw new Error(`File could not be parsed`)
        }

        if (header.identifier != OTAFileIdentifier) {
            throw new Error(`File not an OTA file (identifier did not match)`)
        }

        if (header.imageSize != fileStat['size']) {
            throw new Error(`Image size field value ${header.imageSize} does not match actual size`)
        }

        return header
    }
}

module.exports = Ota