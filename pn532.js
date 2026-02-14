import DialogAgent from './frame.js'

export default class Pn532 extends DialogAgent {
    static forConnection(io) {
        const connTypeName = io.constructor.name
        var inst = this
        if (connTypeName.includes('SerialPort')) {
            inst = new Pn532Hsu(io)
        }
        else if (connTypeName.toLowerCase().includes('i2c')) {
            inst = new Pn532I2c(io)
        }
        else if (connTypeName.toLowerCase().includes('spi')) {
            inst = new Pn532Spi(io)
        }
        else throw new Error('Unknown hardware type: ', connTypeName);

        inst.io.on('open', async () => {
            io.on('data', buff => inst.recv(buff))

            io.on('error', (error) => {
                logger.error('[Pn532] An error occurred on port:', error)
            });

            // NOTE: trigger emit('init') at the subclass
            // this.emit('init')
        })

        return inst
    }

    constructor(io) {
        super()
        this.io = io
    }

    send(buff) {
        return new Promise((res, rej) => this.io.write(buff, function (err) {
            if (err) return rej(err)
            res()
        }))
    }

    async scanTag(delay) {
        await this.cmd('SAMConfiguration', 'normal-mode', 0, true)

        if (delay) this.scanTag.delay = delay
        this.scanTag.loop = true

        const scan = async () => {
            const data = await this.cmd('InListPassiveTarget')
            this.emit('tags', data)

            const { tags } = data
            if (tags) tags.forEach(tag => this.emit('tag', tag.uid))

            if (this.scanTag.loop) setTimeout(scan, this.scanTag.delay || 200)
        }
        scan()
    }
}

const Pn532Hsu_wakeupFrame = Buffer.from([0x55, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
export class Pn532Hsu extends Pn532 {
    constructor(io) {
        super(io)

        io = this.io
        const baudRate = io.baudRate || 115200
        this.sendCmdTimeout = Math.ceil(256 * 4 * 10000 / baudRate) // ref: PN532 User Manual 6.2.2.1 b)
        if (this.sendCmdTimeout < 15) this.sendCmdTimeout = 15

        io.on('open', async () => {
            // ref: 7.2.11: HSU wake up condition
            await this.send(Pn532Hsu_wakeupFrame)
            this.emit('init')
        })
    }

    sendCmd(cmd, ...args) {
        if (this.sendCmdTimeout > 0) return new Promise((resolve, reject) => {
            const timeoutId = setTimeout(
                () => {
                    clear()
                    reject(new Error("Sending timed out"))
                },
                this.sendCmdTimeout
            )

            const clear = () => {
                clearTimeout(timeoutId)
                this.off('recv-ack', clear)
            }
            this.once('recv-ack', clear)

            return super.sendCmd(cmd, ...args)
                .then(resolve, reject)
                .finally(clear)
        })
        return super.sendCmd(cmd, ...args)
    }

}

// #TODO: ref 6.2.4
export class Pn532I2c extends Pn532 {
    constructor(io) {
        super(io)

        io = this.io
        io.on('open', () => {
            this.emit('init')
        })
    }
}

// #TODO: ref 6.2.5
export class Pn532Spi extends Pn532 {
    constructor(io) {
        super(io)

        io = this.io
        io.on('open', () => {
            this.emit('init')
        })
    }
}

/**

Several cases are to be considered; the power modes involved being different:
• Standby mode,
• LowVbat mode,
• Virtual Card mode,
• Wired Card mode,
• Initiator / PCD mode,
• Target / PICC mode. 

*/