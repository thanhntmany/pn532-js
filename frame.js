import EventEmitter from 'node:events'

/**
 * Frames structure
 * 

00 : PREAMBLE
00 FF : START CODE
├── 00 FF : <ACK frame>
├── FF 00 : <NACK frame>
├── FF FF {LENm} {LENl} {LCS} {TFI} [{DATA}....] {DCS} : <Extended information frame>
│    - Lower byte of [LENM + LENL + LCS] = 0x00
│    - {DCS}: Lower byte of [TFI + PD0 + PD1 + … + PDn + DCS] = 0x00
└── {LEN} {LCS} {TFI} [{DATA}....] {DCS} : <information frame>
│    - Lower byte of [LEN + LCS] = 0x00
│    - {DCS}: Lower byte of [TFI + PD0 + PD1 + … + PDn + DCS] = 0x00
└── 01 FF {ERR} {DCS} : <error frame>
00 : POSTAMBLE

 */

const PREAMBLE = 0x00,
    START_CODE_1 = 0x00,
    START_CODE_2 = 0xff,
    POSTAMBLE = 0x00,
    TFI_FROM_HOST = 0xd4,
    TFI_FROM_PN532 = 0xd5

export const GenDCSOfData = data => {
    const l = data.length - 1
    var sum = data[0]
    for (var i = 1; i < l; ++i) sum += data[i]
    return (~sum & 0xff) + 0x01
}

export const LCSOfLEN = LEN => (~LEN & 0xff) + 0x01
export const DCSOfPacket = packet => {
    var cs = 0x00; for (let byte of packet) cs += byte
    return (~cs & 0xff) + 0x01
}
export const FrameOfPackage = cmdBuffer => {
    const LEN = cmdBuffer.length

    if (LEN <= 255) return Buffer.concat([ // Information frame
        Buffer.from([PREAMBLE, START_CODE_1, START_CODE_2, LEN, LCSOfLEN(LEN)]),
        cmdBuffer,
        Buffer.from([DCSOfPacket(cmdBuffer), POSTAMBLE])
    ])

    const LENl = LEN % 256, LENm = (LEN - LENl) / 256
    // #TODO: test this
    return Buffer.concat([ // Extended Information frame
        Buffer.from([PREAMBLE, START_CODE_1, START_CODE_2, LEN, 0xff, 0xff, LENm, LENl, LCSOfLEN(LENm + LENl)]),
        cmdBuffer,
        Buffer.from([DCSOfPacket(cmdBuffer), POSTAMBLE])
    ])
}

export const FrameOfCmd = (code, input) => FrameOfPackage(Buffer.from([TFI_FROM_HOST, code].concat(input)))


/** Frames **/

export const AckFrame = Buffer.from([PREAMBLE, START_CODE_1, START_CODE_2, 0x00, 0xff, POSTAMBLE])
export const NackFrame = Buffer.from([PREAMBLE, START_CODE_1, START_CODE_2, 0xff, 0x00, POSTAMBLE])

export const SAMConfiguration_modes = {
    'normal-mode': 0x01,
    'virtual-card': 0x02,
    'wired-card': 0x03,
    'dual-card': 0x04,
}

export const GetFirmwareVersionFrame = FrameOfPackage(Buffer.from([TFI_FROM_HOST, 0x02]))

/** Commands **/

export const Commands = {
    ACK: {
        send: agent => agent.send(AckFrame)
    },
    NACK: {
        send: agent => agent.send(NackFrame)
    },
    // Miscellaneous
    Diagnose: { code: 0x00 },
    GetFirmwareVersion: {
        code: 0x02,
        send: agent => agent.send(GetFirmwareVersionFrame),
        recv: (agent, output) => {
            const [IC, Ver, Rev, Support] = output
            return {
                IC, Ver, Rev, Support,
                version: Ver + "." + Rev,
                functionalities: {
                    'ISO/IEC 14443 TypeA': !!(Support & 0b00000001),
                    'ISO/IEC 14443 TypeB': !!(Support & 0b00000010),
                    'ISO18092': !!(Support & 0b00000100),
                }
            }
        }
    },
    GetGeneralStatus: { code: 0x04 },
    ReadRegister: { code: 0x06 },
    WriteRegister: { code: 0x08 },
    ReadGPIO: { code: 0x0c },
    WriteGPIO: { code: 0x0e },
    SetSerialBaudRate: { code: 0x10 },
    SetParameters: { code: 0x12 },
    SAMConfiguration: {
        code: 0x14,
        gen: (Mode, Timeout = 0x00, IRQ) => {
            const frame = [SAMConfiguration_modes[Mode] || 0x01]
            if (Mode === 'virtual-card' || !isNaN(Timeout)) frame.push(Timeout || 0)
            if (IRQ !== undefined) {
                if (IRQ === null) {
                    frame.push(0x00)
                } else if (IRQ === true) {
                    frame.push(0x01)
                }
            }
            return frame
        },
        recv: (agent, data) => {
            return data
        }
    },

    // RF communication
    RFConfiguration: { code: 0x32 },
    RFRegulationTest: { code: 0x58 },

    // Initiator
    InJumpForDEP: { code: 0x56 },
    InJumpForPSL: { code: 0x46 },
    InListPassiveTarget: {
        code: 0x4a,
        send: (agent, MaxTg = 1, BrTy = 0x00, InitiatorData) => {
            /**
             *  BrTy is the baud rate and the modulation type to be used during the initialization
                − 0x00 : 106 kbps type A (ISO/IEC14443 Type A),
                − 0x01 : 212 kbps (FeliCa polling),
                − 0x02 : 424 kbps (FeliCa polling),
                − 0x03 : 106 kbps type B (ISO/IEC14443-3B),
                − 0x04 : 106 kbps Innovision Jewel tag. 
             * 
            */
            var frame = [MaxTg, BrTy]
            agent._InListPassiveTarget_BrTy = BrTy
            if (Array.isArray(InitiatorData)) frame = frame.concat(frame)

            return agent.send(FrameOfCmd(0x4a, frame))
        },
        recv: (agent, output) => {
            const res = {}, tags = res.tags = []
            const NbTg = output[0]

            res.NbTg = NbTg // numberOfTags
            switch (agent._InListPassiveTarget_BrTy) {
                case 0x00: // 106 kbps Type A
                    {
                        var p = 1
                        for (var i = 0; i < NbTg; ++i) {
                            var NFCIDLength = output[p + 4],
                                NFCID1 = output.subarray(p + 5, p + 5 + NFCIDLength),
                                tag = {
                                    Tg: output[p],
                                    ATQA: output.subarray(p + 1, p + 3),
                                    SAK: output[p + 3],
                                    SENS_RES: output.subarray(p + 1, p + 3).readInt16BE(0),
                                    SEL_RES: output[p + 3],
                                    NFCIDLength,
                                    NFCID1,
                                    uid: NFCID1,
                                }
                            p += 5 + NFCIDLength

                            var TL = output[p]
                            if (TL) {
                                tag.ATS = { // #TODO: parse full Answer To Select (ATS) in ISO/IEC 14443-
                                    TL,
                                    T0: output[p + 1],
                                    TA1: output[p + 2],
                                    TB1: output[p + 3],
                                    TC1: output[p + 4],
                                    TCK: output[p + TL - 1]
                                }
                                p += TL
                            }

                            tags.push(tag)
                        }
                    }
                    break;

                case 0x03: // 106 kbps Type B
                    {
                        var p = 1
                        for (var i = 0; i < NbTg; ++i) {
                            var ATTRIB_RES_len = output[p + 14],
                                tag = {
                                    Tg: output[p],
                                    ATQB: output.subarray(p + 2, p + 14),
                                    ATTRIB_RES_len,
                                    ATTRIB_RES: output.subarray(p + 15, p + 15 + ATTRIB_RES_len),
                                }
                            p += 15 + ATTRIB_RES_len
                            tags.push(tag)
                        }
                    }
                    break;

                // 212/424 kbps
                case 0x01:
                case 0x02:
                    {
                        var p = 1
                        for (var i = 0; i < NbTg; ++i) {
                            var POL_RES_len = output[p + 1],
                                tag = {
                                    Tg: output[p],
                                    POL_RES_len,
                                    NFCID2t: output.subarray(p + 3, p + 11),
                                    Pad: output.subarray(p + 11, p + 19),
                                }

                            if (POL_RES_len > 18) tag.SYST_CODE = output.subarray(p + 19, p + 21)
                            p += 1 + POL_RES_len
                            tags.push(tag)
                        }
                    }
                    break;

                case 0x04: // 106 kbps Innovision Jewel tag
                    {
                        var p = 1
                        for (var i = 0; i < NbTg; ++i) {
                            tags.push({
                                Tg: output[p],
                                SENS_RES: output.subarray(p + 1, p + 3),
                                JEWELID: output.subarray(p + 3, p + 7),
                            })
                            p += 7
                        }
                    }
                    break;
            }

            return res
        }
    },
    InATR: { code: 0x50 },
    InPSL: { code: 0x4E },
    InDataExchange: {
        code: 0x40,
        gen: (Tg = 0x01, DataOut) => {
            const frame = [Tg, 0x30, 0x04]
            return frame
        }
    },
    InCommunicateThru: { code: 0x42 },
    InDeselect: { code: 0x44 },
    InRelease: { code: 0x52 },
    InSelect: { code: 0x54 },
    InAutoPoll: { code: 0x60 },

    // Target
    TgInitAsTarget: { code: 0x8c },
    TgSetGeneralBytes: { code: 0x60 },
    TgGetData: { code: 0x86 },
    TgSetData: { code: 0x8e },
    TgSetMetaData: { code: 0x94 },
    TgGetInitiatorCommand: { code: 0x88 },
    TgResponseToInitiator: { code: 0x90 },
    TgGetTargetStatus: { code: 0x8a },
}

export const Commands_recv = {}
{
    var obj, code, recv
    for (var cmd in Commands) {
        obj = Commands[cmd]
        obj.name = cmd
        code = obj?.code
        recv = obj?.recv

        if (recv instanceof Function && code > 0) {
            recv.cmd = obj
            Commands_recv[code + 1] = recv
        }
    }
}

export const ErrorMsg = {
    0x01: 'Time Out, the target has not answered',
    0x02: 'A CRC error has been detected by the CIU',
    0x03: 'A Parity error has been detected by the CIU',
    0x04: 'During an anti-collision/select operation (ISO/IEC14443-3 Type A and ISO/IEC18092 106 kbps passive mode), an erroneous Bit Count has been detected',
    0x05: 'Framing error during Mifare operation',
    0x06: 'An abnormal bit-collision has been detected during bit wise anti-collision at 106 kbps',
    0x07: 'Communication buffer size insufficient',
    0x09: 'RF Buffer overflow has been detected by the CIU (bit BufferOvfl of the register CIU_Error)',
    0x0a: 'In active communication mode, the RF field has not been switched on in time by the counterpart (as defined in NFCIP-1 standard)',
    0x0b: 'RF Protocol error (description of the CIU_Error register)',
    0x0d: 'Temperature error: the internal temperature sensor has detected overheating, and therefore has automatically switched off the antenna drivers',
    0x0e: 'Internal buffer overflow',
    0x10: 'Invalid parameter (range, format, …)',
    0x12: 'DEP Protocol: The PN532 configured in target mode does not support the command received from the initiator (the command received is not one of the following: ATR_REQ, WUP_REQ, PSL_REQ, DEP_REQ, DSL_REQ, RLS_REQ.).',
    0x13: 'DEP Protocol, Mifare or ISO/IEC14443-4: The data format does not match to the specification.',
    0x14: 'Mifare: Authentication error',
    0x23: 'ISO/IEC14443-3: UID Check byte is wrong',
    0x25: 'DEP Protocol: Invalid device state, the system is in a state which does not allow the operation',
    0x26: 'Operation not allowed in this configuration (host controller interface)',
    0x27: 'This command is not acceptable due to the current context of the PN532 (Initiator vs. Target, unknown target number, Target not in the good state, …)',
    0x29: 'The PN532 configured as target has been released by its initiator',
    0x2a: 'PN532 and ISO/IEC14443-3B only: the ID of the card does not match, meaning that the expected card has been exchanged with another one.',
    0x2b: 'PN532 and ISO/IEC14443-3B only: the card previously activated has disappeared.',
    0x2c: 'Mismatch between the NFCID3 initiator and the NFCID3 target in DEP 212/424 kbps passive.',
    0x2d: 'An over-current event has been detected',
    0x2e: 'NAD missing in DEP frame',
}
export class CommandError extends Error {
    constructor(byteCode) {
        const code = byteCode & 0b00111111
        super(ErrorMsg[code] || 'Unknow CommandError')
        this.code = code
        this.NADPresent = byteCode & 0b10000000 > 0
        this.MI = byteCode & 0b01000000 > 0
    }
}

/** DialogAgent **/
const STAGE_SEEK_START_CODE = Symbol('seek to the START_CODE'),
    STAGE_DETECT_TYPE = Symbol('detect type of frame'),
    STAGE_DETECT_TYPE_EX_INFO = Symbol('detect type of Extended information frame'),
    STAGE_EXTRACT_DATA = Symbol('extract data from info frame')

export default class DialogAgent extends EventEmitter {
    constructor() {
        super()
        this.logger = console

        this._buff = Buffer.alloc(0)
        this._p = 0
        this._info_len = 0
        this._stage = STAGE_SEEK_START_CODE

        // init
        this.onCmdRes_listeners = {}
        // this.on(`cmd-res`, this.onCmdRes.bind(this))
    }

    onceCmdRes(code, listener) {
        const listeners = this.onCmdRes_listeners[code] || (this.onCmdRes_listeners[code] = [])
        listeners.push(listener)
    }

    onCmdRes(code, output) {
        const listeners = this.onCmdRes_listeners[code] || (this.onCmdRes_listeners[code] = [])
        var lis
        while (lis = listeners.shift()) {
            try {
                lis(output)
            } catch (error) {
                this.logger.error('onCmdRes error', error)
            }
        }
    }

    onRecvData(data, isValid) {
        if (!isValid) this.emit('data-invalid', data)
        const len = data.length
        if (len < 1) return
        const TFI = data[0]
        if (len === 1) {
            return this.emit('recv-error', new CommandError(TFI))
        }
        if (len > 1 && TFI === TFI_FROM_PN532) {
            const CC = data[1]
            if (!CC) throw new Error("Notfound handler for command code:", CC.toString(16), CC)
            const recv = Commands_recv[CC]
            return recv ? this.onCmdRes(CC - 1, recv(this, data.subarray(2))) : this.onCmdRes(CC - 1, data.subarray(2))
        }
    }

    // accumulation and processing chunks -> trigger event
    recv(buff) {
        var buff = this._buff = Buffer.concat([this._buff, buff]), p = this._p, l = buff.length
        while (true) {
            switch (this._stage) {
                case STAGE_SEEK_START_CODE:
                    {
                        if (++p >= l) return
                        if (buff[p] === START_CODE_2 && buff[p - 1] === START_CODE_1) {
                            ++p
                            this._stage = STAGE_DETECT_TYPE
                        }
                        this._p = p
                    }
                    break;

                case STAGE_DETECT_TYPE:
                    {
                        if (p + 1 >= l) return
                        const LEN = buff[p], LCS = buff[p + 1]

                        if (LEN === 0x00 && LCS === 0xff) {
                            // trigger ACK Frame
                            this.emit('recv-ack')
                            this._p = p += 2
                            this._stage = STAGE_SEEK_START_CODE
                        }
                        else if (LEN === 0xff && LCS === 0x00) {
                            // trigger NACK Frame
                            this.emit('recv-nack')
                            this._p = p += 2
                            this._stage = STAGE_SEEK_START_CODE
                        }
                        else if (LEN === 0xff && LCS === 0xff) {
                            this._p = p += 2
                            this._stage = STAGE_DETECT_TYPE_EX_INFO
                            // process Extended information frame
                        }
                        else if (((LEN + LCS) & 0xff) === 0x00) { // Lower byte of [LEN + LCS] = 0x00
                            this._p = p += 2
                            // trigger <information frame>
                            this._info_len = LEN
                            this._stage = STAGE_EXTRACT_DATA
                        }
                        else this._stage = STAGE_SEEK_START_CODE
                    }
                    break;

                case STAGE_DETECT_TYPE_EX_INFO:
                    {
                        if (p + 2 >= l) return
                        const LENm = buff[p], LENl = buff[p + 1], LCS = buff[p + 2]
                        if (((LENm + LENl + LCS) & 0xff) === 0x00) { // Lower byte of [LENM + LENL + LCS] = 0x00
                            this._p = p += 3
                            // trigger <information frame>
                            this._info_len = LENm << 8 + LENl
                            this._stage = STAGE_EXTRACT_DATA
                        }
                        else this._stage = STAGE_SEEK_START_CODE
                    }
                    break;

                case STAGE_EXTRACT_DATA:
                    {
                        const len = this._info_len
                        if (p + len + 1 >= l) return

                        const data = buff.subarray(p, p + len), DCS = buff[p + len]
                        var cs = 0x00; for (let byte of data) cs += byte
                        const dataIsValid = ((cs + DCS) & 0xff) === 0x00 // Lower byte of [TFI + PD0 + PD1 + … + PDn + DCS] = 0x00
                        this.onRecvData(data, dataIsValid)

                        buff = this._buff = Buffer.copyBytesFrom(buff, p + len + 1)
                        l = buff.length
                        p = this._p = 0
                        this._stage = STAGE_SEEK_START_CODE
                    }
                    break;

                default:
                    break;
            }
        }

    }

    send(buff) {
        throw new Error('Must be implemented in subclass');
    }

    sendAck() {
        return this.send(AckFrame)
    }

    sendNack(code, listener) {
        this.onceCmdRes(code, listener)
        return this.send(NackFrame)
    }

    sendCmd(cmd, ...args) {
        const CMD = Commands[cmd]
        if (!CMD) throw new Error('Command handler not found: ' + cmd)

        const { code, gen, send } = CMD
        return new Promise((resolve, reject) => {
            var pr
            if (gen instanceof Function) pr = this.send(FrameOfCmd(code, gen(...args)))
            if (send instanceof Function) pr = send(this, ...args)

            // Checking if pr is a Promise
            if (!!pr && typeof pr.then === 'function') {
                pr.catch(reject)
                this.onceCmdRes(code, resolve)
            }
            else reject(new Error('pr must be thenables'))
        })
    }

    cmd(cmd, ...args) {
        return new Promise((resolve, reject) => {
            const retry = () => {
                clear()
                this.sendNack(Commands[cmd]?.code, resolve)
            }
            this.once('data-invalid', retry)
            this.once('recv-error', reject)
            const clear = () => {
                this.off('data-invalid', retry)
                this.off('recv-error', reject)
            }

            this.sendCmd(cmd, ...args)
                .then(value => {
                    clear()
                    resolve(value)
                })
                .catch(reason => {
                    this.logger.warn('Detects an error in the response packet', reason, 'Send NACK.')
                    retry()
                })
                .finally(clear)
        })
    }
}