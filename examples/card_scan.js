import { SerialPort } from 'serialport'
var serialPort = new SerialPort({
    path: '/dev/ttyUSB0',
    baudRate: 115200
});

serialPort.on('open', function () {
    console.log("serialPort Open");
})


import Pn532 from '../pn532.js'
var hostController = Pn532.forConnection(serialPort)

hostController.on('tag', uid => {
    console.log('[host] uid', uid);
})

hostController.on('init', () => {
    console.log('\nReading tag data...');
    hostController.scanTag()
})
