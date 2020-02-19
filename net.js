const net = require('net')
const noise = require('./noise')
const crypto = require('crypto')
const curve = require('secp256k1')
const message = require('./messages')
const funding = require('./funding')

const initiatorStatic = Buffer.from('1111111111111111111111111111111111111111111111112111111111111111', 'hex')
const initiatorEphemeral = Buffer.from('1212121212121212121212121212121212121212121212121212121212121212', 'hex')
const nodeId = Buffer.from('03835925714bf59d2fce0a54dccc55c0b2ca5866cc271dee4c4216794e6b56507a', 'hex')
console.log(Buffer.from(curve.publicKeyCreate(initiatorStatic)).toString('hex'))
const client = new net.Socket()
const initiator = new noise.Initiator(initiatorStatic, initiatorEphemeral)

initiator.initialise(nodeId, 'hex')

// const server = net.createServer(function (socket) {
//   // socket.write('Echo server\r\n')
//   socket.pipe(socket)
// })

// server.listen(57000, '127.0.0.1')

let counter = 0

// open channel message parameters

const fundingManager = new funding.FundingManager()

client.connect(9734, '127.0.0.1', function () {
  console.log('connected')
  client.write(initiator.one(nodeId))
})

let leftover = null

client.on('data', function (data) {
  counter++
  // console.log(data.toString('hex'))

  if (data.byteLength <= 18) {
    leftover = data
    return
  }

  if (leftover !== null) {
    data = Buffer.concat([leftover, data])
    leftover = null
  }

  if (counter < 2) {
    initiator.two(data)
    client.write(initiator.three())
  } else if (counter === 2) {
    console.log('writing')
    client.write(initiator.send(Buffer.from('00100000000181', 'hex')))
    const received = initiator.receive(data)
  } else {
    const received = initiator.receive(data)
    console.log(received.readUInt16BE())
    console.log(received.slice(68).toString('hex'), 'received')

    if (received.toString('hex') === '001200100000') {
      console.log('ping')
      client.write(initiator.send(Buffer.from('0013001000000000000000000000000000000000', 'hex')))
    } else {
      switch (received.readUInt16BE()) {
        case 32 :
          const channelReq = new message.OpenChannel()

          channelReq.decode(received)
          console.log(channelReq)
          const opts = channelReq
          opts.minimumDepth = 4
          // Object.entries(opts).forEach(function ([key, value]) {
          //   if (value.serializeCompressed) console.log(key, value.serializeCompressed().toString('hex'))
          // })

          const acceptOpts = fundingManager.handleChannelOpen(opts)
          const acceptMsg = message.newAcceptChannelMsg(acceptOpts)
          console.log(acceptMsg, 'accept')
          client.write(initiator.send(acceptMsg.encode()))
          break
          // const messageType = received.readUInt16BE()
          // console.log(messageType)
          // console.log('chainHash: ', received.slice(2, 34).toString('hex'))
          // console.log('first block num: ', received.readUInt32BE(34))
          // console.log('number of blocks: ', received.readUInt32BE(38))
          // console.log('tlvs: ', received.slice(42))
          // console.log('received: ', received)

          // const message = `0001815e288b59${initiator.static.pub.serializeCompressed().toString('hex')}303030${Buffer.alloc(32).fill(Buffer.from('alias', 'utf8')).toString('hex')}0007017f000001cfab`
          // const toSign = crypto.createHash('sha256').update(Buffer.from(message, 'hex')).digest()
          // const signature = Buffer.from(curve.signatureExport(curve.ecdsaSign(toSign, initiatorStatic).signature))
          // const sig64 = Buffer.concat([signature.slice(4, 36), signature.slice(38)])
          // const toSend = `0101${sig64.toString('hex')}${message}`

          // setTimeout(() => client.write(initiator.send(Buffer.from('001200100000', 'hex'))), 1000)

        case 34:
          const fundingCreated = new message.FundingCreated()

          fundingCreated.decode(received)
          const fundingSigned = fundingManager.handleFundingCreated(fundingCreated)
          console.log(fundingSigned)
          // const fundingLocked = funding
      }
    }
  }
})

client.on('close', function () {
  console.log('connection closed.')
})

client.on('error', console.log)
