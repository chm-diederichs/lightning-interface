const crypto = require('crypto')
const curve = require('secp256k1')
const { toBigIntBE, toBufferBE } = require('bigint-buffer')

const PACKET_BYTES = module.exports.PACKET_BYTES = 1366
const ROUTING_INFO_SIZE = 1300
const STREAM_BYTES = ROUTING_INFO_SIZE * 2
const BASE_VERSION = 0
const HMAC_SIZE = 32

const KEY_TYPES = {
  rho: Buffer.from("0072686f", 'hex'),
  mu: Buffer.from("mu"),
  um: Buffer.from("um")
}

module.exports = {
  pack,
  generateCipherStream
}

/* 
paymentInfo = {
  payload: {
    HMAC,
    routingInfo,
    version
  },
  pubkey
} 
*/

function pack (hops) {
  const session = generateKey()

  const ephemerals = []
  const secrets = []

  let blindingFactor
  let secret
  let ephemeral

  const version = Buffer.alloc(1, BASE_VERSION)

  // initialise ephemeral key as session key
  ephemeral = generateKey(session.priv)

  for (let i = 0; i < hops.length; i++) {    
    secret = ecdh(hops[i].nodePub, ephemeral.priv)

    ephemerals.push(ephemeral)
    secrets.push(secret)

    blindingFactor = sha256(Buffer.concat([ephemeral.pub, secret]))

    // generate ephemeral key for i + 1
    const nextKey = multiply(ephemeral.priv, blindingFactor, 32)
    ephemeral = generateKey(nextKey)
  }

  // generate padding
  const filler = generateFiller('rho', hops, secrets)

  const rhoKeys = []
  // allocate and initialise fields to zero-filled slices
  let mixHeader = Buffer.alloc(ROUTING_INFO_SIZE)
  let nextHmac = Buffer.alloc(HMAC_SIZE)
  let payloadBuf = new PayloadBuffer()

  // compute the routing information for each hop along with a 
  // MAC of the routing information using the shared key for that hop.
  for (let i = hops.length - 1; i >= 0; i--) {
    const rhoKey = generateTypedKey('rho', secrets[i])
    rhoKeys.push(rhoKey)
    const muKey = generateTypedKey('mu', secrets[i])

    hops[i].hopPayload.HMAC = nextHmac

    // shift and obfuscate routing information
    const streamBytes = generateCipherStream(rhoKey, ROUTING_INFO_SIZE)
    const payload = hops[i].hopPayload
    shiftRight(mixHeader, payload.numBytes())

    // payloadBuf.setBytes(ephemerals[i].pub.serializeCompressed())
    payloadBuf.setBytes(payload.payload)
    payloadBuf.setBytes(payload.HMAC)
    
    mixHeader.set(payloadBuf.final())

    // re-encrypt the packet
    for (let i = 0; i < mixHeader.length; i++) {
      mixHeader[i] ^= streamBytes[i]
    }

    // pad the tail of the packet if this is the last hop
    if (i === hops.length - 1) {
      mixHeader.set(filler, mixHeader.length - filler.length)
    }

    let packet = mixHeader
    nextHmac = calcMac(muKey, packet)

    payloadBuf = new PayloadBuffer()
  }

  pack.rho = rhoKeys
  return new OnionPacket(BASE_VERSION, session.pub.serializeCompressed(), mixHeader, nextHmac)
}

var PayloadBuffer = function () {
  this.buf = Buffer.alloc(ROUTING_INFO_SIZE)
  this.offset = 0
}

PayloadBuffer.prototype.setBytes = function (bytes) {
  this.buf.set(bytes, this.offset)
  this.offset += bytes.byteLength
  return this
}

PayloadBuffer.prototype.final = function () {
  return this.buf.slice(0, this.offset)
}

var OnionPacket = function (version, ephemeralKey, routingInfo, headerMAC) {
  this.version = version
  this.ephemeralKey = ephemeralKey
  this.routingInfo = routingInfo
  this.headerMAC = headerMAC
}

OnionPacket.prototype.encode = function () {
  let buf = Buffer.alloc()

  for (let value of Object.values(this)) {
    if (!value instanceof Uint8Array) fail('arguments should be passed as Buffers')
    buf = Buffer.concat([buf, value])
  }

  return buf
}

OnionPacket.prototype.decode = function (buf, offset) {
  this.version = buf.readUInt8(buf, offset)
  offset += 1

  if (version !== BASE_VERSION) fail('version not supported')

  this.ephemeral = extractKey(buf.slice(offset, offset + 33))
  offset += 33

  this.routingInfo = buf.slice(offset, offset + ROUTING_INFO_SIZE)
  offset += ROUTING_INFO_SIZE

  this.hmacSize = buf.slice(offset, offset + HMAC_SIZE)
  offset += hmacSize

  return this
}

function fail (message) {
  return new Error(message)
}

function sha256 (data) {
  if (!data instanceof Uint8Array) data = Buffer.from(data, 'hex')
  return crypto.createHash('sha256').update(data).digest()
}

function calcMac (key, data) {
  if (!data instanceof Uint8Array) data = Buffer.from(data, 'hex')
  return crypto.createHmac('sha256', key).update(data).digest()
}

function ecdh (pubkey, privkey) {
  return Buffer.from(curve.ecdh(pubkey, privkey))
}

function multiply (buf1, buf2, width) {
  return toBufferBE(toBigIntBE(buf1) * toBigIntBE(buf2), width)
}

function generateFiller (keyType, path, secrets) {
  const numHops = path.length

  const fillerSize = path.totalPayloadSize() - path[numHops - 1].hopPayload.numBytes()
  const filler = Buffer.alloc(fillerSize)

  for (let i = 0; i < numHops - 1; i++) {
    // sum frames used by prior hops
    let fillerStart = ROUTING_INFO_SIZE

    for (let hop of path.slice(0, i)) {
      fillerStart -= hop.hopPayload.numBytes()
    }

    const fillerEnd = ROUTING_INFO_SIZE + path[i].hopPayload.numBytes()

    const streamKey = generateTypedKey(keyType, secrets[i])
    const streamBytes = generateCipherStream(streamKey, STREAM_BYTES)

    // xor filler with generated random bytes
    for (let i = 0; i < filler.length; i++) {
      filler[i] = filler[i] ^ streamBytes.slice(fillerStart, fillerEnd)[i]
    }
  }

  return filler
}

function generateCipherStream (key, byteLength) {
  const nonce = Buffer.alloc(16)
  const cipher = crypto.createCipheriv('chacha20', key, nonce)

  let encrypted = cipher.update(Buffer.alloc(byteLength))
  encrypted = Buffer.concat([encrypted, cipher.final()])
  return encrypted
}

function generateKey (type, secret) {
  const hmac = crypto.createHmac('sha256', KEY_TYPES.type)
  hmac.update(secret)

  return hmac.digest()
}

function shiftRight (buf, shiftBytes) {
  for (let i = buf.length - 1; i >= 0; i--) {
    if (i < shiftBytes) buf[i] = 0
    else buf[i] = buf[i - shiftBytes]
  }
  return buf
}

function generateKey (privKey) {
  const keyPair = {}

  keyPair.priv = privKey || newPrivKey()
  keyPair.pub = curve.publicKeyCreate(keyPair.priv)

  keyPair.pub.serializeCompressed = function () {
    return Buffer.from(curve.publicKeyConvert(this))
  }

  return keyPair

  function newPrivKey () {
    let key
    do {
      key = crypto.randomBytes(32)
    } while (!curve.privateKeyVerify(key))
    return key
  }
}

function generateTypedKey (type, secret) {
  return crypto.createHmac('sha256', type).update(secret).digest()
}

function extractKey (publicKey) {
  const pub = curve.publicKeyConvert(publicKey, false)
  pub.serializeCompressed = function () {
    return Buffer.from(curve.publicKeyConvert(this))
  }

  return pub
}
