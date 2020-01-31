const crypto = require('crypto')

const PAYLOAD_LEGACY = 0
const PAYLOAD_TLV = 1
const HMAC_SIZE = 32
const NUM_MAX_HOPS = 27
const NUM_PADDING_BYTES = 12

module.exports = {
  newHopPayload
}

// HopData is the information destined for individual hops. It is a fixed
// size 64 bytes, prefixed with a 1 byte realm (bitcoin: 0x00) indicating 
// how to interpret the following data. The last 32 bytes are always the 
// HMAC to be passed to the next hop, or zero if this is the packet is not
// to be forwarded, since this is the last hop.
module.exports.HopData = HopData = function (nextAddress, forwardAmount, outgoingCltv) {
  this.realm = 0x00
  this.nextAddress = nextAddress
  this.forwardAmount = forwardAmount
  this.outgoingCltv = outgoingCltv
  this.paddingBytes = Buffer.alloc(NUM_PADDING_BYTES)
}

HopData.prototype.encode = function (buf, offset) {
  if (!offset) offset = 0
  const startIndex = offset

  buf.writeUInt8(this.realm, offset)
  offset += 1

  buf.set(this.nextAddress, offset)
  offset += this.nextAddress.byteLength

  writeUInt64BE(this.forwardAmount, buf, offset)
  offset += 8

  buf.writeUInt32BE(this.outgoingCltv, offset)
  offset += 4

  buf.set(this.paddingBytes, offset)
  offset += this.paddingBytes.byteLength

  this.encode.bytes = offset - startIndex
}

HopData.prototype.decode = function (buf, offset) {
  if (!offset) offset = 0
  const startIndex = offset

  this.realm = buf.readUInt8(offset)
  offset += 1

  this.nextAddress = buf.slice(offset, offset + 8)
  offset += 8

  this.forwardAmount = readUInt64BE(buf, offset)
  offset += 8

  this.outgoingCltv = buf.readUInt32BE(buf, offset)
  offset += 4

  this.paddingBytes = buf.slice(offset, offset + NUM_PADDING_BYTES)
  offset += NUM_PADDING_BYTES

  this.decode.bytes = offset - startIndex
}

// HopPayload is a slice of bytes and associated payload-type that are destined
// for a specific hop in the PaymentPath. The payload itself is treated as an
// opaque data field by the onion router. The included Type field informs the
// serialization/deserialziation of the raw payload.
var HopPayload = function () {
  this.type
  this.payload
  this.HMAC
}

function newHopPayload (hopData, eob) {
  const h = new HopPayload()
  const len = hopData ? 65 : eob.byteLength
  const b = Buffer.alloc(len)

  if (!(hopData || eob.length)) {
    return new Error('either hop data or eob must be specified')
  }

  if (hopData && eob) {
    return new Error('cannot specify both hop data and eob')
  }

  if (hopData !== null) {
    hopData.encode(b)
    h.type = PAYLOAD_LEGACY
  } else {
    b.set(eob)
    h.type = PAYLOAD_TLV
  }

  h.payload = b.slice(0, hopData.encode.bytes)
  return h
}

HopPayload.prototype.numBytes = function () {
  const size = this.payload.byteLength + HMAC_SIZE

  if (this.type === PAYLOAD_TLV) {
    const payloadSize = this.payload.byteLength
    size += varint.encodingLength(payloadSize)
  }

  return size
}

HopPayload.prototype.encode = function (buf, offset) {
  if (!offset) offset = 0
  const startIndex = offset

  if (this.type !== 0x00) {
    varint.encode(this.payload.length, buf, offset)
    offset += varint.encode.bytes
  }

  buf.set(this.payload, offset)
  offset += this.payload.byteLength

  buf.set(this.HMAC, offset)
  offset += HMAC_SIZE

  this.encode.bytes = offset - startIndex
}

HopPayload.prototype.decode = function (buf, offset) {
  if (!offset) offset = 0
  const startIndex = offset

  const peekByte = buf.readUInt8(offset)

  switch (peekByte) {
    // legacy format payload
    case 0x00:
      const payloadSize = legacyHopDataSIze - hmacSize
      offset++

      this.type = PAYLOAD_LEGACY
      break

    // TLV format
    default:
      const payloadSize = varint.decode(buf, offset)
      offset += varint.decode.bytes

      this.type = PAYLOAD_TLV
  }

  this.payload = buf.slice(offset, offset + this.payload.length)
  offset += this.payload.length

  this.HMAC = buf.slice(offset, offset + HMAC_SIZE)
  offset += HMAC_SIZE

  this.decode.bytes = offset - startIndex
}

HopPayload.prototype.hopData = function () {
  // if this isn't legacy payload, we don't know the structure to decode
  if (this.type !== PAYLOAD_LEGACY) {
    return null
  }

  const hopData = new HopData()
  hopData.decode(this.payload)

  return hopData
}

module.exports.OnionHop = OnionHop = function (nodePub, hopPayload) {
  this.nodePub = nodePub 
  this.hopPayload = hopPayload
}

OnionHop.prototype.isEmpty = function () {
  return this.nodePub === null
}

module.exports.paymentPath = function (hops) {
  const obj = hops

  obj.nodeKeys = function () {
    const nodeKeys = []
    
    const trueLength = this.trueRouteLength()
    for (let i = 0; i < trueLength; i++) {
      nodeKeys.push(this[i].nodePub)
    }

    return nodeKeys
  }

  obj.trueRouteLength = function () {
    let trueRouteLength = 0

    for (let hop of this) {
      if (hop.isEmpty()) return routeLength
      routeLength++
    }

    return routeLength
  }

  obj.totalPayloadSize = function () {
    let totalSize = 0

    for (let hop of this) {
      if (hop.isEmpty()) continue
      totalSize += hop.hopPayload.numBytes()
    }

    return totalSize
  }

  return obj
}

function writeUInt64BE(value, buf, offset) {
  value = BigInt(value)
  // assert(-BigInt('0x8000000000000000') <= value && value <= BigInt('0x7fffffffffffffff'), 'TODO out of range')
  offset += 7

  let lo = Number(value & 0xffffffffn);
  buf[offset--] = lo;
  lo = lo >> 8;
  buf[offset--] = lo;
  lo = lo >> 8;
  buf[offset--] = lo;
  lo = lo >> 8;
  buf[offset--] = lo;
  
  let hi = Number(value >> 32n & 0xffffffffn);
  buf[offset--] = hi;
  hi = hi >> 8;
  buf[offset--] = hi;
  hi = hi >> 8;
  buf[offset--] = hi;
  hi = hi >> 8;
  buf[offset--] = hi;
  return offset + 8;
}
