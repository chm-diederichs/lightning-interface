const curve = require('secp256k1')
const assert = require('nanoassert')

module.exports = {
  newOpenChannelMsg,
  newAcceptChannelMsg
}

module.exports.OpenChannel = OpenChannel = function (opts) {
  this.type = 32
  this.chainHash
  this.temporaryChannelId
  this.fundingSatoshis
  this.pushMsat
  this.dustLimitSatoshis
  this.maxHtlcValueInFlightMsat
  this.channelReserveSatoshis
  this.htlcMinimumSat
  this.feeratePerKw
  this.toSelfDelay
  this.maxAcceptedHtlcs
  this.fundingPubkey
  this.revocationBasepoint
  this.paymentBasepoint
  this.delayedPaymentBasepoint
  this.htlcBasepoint
  this.firstPerCommitmentPoint
  this.channelFlags
  this.shutdownLen // optional
  this.shutdownScriptPubKey // optional
}

function newOpenChannelMsg (opts) {
  const msg = new OpenChannel()

  msg.chainHash = opts.chainHash
  msg.temporaryChannelId = opts.temporaryChannelId
  msg.fundingSatoshis = opts.fundingSatoshis
  msg.pushMsat = opts.pushMsat
  msg.dustLimitSatoshis = opts.dustLimitSatoshis
  msg.maxHtlcValueInFlightMsat = opts.maxHtlcValueInFlightMsat
  msg.channelReserveSatoshis = opts.channelReserveSatoshis
  msg.htlcMinimumSat = opts.htlcMinimumSat
  msg.feeratePerKw = opts.feeratePerKw
  msg.toSelfDelay = opts.toSelfDelay
  msg.maxAcceptedHtlcs = opts.maxAcceptedHtlcs
  msg.fundingPubkey = opts.fundingPubkey
  msg.revocationBasepoint = opts.revocationBasepoint
  msg.paymentBasepoint = opts.paymentBasepoint
  msg.delayedPaymentBasepoint = opts.delayedPaymentBasepoint
  msg.htlcBasepoint = opts.htlcBasepoint
  msg.firstPerCommitmentPoint = opts.firstPerCommitmentPoint
  msg.channelFlags = opts.channelFlags
  
  // optional
  msg.shutdownLen = opts.shutdownLen
  msg.shutdownScriptPubKey = opts.shutdownScriptPubKey

  return msg
}

OpenChannel.prototype.encode = function (buf, offset) {
  if (!buf) buf = Buffer.alloc(this.numBytes())
  if (!offset) offset = 0
  const startIndex = offset

  buf.writeUInt16BE(this.type, offset)
  offset += 2

  buf.set(this.chainHash, offset)
  offset += 32

  buf.set(this.temporaryChannelId, offset)
  offset += 32

  writeUInt64BE(this.fundingSatoshis, buf, offset)
  offset += 8

  writeUInt64BE(this.pushMsat, buf, offset)
  offset += 8

  writeUInt64BE(this.dustLimitSatoshis, buf, offset)
  offset += 8

  writeUInt64BE(this.maxHtlcValueInFlightMsat, buf, offset)
  offset += 8

  writeUInt64BE(this.channelReserveSatoshis, buf, offset)
  offset += 8

  writeUInt64BE(this.htlcMinimumSat, buf, offset)
  offset += 8

  buf.writeUInt32BE(this.feeratePerKw, offset)
  offset += 4

  buf.writeUInt16BE(this.toSelfDelay, offset)
  offset += 2

  buf.writeUInt16BE(this.maxAcceptedHtlcs, offset)
  offset += 2

  buf.set(this.fundingPubkey.compress(), offset)
  offset += 33

  buf.set(this.revocationBasepoint.compress(), offset)
  offset += 33

  buf.set(this.paymentBasepoint.compress(), offset)
  offset += 33

  buf.set(this.delayedPaymentBasepoint.compress(), offset)
  offset += 33

  buf.set(this.htlcBasepoint.compress(), offset)
  offset += 33

  buf.set(this.firstPerCommitmentPoint.compress(), offset)
  offset += 33

  buf.set(this.channelFlags, offset)
  offset += 1

  if (this.shutdownLen) {
    buf.writeUInt16BE(this.shutdownLen, offset)
    offset += 2

    buf.set(this.shutdownScriptPubKey, offset)
    offset += this.shutdownLen
  }

  this.encode.bytes = offset - startIndex
  return buf
}

OpenChannel.prototype.decode = function (buf, offset) {
  if (!offset) offset = 0
  const startIndex = offset

  assert(buf.readUInt16BE(offset) === this.type, 'wrong type: open channel messages should be type 32.')
  offset += 2

  this.chainHash = buf.slice(offset, offset + 32)
  offset += 32

  this.temporaryChannelId = buf.slice(offset, offset + 32)
  offset += 32

  this.fundingSatoshis = readUInt64BE(buf, offset)
  offset += 8

  this.pushMsat = readUInt64BE(buf, offset)
  offset += 8

  this.dustLimitSatoshis = readUInt64BE(buf, offset)
  offset += 8

  this.maxHtlcValueInFlightMsat = readUInt64BE(buf, offset)
  offset += 8

  this.channelReserveSatoshis = readUInt64BE(buf, offset)
  offset += 8

  this.htlcMinimumSat = readUInt64BE(buf, offset)
  offset += 8

  this.feeratePerKw = buf.readUInt32BE(offset)
  offset += 4

  this.toSelfDelay = buf.readUInt16BE(offset)
  offset += 2

  this.maxAcceptedHtlcs = buf.readUInt16BE(offset)
  offset += 2

  this.fundingPubkey = readPubKey(buf, offset)
  offset += 33

  this.revocationBasepoint = readPubKey(buf, offset)
  offset += 33

  this.paymentBasepoint = readPubKey(buf, offset)
  offset += 33

  this.delayedPaymentBasepoint = readPubKey(buf, offset)
  offset += 33

  this.htlcBasepoint = readPubKey(buf, offset)
  offset += 33

  this.firstPerCommitmentPoint = readPubKey(buf, offset)
  offset += 33

  this.channelFlags = buf.readUInt8(offset)
  offset += 1

  if (offset < buf.byteLength) {
    this.shutdownLen = buf.readUInt16BE(offset)
    offset += 2

    this.shutdownScriptPubKey = buf.slice(offset, offset + this.shutdownLen)
    offset += this.shutdownLen
  }

  this.decode.bytes = offset - startIndex
  return this
}

OpenChannel.prototype.numBytes = function () {
  const length = 321
  if (this.shutdownLen) {
    length += 2
    length += this.shutdownLen
  }

  return length
}

module.exports.AcceptChannel = AcceptChannel = function () {
  this.type = 33
  this.temporaryChannelId
  this.dustLimitSatoshis
  this.maxHtlcValueInFlightMsat
  this.channelReserveSatoshis
  this.htlcMinimumSat
  this.minimumDepth
  this.toSelfDelay
  this.maxAcceptedHtlcs
  this.fundingPubkey
  this.revocationBasepoint
  this.paymentBasepoint
  this.delayedPaymentBasepoint
  this.htlcBasepoint
  this.firstPerCommitmentPoint

  // optional
  this.shutdownLen
  this.shutdownScriptPubKey
}

function newAcceptChannelMsg (opts) {
  const msg = new AcceptChannel()

  msg.temporaryChannelId = opts.temporaryChannelId
  msg.dustLimitSatoshis = opts.dustLimitSatoshis
  msg.maxHtlcValueInFlightMsat = opts.maxHtlcValueInFlightMsat
  msg.channelReserveSatoshis = opts.channelReserveSatoshis
  msg.htlcMinimumSat = opts.htlcMinimumSat
  msg.minimumDepth = opts.minimumDepth
  msg.toSelfDelay = opts.toSelfDelay
  msg.maxAcceptedHtlcs = opts.maxAcceptedHtlcs
  msg.fundingPubkey = opts.fundingPubkey
  msg.revocationBasepoint = opts.revocationBasepoint
  msg.paymentBasepoint = opts.paymentBasepoint
  msg.delayedPaymentBasepoint = opts.delayedPaymentBasepoint
  msg.htlcBasepoint = opts.htlcBasepoint
  msg.firstPerCommitmentPoint = opts.firstPerCommitmentPoint

  // optional
  msg.shutdownLen = opts.shutdownLen
  msg.shutdownScriptPubKey = opts.shutdownScriptPubKey

  return msg
}

AcceptChannel.prototype.encode = function (buf, offset) {
  if (!buf) buf = Buffer.alloc(this.numBytes())
  if (!offset) offset = 0
  const startIndex = offset

  buf.writeUInt16BE(this.type, offset)
  offset += 2

  buf.set(this.temporaryChannelId, offset)
  offset += 32
  
  writeUInt64BE(this.dustLimitSatoshis, buf, offset)
  offset += 8

  writeUInt64BE(this.maxHtlcValueInFlightMsat, buf, offset)
  offset += 8

  writeUInt64BE(this.channelReserveSatoshis, buf, offset)
  offset += 8

  writeUInt64BE(this.htlcMinimumSat, buf, offset)
  offset += 8

  buf.writeUInt32BE(this.minimumDepth, offset)
  offset += 4

  buf.writeUInt16BE(this.toSelfDelay, offset)
  offset += 2

  buf.writeUInt16BE(this.maxAcceptedHtlcs, offset)
  offset += 2

  buf.set(this.fundingPubkey.compress(), offset)
  offset += 33

  buf.set(this.revocationBasepoint.compress(), offset)
  offset += 33

  buf.set(this.paymentBasepoint.compress(), offset)
  offset += 33

  buf.set(this.delayedPaymentBasepoint.compress(), offset)
  offset += 33

  buf.set(this.htlcBasepoint.compress(), offset)
  offset += 33

  buf.set(this.firstPerCommitmentPoint.compress(), offset)
  offset += 33

  // optionals
  if (this.shutdownLen) {
    buf.writeUInt16BE(this.shutdownLen, offset)
    offset += 2

    buf.set(this.shutdownScriptPubKey, offset)
    offset += this.shutdownLen
  }

  this.encode.bytes = offset - startIndex
  return buf
}

AcceptChannel.prototype.decode = function (buf, offset) {
  if (!offset) offset = 0
  const startIndex = offset

  assert(buf.readUInt16BE(offset) === this.type, 'wrong type: accept channel messages should be type 33.')
  offset += 2

  this.temporaryChannelId = buf.slice(offset, offset + 32)
  offset += 32

  this.dustLimitSatoshis = readUInt64BE(buf, offset)
  offset += 8

  this.maxHtlcValueInFlightMsat = readUInt64BE(buf, offset)
  offset += 8

  this.channelReserveSatoshis = readUInt64BE(buf, offset)
  offset += 8

  this.htlcMinimumSat = readUInt64BE(buf, offset)
  offset += 8

  this.minimumDepth = readUInt32BE(buf, offset)
  offset += 4

  this.toSelfDelay = buf.readUInt16BE(offset)
  offset += 2

  this.maxAcceptedHtlcs = buf.readUInt16BE(offset)
  offset += 2

  this.fundingPubkey = readPubKey(buf, offset)
  offset += 33

  this.revocationBasepoint = readPubKey(buf, offset)
  offset += 33

  this.paymentBasepoint = readPubKey(buf, offset)
  offset += 33

  this.delayedPaymentBasepoint = readPubKey(buf, offset)
  offset += 33

  this.htlcBasepoint = readPubKey(buf, offset)
  offset += 33

  this.firstPerCommitmentPoint = readPubKey(buf, offset)
  offset += 33

  if (offset < buf.byteLength) {
    this.shutdownLen = buf.readUInt16BE(offset)
    offset += 2

    this.shutdownScriptPubKey = buf.slice(offset, offset + this.shutdownLen)
    offset += this.shutdownLen
  }

  this.decode.bytes = offset - startIndex
  return this
}

AcceptChannel.prototype.numBytes = function () {
  const length = 272
  if (this.shutdownLen) {
    length += 2
    length += this.shutdownLen
  }

  return length
}

module.exports.FundingCreated = FundingCreated = function () {
  this.type = 34

  this.temporaryChannelId
  this.fundingTxid
  this.fundingOutputIndex
  this.signature
}


FundingCreated.prototype.decode = function (buf, offset) {
  if (!buf) buf = Buffer.alloc(this.numBytes())
  if (!offset) offset = 0
  const startIndex = offset

  buf.writeUInt16BE(this.type, offset)
  offset += 2

  buf.set(this.temporaryChannelId, offset)
  offset += 32

  buf.set(this.fundingTxid, offset)
  offset += 32

  buf.writeUInt16BE(this.fundingOutputIndex, offset)
  offset += 2

  buf.set(this.signature, offset)
  offset += 64

  this.decode.bytes = offset - startIndex
  return this
}

FundingCreated.prototype.decode = function (buf, offset) {
  if (!offset) offset = 0
  const startIndex = offset

  assert(buf.readUInt16BE(offset) === this.type, 'wrong type: funding created messages should be type 34')
  offset += 2

  this.temporaryChannelId = buf.slice(offset, offset + 32)
  offset += 32

  this.fundingTxid = buf.slice(offset, offset + 32)
  offset += 32

  this.fundingOutputIndex = buf.readUInt16BE(offset)
  offset += 2

  this.signature = buf.slice(offset, offset + 64)
  offset += 64

  this.decode.bytes = offset - startIndex
  return this
}

FundingCreated.prototype.numBytes = function () {
  return 132
}

function readPubKey (buf, offset) {
  const publicKey = buf.slice(offset, offset + 33)
  const pub = curve.publicKeyConvert(publicKey, false)

  pub.compress = function () {
    return Buffer.from(curve.publicKeyConvert(this))
  }

  return pub
}

// TODO: funding created

var FundingSigned = function () {
  this.type = 35
  this.channelId
  this.signature
}

function newFundingSigned () {

}

function writeUInt64BE (value, buf, offset) {
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

function readUInt64BE (buf, offset) {
  const hi = buf.readUInt32BE(offset)
  const lo = buf.readUInt32BE(offset + 4)

  const result = BigInt(hi) * 2n**32n + BigInt(lo)
  return result
}
