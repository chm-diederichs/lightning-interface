const crypto = require('crypto')
const Keychain = require('./keys')
const script = require('./script')
const assert = require('nanoassert')
const btc = require('/Users/chrisdiederichs/bitcoin-consensus-encoding')

var Funder = function () {
  this.keychain = new Keychain()
  this.channelRequests = []
}

Funder.prototype.receiveChannelRequest = function (msg) {
  const request = new ChannelRequest()
  this.channelRequests.push(request)

  request.handleChannelOpen(msg)
  return request
}

module.exports.FundingManager = ChannelRequest = function () {
  this.keychain = new Keychain()
  this.temporaryChannelId
  this.channelId

  this.openChannel
  this.acceptChannel
  this.fundingCreated
  this.fundingSigned
  this.fundingLocked
}

ChannelRequest.prototype.handleChannelOpen = function (msg) {
  this.temporaryChannelId = msg.temporaryChannelId

  this.keychain.addRemoteKeys(msg)
  this.openChannel = openChannelRequest(msg)

  const acceptChannelOpts = {
    temporaryChannelId: this.temporaryChannelId,
    dustLimitSatoshis: msg.dustLimitSatoshis,
    maxHtlcValueInFlightMsat: msg.maxHtlcValueInFlightMsat,
    channelReserveSatoshis: msg.channelReserveSatoshis,
    htlcMinimumSat: msg.htlcMinimumSat,
    minimumDepth: msg.minimumDepth,
    toSelfDelay: msg.toSelfDelay,
    maxAcceptedHtlcs: msg.maxAcceptedHtlcs,
    fundingPubkey: this.keychain.funding.local.pub,
    revocationBasepoint: this.keychain._revocationBasepoint.local.pub,
    paymentBasepoint: this.keychain._paymentBasepoint.local.pub,
    delayedPaymentBasepoint: this.keychain._delayedPaymentBasepoint.local.pub,
    htlcBasepoint: this.keychain._htlcBasepoint.local.pub,
    firstPerCommitmentPoint: this.keychain._perCommitment.local.pub,

    // optional
    shutdownLen: msg.shutdownLen,
    shutdownScriptPubKey: msg.shutdownScriptPubKey
  }

  assert(Buffer.compare(acceptChannelOpts.temporaryChannelId, this.temporaryChannelId) === 0,
    'temporary channel ids must match')
  assert(acceptChannelOpts.channelReserveSatoshis >= this.openChannel.dustLimitSatoshis,
    `channel reserve sats must be >= ${this.openChannel.dustLimitSatoshis}`)
  assert(acceptChannelOpts.dustLimitSatoshis <= this.openChannel.dustLimitSatoshis,
    `channel reserve sats must be <= ${this.openChannel.dustLimitSatoshis}`)

  this.acceptChannel = acceptChannelOpts
  return this.acceptChannel
}

ChannelRequest.prototype.handleFundingCreated = function (msg) {
  assert(Buffer.compare(msg.temporaryChannelId, this.temporaryChannelId) === 0, 'temporary channel ids must match')

  this.fundingCreated = fundingCreated(msg)
  this.keychain.generateObscuringFactor()
  this.funding = msg.funding

  const obscure = this.keychain.obscuringFactor

  const delay = {
    local: this.acceptChannel.toSelfDelay,
    remote: this.openChannel.toSelfDelay
  }

  assert(this.openChannel.pushMsat < Number.MAX_SAFE_INTEGER, `pushMsat should be < ${Number.MAX_SAFE_INTEGER}`)
  const pushMsatInt = Number(this.openChannel.pushMsat)

  console.log(this.openChannel.feeratePerKw, 'feerate')
  const fee = Math.floor(724 * this.openChannel.feeratePerKw / 1000)
  console.log(fee)
  const pushSat = pushMsatInt / 1000

  const value = {
    local: Math.floor(pushMsatInt / 1000),
    remote: Number(this.openChannel.fundingSatoshis) - pushSat - fee
  }

  const fundingTx = {
    txid: msg.fundingTxid,
    vout: msg.fundingOutputIndex
  }

  const keysForScript = this.keychain.getScriptKeys()
  Object.entries(keysForScript.local).forEach(([key, value]) => console.log('local ' + key + ':', value.compress().toString('hex')))
  Object.entries(keysForScript.remote).forEach(([key, value]) => console.log('remote ' + key + ':', value.compress().toString('hex')))

  // create the first commitment transactions to be signed / verified
  const commitmentTxns = script.createCommitmentTxns(obscure, fundingTx, keysForScript, delay, value, 0, fee)
  console.log(commitmentTxns.toVerify, '____________')

  const fundingScript = script.genFundingPkScript(this.keychain.funding.local.pub.compress(), this.keychain.funding.remote.compress(), this.openChannel.fundingSatoshis)
  const encodedCommitmentToVerify = btc.tx.encode(commitmentTxns.toVerify, true)
  const commitmentDigestToVerify = btc.digest(commitmentTxns.toVerify, fundingScript.witnessScript, this.openChannel.fundingSatoshis, 0, 0x01)
  console.log(commitmentDigestToVerify.toString('hex'))
  console.log(fundingScript.witnessScript.toString('hex'))

  assert(this.keychain.verifyCommitmentSig(msg.signature, commitmentDigestToVerify), 'signature could not be verified.')

  // TODO: proper storage for signatures
  const theirSignature = msg.signature
  const ourSignature = this.keychain.signCommitment(encodedCommitmentToSign)

  // channelId - funding.txid ^ funding.vout
  const obscureId = this.funding.txid.readUInt16BE(30) ^ this.funding.vout
  this.channelId = Buffer.concat([this.funding.txid.slice(0, 30), obscureId])

  this.fundingSigned = {
    channelId: this.channelId,
    signature: ourSignature
  }

  return this.fundingSigned
}

ChannelRequest.prototype.lockFunding = function () {
  if (this.fundingLocked) return

  const nextCommitmentPoint = this.keychain.updateLocal()
  this.fundingLocked = {
    channelId: this.channelId,
    nextCommitmentPoint
  }

  return this.fundingLocked
}

ChannelRequest.prototype.finalise = function () {
  // move channel from pending to open
}
// 001f682e61aefe04b4d33bd908013841058282ea04413610144a0e13cefa6efa8800

function openChannelRequest (msg) {
  const info = {}

  info.temporaryChannelId = msg.temporaryChannelId
  info.fundingSatoshis = msg.fundingSatoshis
  info.pushMsat = msg.pushMsat
  info.maxHtlcValueInFlightMsat = msg.maxHtlcValueInFlightMsat
  info.dustLimitSatoshis = msg.dustLimitSatoshis
  info.channelReserveSatoshis = msg.channelReserveSatoshis
  info.htlcMinimumSat = msg.htlcMinimumSat
  info.feeratePerKw = msg.feeratePerKw
  info.toSelfDelay = msg.toSelfDelay
  info.maxAcceptedHtlcs = msg.maxAcceptedHtlcs

  info.channelFlags = msg.channelFlags

  return info
}

function fundingCreated (msg) {
  const info = {}

  info.fundingTxid = msg.fundingTxid
  info.fundingOutputIndex = msg.fundingOutputIndex
  info.signature = msg.signature

  return info
}

function shasum (data) {
  return crypto.createHash('sha256').update(data).digest()
}

function reverse (buf) {
  const ret = Buffer.alloc(buf.byteLength)
  for (let i = 0; i < buf.byteLength; i++) {
    ret[i] = buf[buf.byteLength - 1 - i]
  }

  return ret
}
