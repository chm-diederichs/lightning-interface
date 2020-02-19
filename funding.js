const Keychain = require('./keys')
const script = require('./script')
const assert = require('nanoassert')
const btc = require('bitcoin-consensus-encoding')

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
    fundingPubkey: this.keychain.funding.pub,
    revocationBasepoint: this.keychain._revocationBasepoint.local.pub,
    paymentBasepoint: this.keychain._paymentBasepoint.local.pub,
    delayedPaymentBasepoint: this.keychain._delayedPaymentBasepoint.local.pub,
    htlcBasepoint: this.keychain._htlcBasepoint.local.pub,
    firstPerCommitmentPoint: this.keychain._perCommitment.pub,

    // optional
    shutdownLen: msg.shutdownLen,
    shutdownScriptPubKey: msg.shutdownScriptPubKey
  }

  assert(acceptChannelOpts.temporaryChannelId === this.openChannel.temporaryChannelId,
    'temporary channel ids must match')
  assert(acceptChannelOpts.channelReserveSatoshis >= this.openChannel.dustLimitSatoshis,
    `channel reserve sats must be >= ${this.openChannel.dustLimitSatoshis}`)
  assert(acceptChannelOpts.dustLimitSatoshis <= this.openChannel.dustLimitSatoshis,
    `channel reserve sats must be <= ${this.openChannel.dustLimitSatoshis}`)

  this.acceptChannel = acceptChannelOpts
  return this.acceptChannel
}

ChannelRequest.prototype.handleFundingCreated = function (msg) {
  assert(msg.temporaryChannelId === this.temporaryChannelId, 'temporary channel ids must match')

  this.fundingCreated = fundingCreated(msg)
  this.keychain.generateObscuringFactor()
  this.funding = msg.funding

  const obscure = this.keychain.obscuringFactor

  const delay = {
    local: this.acceptChannel.toSelfDelay,
    remote: this.openChannel.toSelfDelay
  }

  const value = {
    local: Math.floor(this.openChannel.pushMsat / 1000),
    remote: this.openChannel.fundingSatoshis
  }

  const feerate = this.openChannel.feeratePerKw

  // create the first commitment transactions to be signed / verified
  const commitmentTxns = script.createCommitmentTxns(obscure, msg.funding, delay, value, 1, feerate)

  assert(this.keychain.verifyCommitmentSig(msg.signature, commitmentTxns.toVerify), 'signature could not be verified.')

  // TODO: proper storage for signatures
  const theirSignature = msg.signture
  const ourSignature = this.keychain.signCommitment(commitmentTxns.toSign)

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
