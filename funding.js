const Keychain = require('./keys')
const script = require('./script')
const assert = require('nanoassert')

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

var ChannelRequest = function () {
  this.keychain = new Keychain()
  this.temporaryChannelId

  this.openChannel
  this.acceptChannel
  this.fundingCreated
  this.fundingSigned
  this.initiatorFundingLocked
  this.responderFundingLocked
}

ChannelRequest.prototype.handleChannelOpen = function (msg, opts) {
  this.temporaryChannelId = msg.temporaryChannelId

  this.keychain.addRemoteKeys(msg)
  this.openChannel = openChannelRequest(msg)

  const acceptChannelOpts = {
    temporaryChannelId: this.temporaryChannelId,
    dustLimitSatoshis: opts.dustLimitSatoshis,
    maxHtlcValueInFlightMsat: opts.maxHtlcValueInFlightMsat,
    channelReserveSatoshis: opts.channelReserveSatoshis,
    htlcMinimumSat: opts.htlcMinimumSat,
    minimumDepth: opts.minimumDepth,
    toSelfDelay: opts.toSelfDelay,
    maxAcceptedHtlcs: opts.maxAcceptedHtlcs,
    fundingPubkey: this.keychain.funding.pub,
    revocationBasepoint: this.keychain._revocationBasepoint.local.pub,
    paymentBasepoint: this.keychain._paymentBasepoint.local.pub,
    delayedPaymentBasepoint: this.keychain._delayedPaymentBasepoint.local.pub,
    htlcBasepoint: this.keychain._htlcBasepoint.local.pub,
    firstPerCommitmentPoint: this.keychain._perCommitment.local.pub,

    // optional
    shutdownLen: opts.shutdownLen,
    shutdownScriptPubKey: opts.shutdownScriptPubKey
  }

  assert(acceptChannelOpts.temporaryChannelId === this.openChannel.temporaryChannelId,
    'temporary channel ids must match')
  assert(acceptChannelOpts.channelReserveSatoshis >= this.openChannel.dustLimitSatoshis,
    `channel reserve sats must be >= ${this.openChannel.dustLimitSatoshis}`)
  assert(acceptChannelOpts.dustLimitSatoshis <= this.openChannel.dustLimitSatoshis,
    `channel reserve sats must be <= ${this.openChannel.dustLimitSatoshis}`)

  this.acceptChannel = acceptChannelOpts
}

ChannelRequest.handleFundingCreated = function (msg) {
  assert(msg.temporaryChannelId === this.temporaryChannelId, 'temporary channel ids must match')

  this.fundingCreated = fundingCreated(msg)

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
