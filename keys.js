const curve = require('secp256k1')
const crypto = require('crypto')
const assert = require('nanoassert')
const biguintle = require('biguintle')

module.exports = Keychain = function () {
  this.funding = generateKeyPair()
  this.obscuringFactor

  this._perCommitment = new PerCommitment()

  this._revocationBasepoint = {}
  this._paymentBasepoint = {}
  this._delayedPaymentBasepoint = {}
  this._htlcBasepoint = {}

  this._revocationBasepoint.local = generateKeyPair()
  this._paymentBasepoint.local = generateKeyPair()
  this._delayedPaymentBasepoint.local = generateKeyPair()
  this._htlcBasepoint.local = generateKeyPair()
}

Keychain.prototype.signCommitment = function (data) {
  const ecdsaSig = curve.ecdsaSign(data, this.funding.local.priv)
  return curve.signatureExport(ecdsaSig)
}

Keychain.prototype.verifyCommitmentSig = function (signature, data) {
  const ecdsaSig = curve.signatureImport(signature)
  return curve.ecdsaVerify(ecdsaSig, data, this.funding.remote)
}

Keychain.prototype.updateLocal = function () {
  return this._perCommitment.update()
}

Keychain.prototype.addRemoteKeys = function (opts) {
  this.funding.remote = opts.fundingPubkey

  this._revocationBasepoint.remote = opts.revocationBasepoint
  this._paymentBasepoint.remote = opts.paymentBasepoint
  this._delayedPaymentBasepoint.remote = opts.delayedPaymentBasepoint
  this._htlcBasepoint.remote = opts.htlcBasepoint
}

// NOTE: insecure
Keychain.prototype.getLocalKeys = function () {
  const keys = {}

  keys.local = deriveKeys(this._perCommitment, this._paymentBasepoint.local)
  keys.delayedPayment = deriveKeys(this._perCommitment, this._delayedPaymentBasepoint.local)
  keys.htlc = deriveKeys(this._perCommitment, this._htlcBasepoint.local)

  return keys
}

Keychain.prototype.getRemoteKeys = function () {
  const keys = {}

  keys.remote = derivePub(this.prevRemoteCommitment, this._paymentBasepoint.remote)
  keys.delayedPayment = derivePub(this.prevRemoteCommitment, this._delayedPaymentBasepoint.remote)
  keys.htlc = derivePub(this.prevRemoteCommitment, this._htlcBasepoint.remote)

  return keys
}

Keychain.prototype.getRevocationKey = function () {
  const remoteCommitment = generateKeyPair(this.prevRemoteCommitment)

  return deriveRevocationKey(remoteCommitment, this._revocationBasepoint.local)
}

Keychain.prototype.getRemoteRevocationKey = function () {
  return deriveRevocationPub(this._perCommitment, this._revocationBasepoint.remote)
}

Keychain.prototype.generateObscuringFactor = function (initiator = false) {
  const arr = []

  if (initiator) {
    arr.push(this._paymentBasepoint.local.pub)
    arr.push(this._paymentBasepoint.remote)
  } else {
    arr.push(this._paymentBasepoint.remote)
    arr.push(this._paymentBasepoint.local.pub)
  }

  this.obscuringFactor = shasum(Buffer.concat(arr))
  return this.obscuringFactor
}

var PerCommitment = function () {
  this._seed = crypto.randomBytes(32)
  this.counter = 2 ** 48 - 1
  this.priv
  this.pub

  this.update()
}

PerCommitment.prototype.update = function () {
  assert(this.counter > 0, 'maximum amount of per commitment secrets have been derived')
  this.priv = generateFromSeed(this._seed, this.counter)
  this.pub = generatePubKey(this.priv)
  this.counter--

  return this.pub
}

function deriveRevocationPub (commitment, base) {
  const revocationTweak = generateTweak(base.pub, commitment.pub)
  const commitmentTweak = generateTweak(commitment.pub, base.pub)

  const privKey = curve.add(curve.multiply(base.pub, revocationTweak), curve.multiply(commit.pub, commitmentTweak))

  return generateKeyPair(privKey)
}

// helpers
function deriveRevocationKey (commitment, base) {
  const revocationTweak = generateTweak(base.pub, commitment.pub)
  const commitmentTweak = generateTweak(commitment.pub, base.pub)

  const privKey = add(multiply(base.priv, revocationTweak), multiply(commit.priv, commitmentTweak))

  return generateKeyPair(privKey)
}

function generateTweak (commitmentPoint, basepoint) {
  const toHash = Buffer.concat([commitmentPoint, basepoint])
  return crypto.createHash('sha256').update(toHash).digest()
}

function derivePub (commitmentPoint, basepoint) {
  const tweak = generateTweak(commitmentPoint, basepoint)
  return curve.publicKeyTweakAdd(basepoint, tweak)
}

function deriveKeys (commitmentPoint, basekey) {
  const tweak = generateTweak(commitmentPoint, basekey.pub)
  const privKey = add(basekey.priv, tweak)

  return generateKeyPair(privKey)
}

// buffer arithmetic
function multiply (a, b) {
  const mult = biguintle.decode(a) * biguintle.decode(b)
  return biguintle.encode(mult)
}

function add (a, b) {
  const mult = biguintle.decode(a) + biguintle.decode(b)
  return biguintle.encode(mult)
}

// generate key pairs
function generateKeyPair (privKey) {
  const keyPair = {}

  keyPair.priv = privKey || newPrivKey()
  keyPair.pub = generatePubKey(keyPair.priv)

  return keyPair

  function newPrivKey () {
    let key
    do {
      key = crypto.randomBytes(32)
    } while (!curve.privateKeyVerify(key))
    return key
  }
}

function generatePubKey (privKey) {
  const pub = curve.publicKeyCreate(privKey)
  pub.serializeCompressed = function () {
    return Buffer.from(curve.publicKeyConvert(this))
  }

  return pub
}

function extractKey (publicKey) {
  const pub = curve.publicKeyConvert(publicKey, false)
  pub.serializeCompressed = function () {
    return Buffer.from(curve.publicKeyConvert(this))
  }

  return pub
}

// specified in BOLT-03
function generateFromSeed (seed, counter) {
  const upperCounter = Math.floor(counter / 2 ** 32)
  const lowerCounter = counter % 2 ** 32
  let mask = 2 ** 15

  // do upper counter
  let upperSeed = seed.readUInt16BE(26)
  for (let i = 0; i < 16; i++) {
    if (upperCounter & mask > 0) upperSeed ^= mask
    mask = mask >> 1
  }
  seed.writeUInt16BE(upperSeed, 26)

  mask = 2 ** 31
  var lowerSeed = seed.readUInt32BE(28)
  for (let i = 0; i < 32; i++) {
    if (lowerCounter) lowerSeed ^= mask
    mask = mask >> 1
  }
  seed.writeUInt32BE(upperSeed, 26)

  const result = crypto.createHash('sha256').update(seed).digest()
  return result
}

function shasum (data) {
  return crypto.createHash('sha256').update(data).digest()
}
