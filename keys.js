const curve = require('secp256k1')
const crypto = require('crypto')
const assert = require('nanoassert')
const biguintbe = require('biguintbe')

const CURVE_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n

module.exports = Keychain = function () {
  this.funding = {}
  this.funding.local = generateKeyPair()
  this.obscuringFactor

  this.prevRemoteCommitment

  this._revocationBasepoint = {}
  this._paymentBasepoint = {}
  this._delayedPaymentBasepoint = {}
  this._htlcBasepoint = {}
  this._perCommitment = {}

  this._revocationBasepoint.local = generateKeyPair()
  this._paymentBasepoint.local = generateKeyPair()
  this._delayedPaymentBasepoint.local = generateKeyPair()
  this._htlcBasepoint.local = generateKeyPair()
  this._perCommitment.local = new PerCommitment()
}

Keychain.prototype.signCommitment = function (digest, privKey) {
  if (!privKey) privKey = this.funding.local.priv
  const sigHash = dSha(digest)
  const ecdsaSig = curve.ecdsaSign(sigHash, privKey)
  return ecdsaSig.signature
  return curve.signatureExport(ecdsaSig.signature)
}

Keychain.prototype.verifyCommitmentSig = function (signature, digest) {
  console.log(signature.toString('hex'), '\n')
  // const ecdsaSig = curve.signatureImport(signature)
  const sigHash = dSha(digest)
  console.log('where')
  console.log(Buffer.from(this.funding.remote).toString('hex'))
  console.log(sigHash.toString('hex'), sigHash)
  return curve.ecdsaVerify(signature, sigHash, this.funding.remote.compress())
}

Keychain.prototype.updateLocal = function () {
  return this._perCommitment.local.update()
}

Keychain.prototype.addRemoteKeys = function (opts) {
  this.funding.remote = opts.fundingPubkey

  this._revocationBasepoint.remote = extractKey(opts.revocationBasepoint)
  this._paymentBasepoint.remote = extractKey(opts.paymentBasepoint)
  this._delayedPaymentBasepoint.remote = extractKey(opts.delayedPaymentBasepoint)
  this._htlcBasepoint.remote = extractKey(opts.htlcBasepoint)
  this._perCommitment.remote = extractKey(opts.firstPerCommitmentPoint)

  console.log("local revocation:", this._revocationBasepoint.local.pub.compress())
  console.log("local payment:", this._paymentBasepoint.local.pub.compress())
  console.log("local delay:", this._delayedPaymentBasepoint.local.pub.compress())
  console.log("local htlc:", this._htlcBasepoint.local.pub.compress())
  console.log("remote revocation:", this._revocationBasepoint.remote.compress())
  console.log("remote payment:", this._paymentBasepoint.remote.compress())
  console.log("remote delay:", this._delayedPaymentBasepoint.remote.compress())
  console.log("remote htlc:", this._htlcBasepoint.remote.compress())
  console.log(this._perCommitment.remote.compress())
}

Keychain.prototype.getScriptKeys = function () {
  const scriptKeys = {}
  
  scriptKeys.local = this.getLocalPubKeys()
  scriptKeys.remote = this.getRemotePubKeys()
  scriptKeys.local.revocation = this.getRemoteRevocationPubKey()
  scriptKeys.remote.revocation = this.getRevocationPubKey()

  return scriptKeys
}

// NOTE: insecure
Keychain.prototype.getLocalKeyPairs = function () {
  const keys = {}

  keys.payment = deriveKeys(this._perCommitment.local, this._paymentBasepoint.local)
  keys.delayedPayment = deriveKeys(this._perCommitment, this._delayedPaymentBasepoint.local)
  keys.htlc = deriveKeys(this._perCommitment, this._htlcBasepoint.local)

  return keys
}

Keychain.prototype.getLocalPubKeys = function () {
  const keys = {}

  keys.payment = derivePub(this._perCommitment.remote.compress(), this._paymentBasepoint.local.pub.compress())
  keys.delayedPayment = derivePub(this._perCommitment.local.pub.compress(), this._delayedPaymentBasepoint.local.pub.compress())
  keys.htlc = derivePub(this._perCommitment.local.pub.compress(), this._htlcBasepoint.local.pub.compress())
  keys.remoteHtlc = derivePub(this._perCommitment.local.pub.compress(), this._htlcBasepoint.remote.compress())

  return keys
}

Keychain.prototype.getRemotePubKeys = function () {
  const keys = {}

  keys.payment = derivePub(this._perCommitment.local.pub.compress(), this._paymentBasepoint.remote.compress())
  keys.delayedPayment = derivePub(this._perCommitment.remote.compress(), this._delayedPaymentBasepoint.remote.compress())
  keys.htlc = derivePub(this._perCommitment.remote.compress(), this._htlcBasepoint.remote.compress())
  keys.remoteHtlc = derivePub(this._perCommitment.remote.compress(), this._htlcBasepoint.local.pub.compress())

  return keys
}

Keychain.prototype.getRevocationPubKey = function () {
  return deriveRevocationPub(this._perCommitment.remote.compress(), this._revocationBasepoint.local.pub.compress())
}

Keychain.prototype.getRevocationKeyPair = function () {
  return deriveRevocationKey(this._perCommitment.local.compress(), this._revocationBasepoint.local.compress())
  const remoteCommitment = generateKeyPair(this.prevRemoteCommitment)

  return deriveRevocationKey(remoteCommitment, this._revocationBasepoint.local)
}

Keychain.prototype.getRemoteRevocationPubKey = function () {
  return deriveRevocationPub(this._perCommitment.local.pub.compress(), this._revocationBasepoint.remote.compress())
}

Keychain.prototype.generateObscuringFactor = function (initiator = false) {
  const arr = []

  if (initiator) {
    arr.push(this._paymentBasepoint.local.pub.compress())
    arr.push(this._paymentBasepoint.remote.compress())
  } else {
    arr.push(this._paymentBasepoint.remote.compress())
    arr.push(this._paymentBasepoint.local.pub.compress())
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
  const revocationTweak = generateTweak(base, commitment)
  const commitmentTweak = generateTweak(commitment, base)

  const keysToAdd = []
  keysToAdd.push(curve.publicKeyTweakMul(base, revocationTweak))
  keysToAdd.push(curve.publicKeyTweakMul(commitment, commitmentTweak))

  const revocationPubKey = curve.publicKeyCombine(keysToAdd)
  return extractKey(revocationPubKey)
}

// helpers
function deriveRevocationKey (commitment, base) {
  const revocationTweak = generateTweak(base.pub.compress(), commitment.pub.compress())
  const commitmentTweak = generateTweak(commitment.pub.compress(), base.pub.compress())

  const privKey = add(multiply(base.priv, revocationTweak), multiply(commitment.priv, commitmentTweak))
  return generateKeyPair(privKey)
}

function generateTweak (commitmentPoint, basepoint) {
  const toHash = Buffer.concat([commitmentPoint, basepoint])
  return crypto.createHash('sha256').update(toHash).digest()
}

function derivePub (commitmentPoint, basepoint) {
  console.log(commitmentPoint, basepoint)
  const tweak = generateTweak(commitmentPoint, basepoint)
  const pubKey = curve.publicKeyTweakAdd(basepoint, tweak)
  return extractKey(pubKey)
}

function deriveKeys (commitmentPoint, basekey) {
  const tweak = generateTweak(commitmentPoint.pub.compress(), basekey.pub.compress())
  const privKey = add(basekey.priv, tweak)

  return generateKeyPair(privKey)
}

// buffer arithmetic
function multiply (a, b) {
  const mult = biguintbe.decode(a) * biguintbe.decode(b)
  return biguintbe.encode(mult % CURVE_ORDER)
}

function add (a, b) {
  const mult = biguintbe.decode(a) + biguintbe.decode(b)
  return biguintbe.encode(mult)
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
  
  pub.compress = function () {
    return Buffer.from(curve.publicKeyConvert(this))
  }

  pub.decompress = function () {
    return Buffer.from(curve.publicKeyConvert(this, false))
  }

  return pub
}

module.exports.extractKey = extractKey = function (publicKey) {
  const pub = curve.publicKeyConvert(publicKey, false)

  pub.compress = function () {
    return Buffer.from(curve.publicKeyConvert(this))
  }

  pub.decompress = function () {
    return Buffer.from(curve.publicKeyConvert(this, false))
  }

  return pub
}

function decompress (pubkey) {
  return Buffer.from(curve.publicKeyConvert(pubkey, false))
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

function dSha (data) {
  return shasum(shasum(data))
}
