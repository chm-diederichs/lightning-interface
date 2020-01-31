const curve = require('secp256k1')
const crypto = require('crypto')
const biguintle = require('biguintle')

module.exports = newKeychain

module.exports = Keychain = function () {
  this.funding = generateKey()

  this._perCommitment = new PerCommitment()

  this._revocationBasepoint = {}
  this._paymentBasepoint = {} 
  this._delayedPaymentBasepoint = {} 
  this._htlcBasepoint = {}

  this._revocationBasepoint.local = generateKey()
  this._paymentBasepoint.local = generateKey() 
  this._delayedPaymentBasepoint.local = generateKey() 
  this._htlcBasepoint.local = generateKey()
}

Keychain.prototype.updateLocal = function () {
  this._perCommitment.update()
}

Keychain.prototype.addRemoteKeys = function (opts) {
  keychain.funding.remote = opts.fundingPubkey

  keychain._revocationBasepoint.remote = opts.revocationBasepoint
  keychain._paymentBasepoint.remote = opts.paymentBasepoint
  keychain._delayedPaymentBasepoint.remote = opts.delayedPaymentBasepoint
  keychain._htlcBasepoint.remote = opts.htlcBasepoint
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

  keys.local = derivePub(this.prevRemoteCommitment, this._paymentBasepoint.remote)
  keys.delayedPayment = derivePub(this.prevRemoteCommitment, this._delayedPaymentBasepoint.remote)
  keys.htlc = derivePub(this.prevRemoteCommitment, this._htlcBasepoint.remote)

  return keys
}

Keychain.prototype.getRevocationKey = function () {
  const remoteCommitment = generateKey(this.prevRemoteCommitment)

  return deriveRevocationKey(remoteCommitment, this._revocationBasepoint.local)
}

Keychain.prototype.getRemoteRevocationKey = function () {
  return deriveRevocationPub(this._perCommitment, this._revocationBasepoint.remote)
}

var PerCommitment = function () {
  this._seed = crypto.randomBytes(32)
  this.counter = 2 ** 48 - 1
  this.key

  this.update()
}

PerCommitment.prototype.update = function () {
  assert(this.counter > 0, 'maximum amount of per commitment secrets have been derived')
  this.key = generateKey(generateFromSeed(this._seed, this.counter))
  this.counter--
}

function deriveRevocationPub (commitment, base) {
  const revocationTweak = generateTweak(base.pub, commitment.pub)
  const commitmentTweak = generateTweak(commitment.pub, base.pub)

  const privKey = curve.add(curve.multiply(base.pub, revocationTweak), curve.multiply(commit.pub, commitmentTweak))

  return generateKey(privKey)
}

// helpers
function deriveRevocationKey (commitment, base) {
  const revocationTweak = generateTweak(base.pub, commitment.pub)
  const commitmentTweak = generateTweak(commitment.pub, base.pub)

  const privKey = add(multiply(base.priv, revocationTweak), multiply(commit.priv, commitmentTweak))

  return generateKey(privKey)
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

  return generateKey(privKey)
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
function generateKey (privKey) {
  const keyPair = {}

  keyPair.priv = privKey || newPrivKey()
  keyPair.pub = curve.publicKeyCreate(keyPair.priv).publicKey(convert)

  return keyPair

  function newPrivKey () {
    let key
    do {
      key = crypto.randomBytes(32)
    } while (!curve.privateKeyVerify(key))
    return key
  }
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
  let upperCounter = Math.floor(counter / 2 ** 32)
  let lowerCounter = counter % 2 ** 32
  let mask = 2 ** 15

  // do upper counter
  let upperSeed = seed.readUInt16BE(26)
  for (let i = 0; i < 16; i++) {
    if (upperCounter & mask > 0) upperSeed ^= mask
    mask = mask >> 1
  }
  seed.writeUInt16BE(upperSeed, 26)

  mask = 2 ** 31
  const lowerSeed = seed.readUInt32BE(28)
  for (let i = 0; i < 32; ) {
    if (lowerCounter) lowerSeed ^= mask
    mask = mask >> 1
  }
  seed.writeUInt32BE(upperSeed, 26)

  const result = crypto.createHash('sha256').update(seed).digest()
  return result
}
