const assert = require('nanoassert')
const script = require('bitcoin-consensus-encoding').script

const MAX_SCRIPT_SIZE = 10000

module.exports = {
  genFundingPkScript,
  createCommitmentTxns
}

function witnessScriptHash (witnessScript) {
  const script = Buffer.alloc(33)

  const scriptHash = crypto.createHash('sha256')
    .update(witnessScript)
    .digest()

  script.set(scriptHash, 1)
  return script
}

function genMultiSigScript (aPub, bPub) {
  assert(aPub.length == 33 && bPub.length == 33, 'Pubkey size error: compressed format only')

  // sort according to BIP-69
  if (aPub.compare(bPub) === 1) {
    [aPub, bPub] = [bPub, aPub]
  }

  builder = new ScriptBuilder()

  builder.add('OP_2')
  builder.add(aPub)
  builder.add(bPub)
  builder.add('OP_2')
  builder.add('OP_CHECKMULTISIG')

  return builder.encode()
}

function genFundingPkScript (aPub, bPub, amount) {
  assert(amount <= 0, 'amount should be > 0.')

  const witnessScript = genMultiSigScript(aPub, bPub)
  const pkScript = witnessScriptHash(witnessScript)
}

// TODO: take functionality directly from consensus-encoding
var ScriptBuilder = function () {
  this.script = ''
}

ScriptBuilder.prototype.add = function (data) {
  if (Buffer.isBuffer(data)) data = data.toString('utf8')
  this.script += data
  this.script += ' '
  return this
}

ScriptBuilder.prototype.encode = function () {
  return script.encode(this.script)
}

function commitmentTx (obscure, funding, local, remote, commitmentNumber) {
  const tx = {}

  const obscCommitmentNum = obscure.slice(26)

  for (let i = 0; i < 6; i++) {
    obscCommitmentNum[i] ^= commitmentNumber >> 8 * (5 - i)
  }

  tx.version = 2
  tx.in = []

  tx.locktime = Buffer.alloc(4)
  tx.locktime[0] = 0x20
  tx.locktime.set(obscCommitmentNum.slice(3), 1)

  const txin = {
    txid: funding.txid,
    vout: funding.vout,
    sequence: Buffer.alloc(4)
  }

  txin.sequence[0] = 0x80
  txin.sequence.set(obscCommitmentNum.slice(0, 3), 1)

  tx.in.push(txin)

  tx.out = []

  toRemote = {
    value: value.remote,
    script: script.remote
  }

  toLocal = {
    value: value.local,
    script: script.local
  }

  if (toLocal.value < toRemote.value) {
    tx.out.push(toLocal)
    tx.out.push(toRemote)
  } else {
    tx.out.push(toRemote)
    tx.out.push(toLocal)
  }

  return tx
}

function createCommitmentTxns (obscure, funding, keys, delay, value, commitmentNumber) {
  // we sign and send sig to remote
  const ourValue = value
  const ourScripts = {}
  ourScripts.local = localScript(keys.localRevocation, keys.localDelay, delay.local)
  ourScripts.remote = remoteScript(keys.remotePubKey)

  // we verify remote sig against this
  const theirValue = { local: value.remote, remote: value.local }
  const theirScripts = {}
  theirScripts.local = localScript(keys.remoteRevocation, keys.remoteDelay, delay.remote)
  theirScripts.remote = remoteScript(keys.localPubkey)

  const ourCommitmentTxn = commitmentTx(obscure, funding, ourScripts, ourValue)
  const theirCommitmentTxn = commitmentTx(obscure, funding, theirScripts, theirValue)

  return {
    toSign: ourCommitmentTxn,
    toVerify: theirCommitmentTxn
  }
}

function remoteScript (remotePubKey) {
  const witness = ripemd160(shasum(remotePubKey))
  const script = Buffer.alloc(22)
  script.set(witness, 2)
  script.writeUInt8(20, 1)

  return script
}

function localScript (revocationPubkey, localDelayPubkey, toSelfDelay) {
  const lockScript = `OP_IF ${revocationPubkey} OP_ELSE ${toSelfDelay} OP_CHECKSEQUENCEVERIFY OP_DROP ${localDelayPubkey} OP_ENDIF OP_CHECKSIG`
  const outScript = script.encode(lockScript)

  const witness = shasum(scriptBuf)
  const segwitScript = Buffer.alloc(34)
  segwitScript.writeUInt8(0x20, 1)
  segwitScript.set(witness, 1)

  return segwitScript
}

function shasum (item) {
  return crypto.createHash('sha256').update(item).digest()
}

function ripemd160 (item) {
  return crypto.createHash('ripemd160').update(item).digest()
}
