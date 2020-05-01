const assert = require('nanoassert')
const crypto = require('crypto')
const Script = require('btc-script-builder')

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

  builder = new Script()

  builder.addOp('OP_2')
  builder.addData(aPub)
  builder.addData(bPub)
  builder.addOp('OP_2')
  builder.addOp('OP_CHECKMULTISIG')

  return builder.compile()
}

function genFundingPkScript (aPub, bPub, amount) {
  assert(amount >= 0, 'amount should be > 0.')

  // sort according to BIP-69
  if (aPub.compare(bPub) === 1) {
    [aPub, bPub] = [bPub, aPub]
  }

  const witnessScript = genMultiSigScript(aPub, bPub)
  const pkScript = witnessScriptHash(witnessScript)

  return {
    witnessScript,
    pkScript
  }
}

function commitmentTx (obscure, funding, script, value, commitmentNumber) {
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
    if (toLocal.value) tx.out.push(toLocal)
    tx.out.push(toRemote)
  } else {
    if (toRemote.value) tx.out.push(toRemote)
    tx.out.push(toLocal)
  }

  return tx
}

function createCommitmentTxns (obscure, funding, keys, delay, value, commitmentNumber, fee) {
  // NEED TO FIX: ourScripts are for "their tx" changing around leads to wrong obscure
  // we sign and send sig to remote
  const ourValue = value
  const ourScripts = {}

  ourScripts.local = localScript(keys.local.revocation.compress(), keys.local.delayedPayment.compress(), delay.local)
  ourScripts.remote = remoteScript(keys.remote.payment.compress())

  // we verify remote sig against this
  const theirValue = { local: value.remote, remote: value.local }
  const theirScripts = {}
  theirScripts.local = localScript(keys.remote.revocation.compress(), keys.remote.delayedPayment.compress(), delay.remote)
  theirScripts.remote = remoteScript(keys.local.payment.compress())

  const ourCommitmentTxn = commitmentTx(obscure, funding, ourScripts, ourValue, commitmentNumber)
  const theirCommitmentTxn = commitmentTx(obscure, funding, theirScripts, theirValue, commitmentNumber)

  return {
    toSign: theirCommitmentTxn,
    toVerify: ourCommitmentTxn
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
  const lockScript = new Script()
    .addOp('IF')
    .addData(revocationPubkey)
    .addOp('ELSE')
    .addData(toSelfDelay)
    .addOp('CHECKSEQUENCEVERIFY')
    .addOp('DROP')
    .addData(localDelayPubkey)
    .addOp('ENDIF')
    .addOp('CHECKSIG')
    .compile()

  console.log('SCRIPT', lockScript.toString('hex'))
  const witness = shasum(lockScript)
  const scriptPubKey = Buffer.alloc(34)
  scriptPubKey.writeUInt8(0x20, 1)
  scriptPubKey.set(witness, 2)
  console.log(scriptPubKey)

  return scriptPubKey
}

function shasum (item) {
  return crypto.createHash('sha256').update(item).digest()
}

function ripemd160 (item) {
  return crypto.createHash('ripemd160').update(item).digest()
}
