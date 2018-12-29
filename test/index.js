var tape = require('tape')

var groupbox = require('../')

var chloride = require('chloride')
var hash = chloride.crypto_hash_sha256

var alice = hash(new Buffer('ALICE'))
var bob = hash(new Buffer('BOB'))
var carol = hash(new Buffer('CAROL'))

var eve = hash(new Buffer('EVE'))

var nonce = new Buffer(24)
nonce.fill(0)

//TODO: need way more test coverage!

function canDecrypt (t, ctxt, nonce, keys, attempts, plaintext) {
  t.deepEqual(groupbox.unbox(ctxt, nonce, keys, attempts), plaintext)
  var key = groupbox.unboxKey(ctxt, nonce, keys, attempts)
  if(key)
    t.deepEqual(groupbox.unboxBody(ctxt, nonce, key), plaintext)
}

tape('encrypt a simple message and decrypt it', function (t) {

  var plaintext = new Buffer('HELLO SECRET WORLD')
  var ciphertext =
    groupbox.box(plaintext, nonce, [alice, bob])

  canDecrypt(t, ciphertext, nonce, [bob], 2, plaintext)
  canDecrypt(t, ciphertext, nonce, [alice], 2, plaintext)
  canDecrypt(t, ciphertext, nonce, [carol], 2, undefined)
  canDecrypt(t, ciphertext, nonce, [bob], 1, undefined)
  canDecrypt(t, ciphertext, nonce, [alice], 0, undefined)


  t.notOk(groupbox.unbox(ciphertext, nonce, [eve], 8), 'eve cannot decrypt')

  t.end()
})


