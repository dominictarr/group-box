var tape = require('tape')

var groupbox = require('../')

var chloride = require('chloride')
var hash = chloride.crypto_hash_sha256

var alice = hash(new Buffer('ALICE'))
var bob = hash(new Buffer('BOB'))
var carol = hash(new Buffer('CAROL'))

var nonce = new Buffer(24)
nonce.fill(0)


tape('encrypt a simple message and decrypt it', function (t) {

  var plaintext = new Buffer('HELLO SECRET WORLD')
  var ciphertext =
    groupbox.box(plaintext, nonce, [alice, bob])

  t.deepEqual(groupbox.unbox(ciphertext, nonce, [bob], 2), plaintext)
  t.deepEqual(groupbox.unbox(ciphertext, nonce, [alice], 2), plaintext)
  t.deepEqual(groupbox.unbox(ciphertext, nonce, [carol], 2), undefined)

  t.end()
})


