var chloride = require('chloride')

var box = chloride.crypto_secretbox_easy
var unbox = chloride.crypto_secretbox_open_easy
var hmac = chloride.crypto_auth

function random (n) {
  var b = new Buffer(n)
  chloride.randombytes(b, n)
  return b
}

function trim (h) {
  return h.slice(0, 24)
}

const recip_length = 32+1+16
function offset(n) {
  return 32+recip_length*n
}

exports.box = function (plaintext, external_nonce, keys) {
  var nonce = random(32)
  var payload_key = random(32)
  var header_nonce = hmac(external_nonce, nonce)

  var header = Buffer.concat([nonce].concat(keys.map(function (key) {
    return box(
      Buffer.concat([payload_key, new Buffer([keys.length])]),
      trim(header_nonce),
      key
    )
  })))

  return Buffer.concat([
    header,
    box(
      plaintext,
      trim(hmac(header, header_nonce)),
      payload_key
    )
  ])
}

exports.unboxKey = function (ciphertext, external_nonce, keys, attempts) {
  var payload_key = null
  var nonce = ciphertext.slice(0, 32)
  var header_nonce = hmac(external_nonce, nonce)

  //try each of `keys` `attempts` times
  var header_nonce_trim = trim(header_nonce)
  for(var i in keys) {
    var key = keys[i]
    for(var j = 0; j < attempts && offset(j+1) < ciphertext.length; j++) {
      payload_key = unbox(
        ciphertext.slice(offset(j), offset(j+1)),
        header_nonce_trim,
        key
      )
      if(payload_key) return payload_key
    }
  }
}

exports.unboxBody = function (ciphertext, external_nonce, payload_key) {
  if(!payload_key) return
  var header_length = offset(payload_key[32])

  return unbox(
    ciphertext.slice(header_length, ciphertext.length),
    trim(hmac(
      ciphertext.slice(0, header_length),
      hmac(external_nonce, ciphertext.slice(0, 32))
    )),
    payload_key.slice(0, 32)
  )

}

exports.unbox = function (ciphertext, external_nonce, keys, attempts) {
  var payload_key = exports.unboxKey(ciphertext, external_nonce, keys, attempts)
  if(payload_key) return exports.unboxBody(ciphertext, external_nonce, payload_key)
}



