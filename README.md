# group-box

a simpler way to encrypt a box with multiple recipients.

## api

### box (plaintext, external_nonce, keys)

encrypt plaintext to each of `keys`. external nonce should be a unique
but deterministic buffer, at least 32 bytes in length.
(a good candidate is the `author`+`hash` of previous message)

`keys` is an array of 32 byte symmetric keys.
these should probably scalarmult of two curve25519,
or semishared symmetric keys.

### unbox (ciphertext, external_nonce, keys, attempts)

`ciphertext` is the output of `box`,
`external_nonce` and `keys` are the same as in the `box`

`attempts` is how many times each key will be tried.

## representing groups

### direct: message from 1->many individuals

just get the scalarmult between the sender and recipients.
each recipient will attempt to open with their
`scalarmult(themself.secretKey, sender.publicKey)`

since they only need to test one key, but there may
be many recipients, so they'll need to test the key many times,
say, 8.

### broadcast: messages from a singe author to large group.

a author might create a named group of recipients,
such as "friends" or "family" or "colleagues".
they would send them a symmetric key for that group via
a direct private message.

any one in that group will attempt that key when they see
a message from the broadcaster.

``` js
box(plaintext, extern, [group_key], 3)
```

since the author might want to broadcast
to more than one group (friends and family)
recievers will need to test their key multiple times,
say, 3.

### shared: messages between many authors

similar to facebook groups. many authors can both read and write.
any current member can invite someone to the group
(by sending them the key, as in broadcast messages)

recipients must try the key for _every_ group they are a member
of, for _every_ message. therefore, each key should only be tried
once. messages may be encrypted to only one shared group
(but also other types of groups or individuals)

### administrated: messages between many authors, with controlled invite.

Using a key that no one will try is basically shadowbanning yourself.
With an administrator, we they can invite someone with a key
just for them + the current member list (so they can read other member's messages)

The administrator could be a single user, or it could be
a consensus process by the members.

### reveal: unlock a single message

As above where single keys are sent to a particular member,
a key to open a _particular_ message could also be sent
to a individual, or a group, or publically announced.

This could be used to reveal replies to broadcast messages.
the replier sends a direct message to the poster,
who then reposts the key to the reply to their group.

### removing a recipient

Removing a recipient can be accomplished by creating a new
key for all the other members. This would work probably work
best administrated groups. it would also be possible with
shared groups, but there could be some confusion about
what the new key is. Also, whoever added a bad actor the first
time might just readd them.

## discussion

A pattern here is that it's very easy to mute/shadowban someone,
but pretty hard to control read access, that is, it's very easy
to send someone else a key.

TahoeLAFS has a similar pattern, but interestingly, read access
and write access are separate, so you can have delegate.

However, they have the same "muting" problem, and basically
they have servers which only accept ciphertext from authors
that have the write cap. We can't really do this in the same
way, though, because all messages in the chain will be replicated.

## problems

just of the top of my head...
what if someone uses your key from a broadcast group as their
shared group key? (solution: always hmac the stated key with
the style of group)

eg, `hmac(key, "broadcast")`, then there will not be collisions.

It's pretty easy to leak keys in this system...
however, is there any way not to have that anyway?
You can't stop someone taking a screenshot of your post,
and sharing that. (whether you could plausibly deny it
depends on absense of corroborating evidence)

On the other hand, since authorship can be proven,
at least you can prove what you did actually say,
and someone who can't say you said something won't be very credible.

Privacy is a spectrum, and if something is known
to a large group of people that is less "privacy"
privacy is how many people _don't_ know something.

## License

MIT





