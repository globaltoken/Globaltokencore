var Put = require('bufferput');
var buffertools = require('buffertools');
var hex = function(hex) {
  return new Buffer(hex, 'hex');
};

exports.livenet = {
  name: 'livenet',
  magic: hex('C708D32D'),
  addressVersion: 0x26,
  privKeyVersion: 0xa6,
  P2SHVersion: 141,
  P2SHVersion_OLD: 5,
  hkeyPublicVersion: 0x0488c42e,
  hkeyPrivateVersion: 0x0488e1f4,
  genesisBlock: {
    hash: hex('B6D3240D3996511B23B401F611EB137439378188736B4A34933E3EFE00000000'),
    merkle_root: hex('FC7F82994203580179E1D0CF77F32828C2BB4C94A5A60C188C45449476CE17E2'),
    height: 0,
    nonce: 2864352084,
    version: 1,
    prev_hash: buffertools.fill(new Buffer(32), 0),
    timestamp: 1480961109,
    bits: 486604799,
  },
  dnsSeeds: [
    '134.255.221.7'
  ],
  defaultClientPort: 9319
};

exports.mainnet = exports.livenet;

exports.testnet = {  // setup needs to be checked, testnet was not used.
  name: 'testnet',
  magic: hex('3A6F375B'),
  addressVersion: 27,
  privKeyVersion: 0xef,
  P2SHVersion: 8,
  P2SHVersion_OLD: 196,
  hkeyPublicVersion: 0x043587cf,
  hkeyPrivateVersion: 0x04358394,
  genesisBlock: {
    hash: hex('B6D3240D3996511B23B401F611EB137439378188736B4A34933E3EFE00000000'),
    merkle_root: hex('FC7F82994203580179E1D0CF77F32828C2BB4C94A5A60C188C45449476CE17E2'),
    height: 0,
    nonce: 2864352084,
    version: 1,
    prev_hash: buffertools.fill(new Buffer(32), 0),
    timestamp: 1480961109,
    bits: 486604799,
  },
  dnsSeeds: [
    '134.255.221.7'
  ],
  defaultClientPort: 19319
};
