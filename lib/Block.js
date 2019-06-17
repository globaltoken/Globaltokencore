var util = require('../util');
var Script = require('./Script');
var Bignum = require('bignum');
var buffertools = require('buffertools');
var Transaction = require('./Transaction');
var POSTransaction = require('./POSTransaction');
var TransactionIn = Transaction.In;
var TransactionOut = Transaction.Out;
var COINBASE_OP = Transaction.COINBASE_OP;
var VerificationError = require('../util/error').VerificationError;
var BlockRules = {
  maxTimeOffset: 2 * 60 * 60, // How far block timestamps can be into the future
  //largestHash: (new Bignum(2)).pow(256)
  //largestHash: new Bignum('115792089237316195423570985008687907853269984665640564039457584007913129639936') // = 2^256
  largestHash: new Bignum('10000000000000000000000000000000000000000000000000000000000000000', 16)
};

function Block(data) {
  if ("object" !== typeof data) {
    data = {};
  }
  this.hash = data.hash || null;
  this.prev_hash = data.prev_hash || util.NULL_HASH;
  this.merkle_root = data.merkle_root || util.NULL_HASH;
  this.hashreserved = data.hashreserved || util.NULL_HASH;
  this.timestamp = data.timestamp || 0;
  this.bits = data.bits || 0;
  this.nonce = data.nonce || 0;
  this.equihash_nonce = data.equihash_nonce || util.NULL_HASH;
  this.equihash_solution_size = data.equihash_solution_size || 0;
  this.equihash_solution = data.equihash_solution || null;
  this.version = data.version || 0;
  this.height = data.height || 0;
  this.size = data.size || 0;
  this.active = data.active || false;
  this.chainWork = data.chainWork || util.EMPTY_BUFFER;
  this.auxpow = data.auxpow || util.EMPTY_BUFFER;
  this.txs = data.txs || [];
}

Block.prototype.getHeader = function getHeader() {
  var buf = new Buffer(80);
  var ofs = 0;
  buf.writeUInt32LE(this.version, ofs);
  ofs += 4;
  this.prev_hash.copy(buf, ofs);
  ofs += 32;
  this.merkle_root.copy(buf, ofs);
  ofs += 32;
  buf.writeUInt32LE(this.timestamp, ofs);
  ofs += 4;
  buf.writeUInt32LE(this.bits, ofs);
  ofs += 4;
  buf.writeUInt32LE(this.nonce, ofs);
  ofs += 4;
  return buf;
};

Block.prototype.getEquihashHeader = function getEquihashHeader() {
  var buf = new Buffer(140);
  var solution_size_buf = [];
  var solutionbuffer = [];
  var ofs = 0;
  buf.writeUInt32LE(this.version, ofs);
  ofs += 4;
  this.prev_hash.copy(buf, ofs);
  ofs += 32;
  this.merkle_root.copy(buf, ofs);
  ofs += 32;
  this.hashreserved.copy(buf, ofs);
  ofs += 32;
  buf.writeUInt32LE(this.timestamp, ofs);
  ofs += 4;
  buf.writeUInt32LE(this.bits, ofs);
  ofs += 4;
  this.equihash_nonce.copy(buf, ofs);
  ofs += 32;
  solution_size_buf = util.varIntBuf(this.equihash_solution_size);
  solutionbuffer = new Buffer(this.equihash_solution, 'hex');
  return Buffer.concat([buf, solution_size_buf, solutionbuffer]);
};

Block.prototype.parse = function parse(parser, headerOnly) {
  this.version = parser.word32le();
  this.prev_hash = parser.buffer(32);
  this.merkle_root = parser.buffer(32);
  
  // Detects if this Block is an Equihash or Zhash Block.
  if(this.isEquihashAlgo())
     this.hashreserved = parser.buffer(32);

  this.timestamp = parser.word32le();
  this.bits = parser.word32le();
  // Detects if this Block is an Equihash or Zhash Block.
  if(this.isEquihashAlgo())
  {  
     this.equihash_nonce = parser.buffer(32);
     this.equihash_solution_size = parser.varInt();
     this.equihash_solution = parser.buffer(this.equihash_solution_size);
  }
  else
     this.nonce = parser.word32le();

  this.txs = [];
  this.auxpow = [];
  this.size = 0;
  
  // For now, we just store the auxpow buffer, because we don't need it encoded.
  // There is no auxpow explorer for GLT, so currently it is okay to just store the buffer.
  
  if(this.version & 256)
  {
     var auxpow_buffer = [];
     var auxpow_version = parser.word32le(); // auxpow2.0: nVersion
     var zhashPersonalize; // auxpow2.0: Zhash string 
     var zhash_pers_length; // auxpow2.0: The zhash personalization string length
     var merkletx_tx; // auxpow1.0: Merkletx
     if(auxpow_version & 0x00004000)
     {
        zhash_pers_length = parser.varInt();
        zhashPersonalize = parser.buffer(zhash_pers_length); // auxpow2.0: Zhash personalize String 
     }
     if(auxpow_version & 0x00001000)
     {
        console.log("Found Auxpow Block with POS: "+ this.getHash());
        var tx = new POSTransaction();
        tx.parse(parser);
        merkletx_tx = tx; // auxpow2.0: merkletx POS 
     }
     else
     {
        var tx = new Transaction();
        tx.parse(parser);
        merkletx_tx = tx; // auxpow1.0: merkletx
     }
     var auxpow_merkletx_hashblock = parser.buffer(32); // Auxpow1.0: Merkletx -> hashblock
     var merklebranch_count = parser.varInt(); // Auxpow 1.0: Merklebranch counter
     var merklebranch = []; // Auxpow 1.0: Merklebranch

     for (var i = 0; i < merklebranch_count; i++) {
        merklebranch.push(parser.buffer(32));
     }
     var merkle_index = parser.word32ls(); // Auxpow 1.0: Merkle Index
     var chain_merklebranch_count = parser.varInt(); // Auxpow 1.0: Auxpow Chain-Merklebranch counter
     var chain_merklebranch = []; // Auxpow 1.0: Auxpow Chain-Merklebranch
    
     for (var i = 0; i < chain_merklebranch_count; i++) {
        chain_merklebranch.push(parser.buffer(32));
     }
     var auxpow_chain_index = parser.word32ls(); // Auxpow 1.0: Chain Index
     var auxpow_parent_block = []; // Auxpow1.0: Parent Block
    
     // If this is an Equihash Merge mining block, then parse the parent block as an equihash block.
     if(auxpow_version & 0x00002000)
     {
       var auxpow_header_version = parser.word32le();
       var auxpow_header_prevhash = parser.buffer(32);
       var auxpow_header_merkle_root = parser.buffer(32);
       var auxpow_header_hashreserved = parser.buffer(32);
       var auxpow_header_timestamp = parser.word32le();
       var auxpow_header_bits = parser.word32le();
       var auxpow_header_nonce = parser.buffer(32);
       var auxpow_header_solution;
       
       var length = parser.varInt();
       auxpow_header_solution = parser.buffer(length);
       
       var buf = new Buffer(140);
       var solution_size_buf = [];
       var solutionbuffer = [];
       var ofs = 0;
       buf.writeUInt32LE(auxpow_header_version, ofs);
       ofs += 4;
       auxpow_header_prevhash.copy(buf, ofs);
       ofs += 32;
       auxpow_header_merkle_root.copy(buf, ofs);
       ofs += 32;
       auxpow_header_hashreserved.copy(buf, ofs);
       ofs += 32;
       buf.writeUInt32LE(auxpow_header_timestamp, ofs);
       ofs += 4;
       buf.writeUInt32LE(auxpow_header_bits, ofs);
       ofs += 4;
       auxpow_header_nonce.copy(buf, ofs);
       ofs += 32;
       solution_size_buf = util.varIntBuf(length);
       solutionbuffer = new Buffer(auxpow_header_solution, 'hex');
       auxpow_parent_block = Buffer.concat([buf, solution_size_buf, solutionbuffer]);
     }
     else
     {
       var auxpow_header_version = parser.word32le();
       var auxpow_header_prevhash = parser.buffer(32);
       var auxpow_header_merkle_root = parser.buffer(32);
       var auxpow_header_timestamp = parser.word32le();
       var auxpow_header_bits = parser.word32le();
       var auxpow_header_nonce = parser.word32le();
       
       var buf = new Buffer(80);
       var ofs = 0;
       buf.writeUInt32LE(auxpow_header_version, ofs);
       ofs += 4;
       auxpow_header_prevhash.copy(buf, ofs);
       ofs += 32;
       auxpow_header_merkle_root.copy(buf, ofs);
       ofs += 32;
       buf.writeUInt32LE(auxpow_header_timestamp, ofs);
       ofs += 4;
       buf.writeUInt32LE(auxpow_header_bits, ofs);
       ofs += 4;
       buf.writeUInt32LE(auxpow_header_nonce, ofs);
       ofs += 4;
       auxpow_parent_block = buf;       
     }
    
     // Create the Buffer
     var versionbuffer = new Buffer(4);
     versionbuffer.writeUInt32LE(auxpow_version, 0);
     auxpow_buffer.push(versionbuffer);
     if(auxpow_version & 0x00004000)
     {
        auxpow_buffer.push(util.varIntBuf(zhash_pers_length));
        auxpow_buffer.push(new Buffer(zhashPersonalize, 'utf8'));
     }
     auxpow_buffer.push(merkletx_tx.serialize());
     auxpow_buffer.push(new Buffer(auxpow_merkletx_hashblock, 'hex'));
     auxpow_buffer.push(util.varIntBuf(merklebranch_count));
     for(var i = 0; i < merklebranch_count; i++)
     {
        auxpow_buffer.push(new Buffer(merklebranch[i], 'hex'));
     }
     var merkle_index_buffer = new Buffer(4);
     merkle_index_buffer.writeInt32LE(merkle_index, 0);
     auxpow_buffer.push(merkle_index_buffer);
     auxpow_buffer.push(util.varIntBuf(chain_merklebranch_count));
     for(var i = 0; i < chain_merklebranch_count; i++)
     {
        auxpow_buffer.push(new Buffer(chain_merklebranch[i], 'hex'));
     }
     var auxpow_chain_index_buffer = new Buffer(4);
     auxpow_chain_index_buffer.writeInt32LE(auxpow_chain_index, 0);
     auxpow_buffer.push(auxpow_chain_index_buffer);
     auxpow_buffer.push(auxpow_parent_block);
     this.auxpow = Buffer.concat(auxpow_buffer);
  }

  if (headerOnly)
    return;

  var txCount = parser.varInt();

  for (var i = 0; i < txCount; i++) {
    var tx = new Transaction();
    tx.parse(parser);
    this.txs.push(tx);
  }
};

Block.prototype.calcHash = function calcHash() {
  var header;
  if(this.isEquihashAlgo())
     header = this.getEquihashHeader();
  else
     header = this.getHeader();

  return util.twoSha256(header);
};

Block.prototype.isEquihashAlgo = function isEquihashAlgo() {
  switch(this.version & 0xfe00)
  {
      case (5 << 9): // BLOCK_VERSION_EQUIHASH
        return true;
      case (23 << 9): // BLOCK_VERSION_ZHASH
        return true;
      case (46 << 9): // BLOCK_VERSION_EH192
        return true;
      case (47 << 9): // BLOCK_VERSION_MARS
        return true;
  }
  return false;
};

Block.prototype.checkHash = function checkHash() {
  if (!this.hash || !this.hash.length) return false;
  return buffertools.compare(this.calcHash(), this.hash) == 0;
};

Block.prototype.getHash = function getHash() {
  if (!this.hash || !this.hash.length) this.hash = this.calcHash();

  return this.hash;
};

Block.prototype.checkProofOfWork = function checkProofOfWork() {
  var target = util.decodeDiffBits(this.bits);

  // TODO: Create a compare method in node-buffertools that uses the correct
  //       endian so we don't have to reverse both buffers before comparing.
  var reverseHash = buffertools.reverse(this.hash);
  if (buffertools.compare(reverseHash, target) > 0) {
    throw new VerificationError('Difficulty target not met');
  }

  return true;
};

/**
 * Returns the amount of work that went into this block.
 *
 * Work is defined as the average number of tries required to meet this
 * block's difficulty target. For example a target that is greater than 5%
 * of all possible hashes would mean that 20 "work" is required to meet it.
 */
Block.prototype.getWork = function getWork() {
  var target = util.decodeDiffBits(this.bits, true);
  return BlockRules.largestHash.div(target.add(1));
};

Block.prototype.checkTimestamp = function checkTimestamp() {
  var currentTime = new Date().getTime() / 1000;
  if (this.timestamp > currentTime + BlockRules.maxTimeOffset) {
    throw new VerificationError('Timestamp too far into the future');
  }

  return true;
};

Block.prototype.checkTransactions = function checkTransactions(txs) {
  if (!Array.isArray(txs) || txs.length <= 0) {
    throw new VerificationError('No transactions');
  }
  if (!txs[0].isCoinBase()) {
    throw new VerificationError('First tx must be coinbase');
  }
  for (var i = 1; i < txs.length; i++) {
    if (txs[i].isCoinBase()) {
      throw new VerificationError('Tx index ' + i + ' must not be coinbase');
    }
  }

  return true;
};

/**
 * Build merkle tree.
 *
 * Ported from Java. Original code: BitcoinJ by Mike Hearn
 * Copyright (c) 2011 Google Inc.
 */
Block.prototype.getMerkleTree = function getMerkleTree(txs) {
  // The merkle hash is based on a tree of hashes calculated from the transactions:
  //
  //          merkleHash
  //             /\
  //            /  \
  //          A      B
  //         / \    / \
  //       tx1 tx2 tx3 tx4
  //
  // Basically transactions are hashed, then the hashes of the transactions are hashed
  // again and so on upwards into the tree. The point of this scheme is to allow for
  // disk space savings later on.
  //
  // This function is a direct translation of CBlock::BuildMerkleTree().

  if (txs.length == 0) {
    return [util.NULL_HASH.slice(0)];
  }

  // Start by adding all the hashes of the transactions as leaves of the tree.
  var tree = txs.map(function(tx) {
    return tx instanceof Transaction ? tx.getHash() : tx;
  });

  var j = 0;
  // Now step through each level ...
  for (var size = txs.length; size > 1; size = Math.floor((size + 1) / 2)) {
    // and for each leaf on that level ..
    for (var i = 0; i < size; i += 2) {
      var i2 = Math.min(i + 1, size - 1);
      var a = tree[j + i];
      var b = tree[j + i2];
      tree.push(util.twoSha256(Buffer.concat([a, b])));
    }
    j += size;
  }

  return tree;
};

Block.prototype.calcMerkleRoot = function calcMerkleRoot(txs) {
  var tree = this.getMerkleTree(txs);
  return tree[tree.length - 1];
};

Block.prototype.checkMerkleRoot = function checkMerkleRoot(txs) {
  if (!this.merkle_root || !this.merkle_root.length) {
    throw new VerificationError('No merkle root');
  }

  if (buffertools.compare(this.calcMerkleRoot(txs), new Buffer(this.merkle_root)) !== 0) {
    throw new VerificationError('Merkle root incorrect');
  }

  return true;
};

Block.prototype.checkBlock = function checkBlock(txs) {
  if (!this.checkHash()) {
    throw new VerificationError("Block hash invalid");
  }
  this.checkProofOfWork();
  this.checkTimestamp();

  if (txs) {
    this.checkTransactions(txs);
    if (!this.checkMerkleRoot(txs)) {
      throw new VerificationError("Merkle hash invalid");
    }
  }
  return true;
};

Block.getBlockValue = function getBlockValue(height) {
  var subsidy = 100 * util.COIN;
  if(height >= 400000 && height <= 416448)
    subsidy = 200 * util.COIN;
  subsidy = subsidy / (Math.pow(2, Math.floor(height / 840000)));
  subsidy = Math.floor(subsidy);
  subsidy = new Bignum(subsidy);
  return subsidy;
};

Block.prototype.getBlockValue = function getBlockValue() {
  return Block.getBlockValue(this.height);
};

Block.prototype.toString = function toString() {
  return "<Block " + util.formatHashAlt(this.hash) + " height=" + this.height + ">";
};


Block.prototype.createCoinbaseTx =
  function createCoinbaseTx(beneficiary) {
    var tx = new Transaction();
    tx.ins.push(new TransactionIn({
      s: util.EMPTY_BUFFER,
      q: 0xffffffff,
      o: COINBASE_OP
    }));
    tx.outs.push(new TransactionOut({
      v: util.bigIntToValue(this.getBlockValue()),
      s: Script.createPubKeyOut(beneficiary).getBuffer()
    }));
    return tx;
};

Block.prototype.solve = function solve(miner, callback) {
  var header = this.getHeader();
  var target = util.decodeDiffBits(this.bits);
  miner.solve(header, target, callback);
};

/**
 * Returns an object with the same field names as jgarzik's getblock patch.
 */
Block.prototype.getStandardizedObject =
  function getStandardizedObject(txs) {
    var block = {
      hash: util.formatHashFull(this.getHash()),
      version: this.version,
      prev_block: util.formatHashFull(this.prev_hash),
      mrkl_root: util.formatHashFull(this.merkle_root),
      time: this.timestamp,
      bits: this.bits,
      nonce: this.nonce,
      height: this.height
    };


    if (txs) {
      var mrkl_tree = this.getMerkleTree(txs).map(function(buffer) {
        return util.formatHashFull(buffer);
      });
      block.mrkl_root = mrkl_tree[mrkl_tree.length - 1];

      block.n_tx = txs.length;
      var totalSize = 80; // Block header
      totalSize += util.getVarIntSize(txs.length); // txn_count
      txs = txs.map(function(tx) {
        tx = tx.getStandardizedObject();
        totalSize += tx.size;
        return tx;
      });
      block.size = totalSize;
      block.tx = txs;

      block.mrkl_tree = mrkl_tree;
    } else {
      block.size = this.size;
    }
    return block;
};

module.exports = Block;
