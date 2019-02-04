var config = require('../config');
var log = require('../util/log');
var Address = require('./Address');
var Transaction = require('./Transaction');
var Script = require('./Script');
var ScriptInterpreter = require('./ScriptInterpreter');
var util = require('../util');
var bignum = require('bignum');
var Put = require('bufferput');
var Parser = require('../util/BinaryParser');
var buffertools = require('buffertools');
var error = require('../util/error');
var WalletKey = require('./WalletKey');
var PrivateKey = require('./PrivateKey');
var preconditions = require('preconditions').singleton();

var COINBASE_OP = Buffer.concat([util.NULL_HASH, new Buffer('FFFFFFFF', 'hex')]);
var FEE_PER_1000B_SAT = parseInt(0.0001 * util.COIN);

var TransactionIn = Transaction.In;
var TransactionOut = Transaction.Out;

Transaction.COINBASE_OP = COINBASE_OP;

function POSTransaction(data) {
  if ("object" !== typeof data) {
    data = {};
  }
  this.hash = data.hash || null;
  this.version = data.version;
  this.time = data.time;
  this.lock_time = data.lock_time;
  this.ins = Array.isArray(data.ins) ? data.ins.map(function(data) {
    var txin = new TransactionIn();
    txin.s = data.s;
    txin.q = data.q;
    txin.o = data.o;
    return txin;
  }) : [];
  this.outs = Array.isArray(data.outs) ? data.outs.map(function(data) {
    var txout = new TransactionOut();
    txout.v = data.v;
    txout.s = data.s;
    return txout;
  }) : [];
  if (data.buffer) this._buffer = data.buffer;
};
POSTransaction.In = TransactionIn;
POSTransaction.Out = TransactionOut;

POSTransaction.prototype.serialize = function serialize() {
  var bufs = [];

  var buf = new Buffer(4);
  buf.writeUInt32LE(this.version, 0);
  bufs.push(buf);
  
  var buf = new Buffer(4);
  buf.writeUInt32LE(this.time, 0);
  bufs.push(buf);

  bufs.push(util.varIntBuf(this.ins.length));
  this.ins.forEach(function(txin) {
    bufs.push(txin.serialize());
  });

  bufs.push(util.varIntBuf(this.outs.length));
  this.outs.forEach(function(txout) {
    bufs.push(txout.serialize());
  });

  var buf = new Buffer(4);
  buf.writeUInt32LE(this.lock_time, 0);
  bufs.push(buf);

  this._buffer = Buffer.concat(bufs);
  return this._buffer;
};

POSTransaction.prototype.getBuffer = function getBuffer() {
  if (this._buffer) return this._buffer;

  return this.serialize();
};

POSTransaction.prototype.serialize = function serialize() {
  var bufs = [];

  var buf = new Buffer(4);
  buf.writeUInt32LE(this.version, 0);
  bufs.push(buf);
  
  var buf = new Buffer(4);
  buf.writeUInt32LE(this.time, 0);
  bufs.push(buf);

  bufs.push(util.varIntBuf(this.ins.length));
  this.ins.forEach(function(txin) {
    bufs.push(txin.serialize());
  });

  bufs.push(util.varIntBuf(this.outs.length));
  this.outs.forEach(function(txout) {
    bufs.push(txout.serialize());
  });

  var buf = new Buffer(4);
  buf.writeUInt32LE(this.lock_time, 0);
  bufs.push(buf);

  this._buffer = Buffer.concat(bufs);
  return this._buffer;
};

POSTransaction.prototype.getBuffer = function getBuffer() {
  if (this._buffer) return this._buffer;

  return this.serialize();
};

POSTransaction.prototype.calcHash = function calcHash() {
  this.hash = util.twoSha256(this.getBuffer());
  return this.hash;
};

POSTransaction.prototype.calcHash = function calcHash() {
  this.hash = util.twoSha256(this.getBuffer());
  return this.hash;
};

POSTransaction.prototype.checkHash = function checkHash() {
  if (!this.hash || !this.hash.length) return false;

  return buffertools.compare(this.calcHash(), this.hash) === 0;
};

POSTransaction.prototype.getHash = function getHash() {
  if (!this.hash || !this.hash.length) {
    this.hash = this.calcHash();
  }
  return this.hash;
};


POSTransaction.prototype.calcNormalizedHash = function() {
  this.normalizedHash = this.hashForSignature(new Script(), 0, SIGHASH_ALL);
  return this.normalizedHash;
};


POSTransaction.prototype.getNormalizedHash = function() {
  if (!this.normalizedHash || !this.normalizedHash.length) {
    this.normalizedHash = this.calcNormalizedHash();
  }
  return this.normalizedHash;
};

POSTransaction.prototype.parse = function(parser) {
  if (Buffer.isBuffer(parser)) {
    this._buffer = parser;
    parser = new Parser(parser);
  }

  var i, sLen, startPos = parser.pos;

  this.version = parser.word32le();
  this.time = parser.word32le();

  var txinCount = parser.varInt();

  this.ins = [];
  for (i = 0; i < txinCount; i++) {
    var txin = new TransactionIn();
    txin.o = parser.buffer(36); // outpoint
    sLen = parser.varInt(); // script_len
    txin.s = parser.buffer(sLen); // script
    txin.q = parser.word32le(); // sequence
    this.ins.push(txin);
  }

  var txoutCount = parser.varInt();

  this.outs = [];
  for (i = 0; i < txoutCount; i++) {
    var txout = new TransactionOut();
    txout.v = parser.buffer(8); // value
    sLen = parser.varInt(); // script_len
    txout.s = parser.buffer(sLen); // script
    this.outs.push(txout);
  }

  this.lock_time = parser.word32le();
  this.calcHash();
};

module.exports = POSTransaction;
