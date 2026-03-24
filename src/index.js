'use strict';
const crypto = require('crypto');

// Manage and rotate API tokens with metadata and expiry

class TokenManager {
  constructor(options) {
    options = options || {};
    this._tokens = new Map();
    this.defaultTtl = options.defaultTtl || 86400000;
    this.tokenLength = options.tokenLength || 32;
  }

  _generate() {
    return crypto.randomBytes(this.tokenLength).toString('hex');
  }

  create(owner, options) {
    options = options || {};
    const token = this._generate();
    const ttl = options.ttl || this.defaultTtl;
    this._tokens.set(token, {
      owner,
      scopes: options.scopes || [],
      createdAt: Date.now(),
      expiresAt: Date.now() + ttl,
      lastUsed: null,
      rotatedFrom: options.rotatedFrom || null,
    });
    return token;
  }

  validate(token) {
    const entry = this._tokens.get(token);
    if (!entry) return { valid: false, reason: 'not found' };
    if (Date.now() > entry.expiresAt) {
      this._tokens.delete(token);
      return { valid: false, reason: 'expired' };
    }
    entry.lastUsed = Date.now();
    return { valid: true, owner: entry.owner, scopes: entry.scopes };
  }

  rotate(oldToken) {
    const entry = this._tokens.get(oldToken);
    if (!entry) throw new Error('Token not found');
    const newToken = this.create(entry.owner, { scopes: entry.scopes, rotatedFrom: oldToken });
    this._tokens.delete(oldToken);
    return newToken;
  }

  revoke(token) {
    return this._tokens.delete(token);
  }

  listByOwner(owner) {
    return [...this._tokens.entries()]
      .filter(([, v]) => v.owner === owner)
      .map(([k, v]) => ({ token: k.slice(0, 8) + '...', owner: v.owner, expiresAt: v.expiresAt }));
  }

  purgeExpired() {
    const now = Date.now();
    this._tokens.forEach((v, k) => { if (now > v.expiresAt) this._tokens.delete(k); });
    return this;
  }
}

module.exports = TokenManager;
