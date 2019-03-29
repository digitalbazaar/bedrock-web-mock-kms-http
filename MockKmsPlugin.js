/*!
 * Copyright (c) 2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

import * as base64url from 'base64url-universal';

export class MockKmsPlugin {
  constructor() {
    this.id = 'mock';
    this.storage = new Map();
  }

  async generateKey({keyId, operation}) {
    const {invocationTarget: {type}} = operation;
    if(typeof keyId !== 'string') {
      throw new TypeError('"keyId" must be a string.');
    }
    if(typeof type !== 'string') {
      throw new TypeError('"operation.type" must be a string.');
    }

    // disable exporting keys
    let key;
    const extractable = false;

    if(type === 'AesKeyWrappingKey2019') {
      // TODO: support other lengths?
      key = await crypto.subtle.generateKey(
        {name: 'AES-KW', length: 256},
        extractable,
        ['wrapKey', 'unwrapKey']);
    } else if(type === 'Sha256HmacKey2019') {
      // TODO: support other hashes?
      key = await crypto.subtle.generateKey(
        {name: 'HMAC', hash: {name: 'SHA-256'}},
        extractable,
        ['sign', 'verify']);
    } else {
      throw new Error(`Unknown key type "${type}".`);
    }

    this.storage.set(keyId, key);
    return {id: keyId};
  }

  async wrapKey({keyId, operation}) {
    const {unwrappedKey} = operation;
    if(typeof keyId !== 'string') {
      throw new TypeError('"keyId" must be a string.');
    }
    if(typeof unwrappedKey !== 'string') {
      throw new TypeError(
        '"operation.unwrappedKey" must be a base64url-encoded string.');
    }

    const kek = this._getKey(keyId);

    let key = base64url.decode(unwrappedKey);
    // Note: algorithm name doesn't matter; will exported raw.
    // TODO: support other key lengths?
    const extractable = true;
    key = await crypto.subtle.importKey(
      'raw', key, {name: 'AES-GCM', length: 256}, extractable, ['encrypt']);
    const wrappedKey = await crypto.subtle.wrapKey(
      'raw', key, kek, kek.algorithm);
    return {wrappedKey: base64url.encode(new Uint8Array(wrappedKey))};
  }

  async unwrapKey({keyId, operation}) {
    let {wrappedKey} = operation;
    if(typeof keyId !== 'string') {
      throw new TypeError('"keyId" must be a string.');
    }
    if(typeof wrappedKey !== 'string') {
      throw new TypeError(
        '"operation.wrappedKey" must be a base64url-encoded string.');
    }

    const kek = this._getKey(keyId);

    let keyAlgorithm;
    if(kek.algorithm.name === 'AES-KW') {
      // Note: algorithm name doesn't matter; will be exported raw
      keyAlgorithm = {name: 'AES-GCM'};
    } else {
      throw new Error(`Unknown unwrapping algorithm "${kek.algorithm.name}".`);
    }

    wrappedKey = base64url.decode(wrappedKey);
    const extractable = true;
    const key = await crypto.subtle.unwrapKey(
      'raw', wrappedKey, kek, kek.algorithm,
      keyAlgorithm, extractable, ['encrypt']);

    const keyBytes = await crypto.subtle.exportKey('raw', key);
    return {unwrappedKey: base64url.encode(new Uint8Array(keyBytes))};
  }

  async sign({keyId, operation}) {
    const {verifyData} = operation;
    if(typeof keyId !== 'string') {
      throw new TypeError('"keyId" must be a string.');
    }
    if(typeof verifyData !== 'string') {
      throw new TypeError(
        '"operation.verifyData" must be a base64url-encoded string.');
    }

    const key = this._getKey(keyId);

    const data = base64url.decode(verifyData);
    const signature = new Uint8Array(
      await crypto.subtle.sign(key.algorithm, key, data));
    return {signatureValue: base64url.encode(signature)};
  }

  async verify({keyId, operation}) {
    const {signatureValue, verifyData} = operation;
    if(typeof keyId !== 'string') {
      throw new TypeError('"keyId" must be a string.');
    }
    if(typeof verifyData !== 'string') {
      throw new TypeError(
        '"operation.verifyData" must be a base64url-encoded string.');
    }
    if(typeof signatureValue !== 'string') {
      throw new TypeError(
        '"signatureValue" must be a base64url-encoded string.');
    }

    const key = this._getKey(keyId);

    const data = base64url.decode(verifyData);
    const signature = base64url.decode(signatureValue);
    return {
      verified: crypto.subtle.verify(key.algorithm, key, signature, data)
    };
  }

  _getKey(id) {
    const key = this.storage.get(id);
    if(!key) {
      throw new Error(`Key "${id}" not found.`);
    }
    return key;
  }
}
