/*!
 * Copyright (c) 2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

import * as base64url from 'base64url-universal';
import uuid from 'uuid-random';

export class MockKmsPlugin {
  constructor() {
    this.id = 'mock';
    this.storage = new Map();
  }

  async generateKey({controller, type, id = uuid()}) {
    if(typeof type !== 'string') {
      throw new TypeError('"type" must be a string.');
    }
    if(typeof id !== 'string') {
      throw new TypeError('"id" must be a string.');
    }

    if(this.storage.has(id)) {
      throw new Error(`Key "${id}" already exists.`);
    }

    // disable exporting keys
    let key;
    const extractable = false;

    if(type === 'AES-KW') {
      // TODO: support other lengths?
      key = await crypto.subtle.generateKey(
        {name: 'AES-KW', length: 256},
        extractable,
        ['wrapKey', 'unwrapKey']);
    } else if(type === 'HS256') {
      // TODO: support other hashes?
      key = await crypto.subtle.generateKey(
        {name: 'HMAC', hash: {name: 'SHA-256'}},
        extractable,
        ['sign', 'verify']);
    } else {
      throw new Error(`Unknown key type "${type}".`);
    }

    this.storage.set(id, {key, controller});
    return {id};
  }

  async wrapKey({controller, kekId, key}) {
    if(typeof kekId !== 'string') {
      throw new TypeError('"kekId" must be a string.');
    }
    if(typeof key !== 'string') {
      throw new TypeError('"key" must be a base64url-encoded string.');
    }

    const {key: kek} = this._getKeyRegistration({id: kekId, controller});

    key = base64url.decode(key);
    // Note: algorithm name doesn't matter; will exported raw.
    // TODO: support other key lengths?
    const extractable = true;
    key = await crypto.subtle.importKey(
      'raw', key, {name: 'AES-GCM', length: 256}, extractable, ['encrypt']);
    const wrappedKey = await crypto.subtle.wrapKey(
      'raw', key, kek, kek.algorithm);
    return {wrappedKey: base64url.encode(new Uint8Array(wrappedKey))};
  }

  async unwrapKey({controller, kekId, wrappedKey}) {
    if(typeof kekId !== 'string') {
      throw new TypeError('"kekId" must be a string.');
    }
    if(typeof wrappedKey !== 'string') {
      throw new TypeError('"wrappedKey" must be a base64url-encoded string.');
    }

    const {key: kek} = this._getKeyRegistration({id: kekId, controller});

    let keyAlgorithm;
    if(kek.algorithm === 'AES-KW') {
      // Note: algorithm name doesn't matter; will be exported raw
      keyAlgorithm = {name: 'AES-GCM'};
    } else {
      throw new Error(`Unknown unwrapping algorithm "${kek.algorithm}".`);
    }

    wrappedKey = base64url.decode(wrappedKey);
    const extractable = true;
    const key = await crypto.subtle.unwrapKey(
      'raw', wrappedKey, kek, kek.algorithm,
      keyAlgorithm, extractable, ['encrypt']);

    const keyBytes = await crypto.subtle.exportKey('raw', key);
    return {key: base64url.encode(new Uint8Array(keyBytes))};
  }

  async sign({controller, keyId, data}) {
    if(typeof keyId !== 'string') {
      throw new TypeError('"keyId" must be a string.');
    }
    if(typeof data !== 'string') {
      throw new TypeError('"data" must be a base64url-encoded string.');
    }

    const {key} = this._getKeyRegistration({id: keyId, controller});

    data = base64url.decode(data);
    const signature = new Uint8Array(
      await crypto.subtle.sign(key.algorithm, key, data));
    return {signature: base64url.encode(signature)};
  }

  async verify({controller, keyId, data, signature}) {
    if(typeof keyId !== 'string') {
      throw new TypeError('"keyId" must be a string.');
    }
    if(typeof data !== 'string') {
      throw new TypeError('"data" must be a base64url-encoded string.');
    }
    if(typeof signature !== 'string') {
      throw new TypeError('"signature" must be a base64url-encoded string.');
    }

    const {key} = this._getKeyRegistration({id: keyId, controller});

    data = base64url.decode(data);
    signature = base64url.decode(signature);
    return {
      verified: crypto.subtle.verify(key.algorithm, key, signature, data)
    };
  }

  _getKeyRegistration({id, controller}) {
    const registration = this.storage.get(id);
    if(!registration || registration.controller !== controller) {
      throw new Error(`Key "${id}" not found.`);
    }
    return registration;
  }
}
