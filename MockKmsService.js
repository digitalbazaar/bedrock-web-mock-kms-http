/*!
 * Copyright (c) 2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

// TODO: import ocapld
import {MockKmsPlugin} from './MockKmsPlugin.js';

export class MockKmsService {
  constructor({server}) {
    this.plugins = new Map();

    const mockPlugin = new MockKmsPlugin();
    this.plugins.set(mockPlugin.id, mockPlugin);

    const root = `/kms`;
    const routes = {
      operations: `${root}/:plugin/:uuid`
    };

    this.storage = new Map();

    server.post(routes.operations, async request => {
      // get plugin and operation from request
      const {plugin} = request.params;
      const operation = JSON.parse(request.requestBody);
      // TODO: validate operation

      // TODO: verify ocap invocation proof; ensure `controller` matches key ID
      const controller = operation.proof.verificationMethod;

      const isGenerateKeyOp = operation.type === 'GenerateKeyOperation';
      const keyId = isGenerateKeyOp ?
        operation.invocationTarget.id : operation.invocationTarget;

      const record = this.storage.get(keyId);
      if(isGenerateKeyOp) {
        // check for duplicate key
        if(record) {
          return [
            409, {json: true}, new Error(`Key "${keyId}" already exists.`)];
        }
      } else {
        // ensure `controller` matches
        if(record.controller !== controller) {
          return [400, {json: true}, new Error(`Key "${keyId}" not found.`)];
        }
      }

      // determine plugin and method
      const method = operation.type.charAt(0).toLowerCase() +
        operation.type.substring(1, operation.type.indexOf('Operation'));

      // prevent calling private methods
      if(typeof method !== 'string' || method.startsWith('_')) {
        return [
          400,
          {json: true},
          new TypeError('"method" must be a string.')
        ];
      }

      // ensure plugin exists and supports operation method
      const pluginApi = this.plugins.get(plugin);
      if(!(pluginApi && typeof pluginApi[method] === 'function')) {
        return [
          400,
          {json: true},
          new TypeError(`Method "${method}" is not supported.`)
        ];
      }

      let result;
      try {
        result = await pluginApi[method]({keyId, operation});
      } catch(e) {
        let code = 500;
        if(e instanceof TypeError) {
          code = 400;
        }
        return [code, {json: true}, e];
      }

      if(isGenerateKeyOp) {
        this.storage.set(keyId, {controller});
      }

      return [200, {json: true}, result];
    });
  }
}
