/*!
 * Copyright (c) 2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

import {parseRequest} from 'http-signature-header';
import {MockKmsPlugin} from './MockKmsPlugin.js';

export class MockKmsService {
  constructor({server}) {
    this.plugins = new Map();

    const mockPlugin = new MockKmsPlugin();
    this.plugins.set(mockPlugin.id, mockPlugin);

    const root = `/kms`;
    const routes = {
      operations: `${root}/operations`
    };

    server.post(routes.operations, async request => {
      // lowercase headers
      const headers = {};
      for(const key in request.requestHeaders) {
        headers[key.toLowerCase()] = request.requestHeaders[key];
      }
      const requestOptions = {
        method: request.method,
        url: request.url,
        headers
      };

      // get `controller` from key ID in Authorization header
      const parsed = parseRequest(
        requestOptions, {headers: ['expires', 'host', '(request-target)']});
      const controller = parsed.keyId;

      // parse operation from POST data
      const operation = JSON.parse(request.requestBody);

      const {method, parameters, plugin} = operation;
      // TODO: validate method, parameters, plugin

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
        result = await pluginApi[method]({...parameters, controller});
      } catch(e) {
        let code = 500;
        if(e instanceof TypeError) {
          code = 400;
        }
        return [code, {json: true}, e];
      }

      return [200, {json: true}, result];
    });
  }
}
