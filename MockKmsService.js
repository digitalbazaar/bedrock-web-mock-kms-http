/*!
 * Copyright (c) 2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

import {parseRequest} from 'http-signature-header';
import {MockKmsPlugin} from './MockKmsPlugin.js';

export class MockKmsService {
  constructor({mockAdapter}) {
    this.mockAdapter = mockAdapter;
    this.plugins = new Map();

    const mockPlugin = new MockKmsPlugin();
    this.plugins.set(mockPlugin.id, mockPlugin);

    const root = `/kms`;
    const routes = {
      operations: `${root}/operations`
    };

    mockAdapter.onPost(routes.operations).reply(async config => {
      // get `controller` from key ID in Authorization header
      const parsed = parseRequest(
        config, {headers: ['expires', 'host', '(request-target)']});
      const controller = parsed.keyId;

      // parse operation from POST data
      const operation = JSON.parse(config.data);

      const {method, parameters, plugin} = operation;
      // TODO: validate method, parameters, plugin

      // prevent calling private methods
      if(typeof method !== 'string' || method.startsWith('_')) {
        return [400, new TypeError('"method" must be a string.')];
      }

      // ensure plugin exists and supports operation method
      const pluginApi = this.plugins.get(plugin);
      if(!(pluginApi && typeof pluginApi[method] === 'function')) {
        return [400, new TypeError(`Method "${method}" is not supported.`)];
      }

      let result;
      try {
        result = await pluginApi[method]({...parameters, controller});
      } catch(e) {
        let code = 500;
        if(e instanceof TypeError) {
          code = 400;
        }
        return [code, e];
      }

      return [200, JSON.stringify(result)];
    });
  }
}
