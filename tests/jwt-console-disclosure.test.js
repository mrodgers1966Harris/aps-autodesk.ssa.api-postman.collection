/**
 * Runs the collection's JWT exchange pre-request scripts through Newman 6.2.3
 * (postman-runtime 7.39.1 / postman-sandbox 4.7.1) and checks the console
 * channel those versions actually emit.
 *
 * The service-account private key is generated in this process. It is never
 * written into the test source. A local server stands in for the token and
 * key endpoints so the run does not leave the machine.
 *
 * The test fails while any exchange script prints the private key or a
 * signature that verifies with that key. It passes when those scripts still
 * sign a JWT into the environment and leave both values out of the console.
 */
'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');
const test = require('node:test');

const newman = require('newman');

const COLLECTION_PATH = path.join(
    __dirname,
    '..',
    'Secure Service Account (SSA) API.postman_collection.json'
);

const CREATE_KEY_REQUESTS = [
    'SSA API - POST Create Keys',
    'Step 3: Create RSA Private key'
];

const EXCHANGE_REQUESTS = [
    'SSA API - POST Exchange token with JWT Assertion',
    'Step 1 & Step 2: Generate JWT Assertion and Exchange JWT Assertion for a Token',
    'Generate JWT Assertion and Exchange JWT Assertion for a Token'
];

function walkItems (items, found = []) {
    for (const item of items || []) {
        if (Array.isArray(item.item)) {
            walkItems(item.item, found);
        }
        else {
            found.push(item);
        }
    }
    return found;
}

function findRequest (items, name) {
    const match = walkItems(items).find((item) => item.name === name);
    if (!match) {
        throw new Error(`collection is missing request ${name}`);
    }
    return match;
}

function findJsrsaSignUrl (items) {
    for (const item of items || []) {
        const raw = item.request && item.request.url && item.request.url.raw;
        if (typeof raw === 'string' && raw.includes('jsrsasign-all-min.js')) {
            return raw;
        }
        if (Array.isArray(item.item)) {
            const nested = findJsrsaSignUrl(item.item);
            if (nested) {
                return nested;
            }
        }
    }
    return null;
}

function stripAnsi (value) {
    return value.replace(/\u001b\[[0-9;]*m/g, '');
}

/**
 * Collapse console formatting so a wrapped or escaped PEM/JWT still matches.
 * ANSI color, whitespace, and escaped newlines are not part of the secret.
 */
function compactConsoleText (value) {
    return stripAnsi(String(value))
        .replace(/\\r\\n|\\n|\\r/g, '')
        // util.inspect splits long strings with `' + '` when Newman wraps a line.
        .replace(/'\s*\+\s*'/g, '')
        .replace(/[│┌┐└┘├┤┬┴┼╭╮╯╰─]/g, '')
        .replace(/\s+/g, '');
}

function jwtPayload (token) {
    const parts = String(token).split('.');
    if (parts.length !== 3) {
        return null;
    }
    try {
        return JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    }
    catch (error) {
        return null;
    }
}

function flattenMessage (value) {
    if (typeof value === 'string') {
        return value;
    }
    if (value == null) {
        return '';
    }
    if (typeof value === 'number' || typeof value === 'boolean') {
        return String(value);
    }
    try {
        return JSON.stringify(value);
    }
    catch (error) {
        return '';
    }
}

function textContainsSecret (haystack, secret) {
    if (!secret) {
        return false;
    }
    const raw = String(haystack);
    if (raw.includes(secret)) {
        return true;
    }
    const compactSecret = compactConsoleText(secret);
    return compactSecret.length > 0 && compactConsoleText(raw).includes(compactSecret);
}

function jwtFromMessages (messages) {
    const found = [];
    const pattern = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;
    for (const message of messages) {
        const text = flattenMessage(message).trim();
        if (pattern.test(text)) {
            found.push(text);
        }
        const embedded = text.match(/[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g) || [];
        for (const token of embedded) {
            found.push(token);
        }
    }
    return found;
}

function verifiesWithPublicKey (token, publicKeyPem) {
    const parts = String(token).split('.');
    if (parts.length !== 3) {
        return false;
    }
    let header;
    try {
        header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
    }
    catch (error) {
        return false;
    }
    if (!header || header.alg !== 'RS256') {
        return false;
    }
    const verifier = crypto.createVerify('RSA-SHA256');
    verifier.update(`${parts[0]}.${parts[1]}`);
    try {
        return verifier.verify(publicKeyPem, Buffer.from(parts[2], 'base64url'));
    }
    catch (error) {
        return false;
    }
}

function environmentValue (environment, key) {
    if (!environment) {
        return undefined;
    }
    if (typeof environment.get === 'function') {
        return environment.get(key);
    }
    const values = environment.values || [];
    const match = values.find((entry) => entry.key === key);
    return match && match.value;
}

function captureProcessOutput (run) {
    const chunks = [];
    const stdoutWrite = process.stdout.write.bind(process.stdout);
    const stderrWrite = process.stderr.write.bind(process.stderr);
    const record = (chunk, encoding) => {
        chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk), encoding || 'utf8'));
    };
    process.stdout.write = (chunk, encoding, callback) => {
        record(chunk, typeof encoding === 'string' ? encoding : undefined);
        if (typeof encoding === 'function') {
            encoding();
        }
        else if (typeof callback === 'function') {
            callback();
        }
        return true;
    };
    process.stderr.write = (chunk, encoding, callback) => {
        record(chunk, typeof encoding === 'string' ? encoding : undefined);
        if (typeof encoding === 'function') {
            encoding();
        }
        else if (typeof callback === 'function') {
            callback();
        }
        return true;
    };

    return Promise.resolve()
        .then(run)
        .finally(() => {
            process.stdout.write = stdoutWrite;
            process.stderr.write = stderrWrite;
        })
        .then((result) => ({
            result,
            output: Buffer.concat(chunks).toString('utf8')
        }));
}

function startLocalApi (privateKeyPem, kid) {
    const server = http.createServer((request, response) => {
        const url = new URL(request.url, 'http://127.0.0.1');
        if (request.method === 'POST' && url.pathname.endsWith('/keys')) {
            response.writeHead(201, { 'content-type': 'application/json' });
            response.end(JSON.stringify({
                kid,
                privateKey: privateKeyPem,
                status: 'ENABLED'
            }));
            return;
        }
        if (request.method === 'POST' && url.pathname.endsWith('/token')) {
            response.writeHead(200, { 'content-type': 'application/json' });
            response.end(JSON.stringify({
                access_token: 'placeholder-access-token',
                token_type: 'Bearer',
                expires_in: 3600
            }));
            return;
        }
        response.writeHead(404, { 'content-type': 'application/json' });
        response.end(JSON.stringify({ message: 'not found' }));
    });

    return new Promise((resolve, reject) => {
        server.listen(0, '127.0.0.1', () => {
            const address = server.address();
            resolve({
                server,
                baseDomain: `http://127.0.0.1:${address.port}/`
            });
        });
        server.on('error', reject);
    });
}

test('exchange pre-request scripts do not write the private key or JWT to the console', { timeout: 180000 }, async () => {
    const collection = JSON.parse(fs.readFileSync(COLLECTION_PATH, 'utf8'));
    const libraryUrl = findJsrsaSignUrl(collection.item);
    if (!libraryUrl) {
        throw new Error('collection is missing the jsrsasign download request');
    }
    const libraryResponse = await fetch(libraryUrl);
    assert.equal(libraryResponse.ok, true, `could not download the JWT library the collection requests`);
    const jsrsasignSource = await libraryResponse.text();
    assert.equal(jsrsasignSource.includes('KJUR'), true, 'downloaded library does not expose KJUR');

    const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048
    });
    const privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' });
    const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' });
    const kid = 'placeholder-key-id';

    const local = await startLocalApi(privateKeyPem, kid);
    try {
        const requests = [
            ...CREATE_KEY_REQUESTS.map((name) => findRequest(collection.item, name)),
            ...EXCHANGE_REQUESTS.map((name) => findRequest(collection.item, name))
        ];
        const runCollection = {
            info: collection.info,
            item: requests
        };
        const environment = {
            name: 'ssa-console-disclosure-test',
            values: [
                { key: 'client_id', value: 'placeholder-client-id', enabled: true },
                { key: 'client_secret', value: 'placeholder-client-secret', type: 'secret', enabled: true },
                { key: 'base_domain', value: local.baseDomain, enabled: true },
                { key: 'token_scope', value: 'data:read data:write', enabled: true },
                { key: 'ssa_id', value: 'placeholder-service-account-id', enabled: true },
                { key: 'kid', value: kid, enabled: true },
                { key: 'jsrsasign-js', value: jsrsasignSource, enabled: true }
            ]
        };

        const seenUrls = [];
        const consoleByItem = new Map();
        const assertionByItem = new Map();
        let currentItem = null;
        let liveEnvironment = null;

        const { output } = await captureProcessOutput(() => new Promise((resolve, reject) => {
            const emitter = newman.run({
                collection: runCollection,
                environment,
                reporters: ['cli'],
                reporter: { cli: { noConsole: false } },
                color: 'off',
                timeoutRequest: 10000,
                timeoutScript: 120000
            }, (error, summary) => {
                if (error) {
                    reject(error);
                    return;
                }
                resolve(summary);
            });

            emitter.on('start', () => {
                liveEnvironment = emitter.summary && emitter.summary.environment;
            });
            emitter.on('beforeItem', (_error, args) => {
                currentItem = args.item && args.item.name;
                if (currentItem && !consoleByItem.has(currentItem)) {
                    consoleByItem.set(currentItem, []);
                }
            });
            emitter.on('console', (_error, args) => {
                const bucket = consoleByItem.get(currentItem) || [];
                bucket.push(...(args.messages || []));
                consoleByItem.set(currentItem, bucket);
            });
            emitter.on('request', (_error, args) => {
                const url = args.request && args.request.url && args.request.url.toString();
                if (url) {
                    seenUrls.push(url.split('?')[0]);
                }
            });
            emitter.on('item', (_error, args) => {
                const name = args.item && args.item.name;
                if (name) {
                    assertionByItem.set(name, environmentValue(liveEnvironment, 'jwt_assertion'));
                }
            });
        }));

        assert.equal(liveEnvironment != null, true, 'Newman did not expose the run environment');

        const keyPosts = seenUrls.filter((url) => url.startsWith(local.baseDomain) && url.endsWith('/keys'));
        assert.equal(
            keyPosts.length,
            CREATE_KEY_REQUESTS.length,
            `key-creation requests did not all reach the local stand-in (${seenUrls.join(', ')})`
        );
        assert.equal(
            environmentValue(liveEnvironment, 'privateKey') === privateKeyPem,
            true,
            'Create Keys test script did not store the response privateKey on the environment'
        );

        const problems = [];
        for (const name of EXCHANGE_REQUESTS) {
            const messages = consoleByItem.get(name) || [];
            const rendered = messages.map(flattenMessage).join('\n');
            const stored = assertionByItem.get(name);
            const storedVerifies = verifiesWithPublicKey(stored, publicKeyPem);
            const signedTokens = jwtFromMessages(messages).filter((token) => verifiesWithPublicKey(token, publicKeyPem));
            const payload = storedVerifies ? jwtPayload(stored) : null;
            const scope = payload && payload.scope;
            const scopeText = Array.isArray(scope) ? scope.join(' ') : String(scope || '');
            const expiresSoon = payload && Number.isFinite(payload.exp) &&
                payload.exp > (Date.now() / 1000) &&
                payload.exp <= (Date.now() / 1000) + 300 + 5;
            const expectedAudience = `${local.baseDomain}authentication/v2/token`;
            if (!storedVerifies || payload.aud !== expectedAudience ||
                !scopeText.includes('data:read') || !scopeText.includes('data:write') || !expiresSoon) {
                problems.push(`${name} did not leave a short-lived data:read data:write jwt_assertion in the environment`);
            }
            if (textContainsSecret(rendered, privateKeyPem)) {
                problems.push(`${name} wrote privateKey to the console`);
            }
            if (signedTokens.length > 0) {
                problems.push(`${name} wrote the signed assertion to the console`);
            }
            if (storedVerifies && textContainsSecret(output, stored)) {
                problems.push(`Newman CLI output contained the assertion from ${name}`);
            }
        }
        const headerLine = privateKeyPem.split(/\r?\n/).find((line) => line.startsWith('-----BEGIN'));
        if (headerLine && stripAnsi(output).includes(headerLine)) {
            problems.push('Newman CLI output contained privateKey');
        }

        assert.deepEqual(problems, [], problems.join('\n'));
    }
    finally {
        await new Promise((resolve, reject) => {
            local.server.close((error) => error ? reject(error) : resolve());
        });
    }
});
