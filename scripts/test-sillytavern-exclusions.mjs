#!/usr/bin/env node
// Test the installed package's exclusion helper; live HTTP checks cover route wiring.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';

if (process.argv.length !== 3) {
    console.error('Usage: node test-sillytavern-exclusions.mjs <sillytavern-source-or-module-directory>');
    process.exit(2);
}
const source = fs.readFileSync(path.join(process.argv[2], 'src/endpoints/backends/chat-completions.js'), 'utf8');
const helper = source.match(/function isExcludedModel\(modelId\) \{[\s\S]*?\n\}/)?.[0];
assert.ok(helper, 'Installed package has the exclusion helper');
let prefixes = ['rewind/'];
const context = vm.createContext({
    getConfigValue(key, fallback) {
        assert.equal(key, 'openai.excludedModelPrefixes');
        return prefixes === undefined ? fallback : prefixes;
    },
});
vm.runInContext(helper, context);
const excluded = context.isExcludedModel;
for (const id of ['rewind/gpt-6-astra', 'rewind/gpt-chat-latest', ' rewind/gpt-6-astra ']) {
    assert.equal(excluded(id), true, id);
}
for (const id of ['gpt-6-astra', 'vertex/gemini-4-argon', 'bonsai-hikari', 'qwen3.8-27b', null, {}, 42]) {
    assert.equal(excluded(id), false);
}
const models = [{ id: 'rewind/gpt-6-astra' }, { id: 'gpt-6-astra' }, { id: 'bonsai-main' }];
assert.deepEqual(models.filter(model => !excluded(model.id)), models.slice(1));
for (prefixes of [[], null, undefined, [''], [null, 42]]) {
    assert.equal(excluded('rewind/gpt-6-astra'), false, 'Empty or malformed exclusions do not exclude everything');
}
const generate = source.slice(source.indexOf("router.post('/generate'"));
const guardAt = generate.indexOf('if (isExcludedModel(request.body.model))');
const dispatchAt = generate.indexOf('switch (request.body.chat_completion_source)');
assert.ok(guardAt >= 0 && dispatchAt > guardAt, 'Guard precedes every provider dispatch');
assert.ok(generate.includes("type: 'model_not_allowed'"));
assert.ok(source.includes('data.data = data.data.filter(model => !isExcludedModel(model?.id));'));
console.log('PASS installed exclusion helper, catalog filter and pre-dispatch guard');
