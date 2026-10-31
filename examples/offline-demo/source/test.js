'use strict';
const assert = require('assert');
const { slugify, clamp } = require('./index');

assert.strictEqual(slugify('Hello World!'), 'hello-world');
assert.strictEqual(clamp(15, 0, 10), 10);
console.log('ok');
