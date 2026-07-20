// Demo app only — dependencies are pinned to known-vulnerable versions for SCA testing.
const _ = require("lodash");
const minimist = require("minimist");
const postcss = require("postcss");
const qs = require("qs");

const args = minimist(process.argv.slice(2));
console.log("regression-gate-demo-app");
console.log("lodash sample:", _.join(["hello", "world"], " "));
console.log("postcss version:", postcss().version);
console.log("qs sample:", qs.stringify({ a: 1 }));
console.log("args:", args);
