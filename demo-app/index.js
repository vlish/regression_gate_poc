// Demo app only — dependencies are pinned to known-vulnerable versions for SCA testing.
const _ = require("lodash");
const minimist = require("minimist");

const args = minimist(process.argv.slice(2));
console.log("regression-gate-demo-app");
console.log("lodash sample:", _.join(["hello", "world"], " "));
console.log("args:", args);
