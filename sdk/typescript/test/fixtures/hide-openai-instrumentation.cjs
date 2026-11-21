// Test preload: make one optional peer look uninstalled.
const Module = require("node:module");
const orig = Module._resolveFilename;
Module._resolveFilename = function (request, ...rest) {
  if (request === "@arizeai/openinference-instrumentation-openai") {
    const err = new Error(`Cannot find module '${request}'`);
    err.code = "MODULE_NOT_FOUND";
    throw err;
  }
  return orig.call(this, request, ...rest);
};
