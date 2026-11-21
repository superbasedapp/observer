// Test preload: the openai instrumentation is not on the SDK's own path (as
// for a linked `npm install ./sdk/typescript` whose folder holds only the
// runtime dependencies), but the app has it. SBO_SDK_DIR is the SDK folder.
const Module = require("node:module");
const path = require("node:path");
const sdkDir = path.resolve(process.env.SBO_SDK_DIR);
const orig = Module._resolveFilename;
Module._resolveFilename = function (request, parent, ...rest) {
  const from = parent && parent.filename ? path.resolve(parent.filename) : "";
  if (request === "@arizeai/openinference-instrumentation-openai" && from.startsWith(sdkDir + path.sep)) {
    const err = new Error(`Cannot find module '${request}'`);
    err.code = "MODULE_NOT_FOUND";
    throw err;
  }
  return orig.call(this, request, parent, ...rest);
};
