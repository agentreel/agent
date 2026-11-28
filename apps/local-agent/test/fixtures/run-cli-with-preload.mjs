// Test launcher: import a preload module, then run the built CLI in the same
// process. Replaces `node --import <preload> dist/cli.js`, which the runtime
// self-check now (correctly) denies: a preload flag in execArgv is the same
// thing NODE_OPTIONS=--import is.
//
// usage: node run-cli-with-preload.mjs <preload.mjs> <dist/cli.js> [cli args...]
import { pathToFileURL } from "node:url";
import { resolve } from "node:path";

const [preload, cli, ...args] = process.argv.slice(2);
await import(pathToFileURL(resolve(preload)).href);
process.argv = [process.argv[0], resolve(cli), ...args];
await import(pathToFileURL(resolve(cli)).href);
