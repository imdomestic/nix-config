// Merge declared settings without removing JSONC comments or undeclared fields.
import { randomUUID } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, renameSync, rmSync, statSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname } from "node:path";

const [target, settingsJSON, parserPath] = process.argv.slice(2);
const { parse, stringify } = createRequire(import.meta.url)(parserPath);
const isObject = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
const settings = JSON.parse(settingsJSON);
const document = existsSync(target) ? parse(readFileSync(target, "utf8")) : {};
if (!isObject(document) || !isObject(settings)) throw new Error("Settings must be JSON objects");

function merge(document, settings) {
  for (const [key, value] of Object.entries(settings)) {
    if (isObject(value) && isObject(document[key])) merge(document[key], value);
    else document[key] = value;
  }
}

const before = stringify(document, null, 2);
merge(document, settings);
const after = stringify(document, null, 2);
if (before !== after) {
  mkdirSync(dirname(target), { recursive: true });
  const temporary = `${target}.${randomUUID()}.tmp`;
  const mode = existsSync(target) ? statSync(target).mode & 0o777 : 0o600;
  try {
    writeFileSync(temporary, `${after}\n`, { mode, flag: "wx" });
    renameSync(temporary, target);
  } finally {
    rmSync(temporary, { force: true });
  }
}
