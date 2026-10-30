#!/usr/bin/env node
// Validate RALPH.md task configs with the Ralph extension's OWN parser and
// validator, so an operator edit to a runner-protected RALPH.md cannot ship a
// config the loop would reject at startup (or, worse, silently mis-read).
//
// Usage: node scripts/campaign/validate-ralph-config.mjs [path/to/RALPH.md ...]
// Defaults to every tasks/*/RALPH.md in this repository.
import { existsSync, readFileSync } from "node:fs";
import { copyFileSync, mkdtempSync, rmSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { readdirSync, statSync } from "node:fs";

const here = dirname(fileURLToPath(import.meta.url));
const repo = resolve(here, "..", "..");
const srcDir = join(repo, ".pi", "npm", "node_modules", "@lnilluv", "pi-ralph-loop", "src");
const pkg = join(srcDir, "ralph.ts");
if (!existsSync(pkg)) {
  console.error(`validate-ralph-config: extension source not found at ${pkg}`);
  console.error("Install the project package first (npm install --prefix .pi/npm @lnilluv/pi-ralph-loop).");
  process.exit(2);
}

// Node refuses --experimental-strip-types for files under node_modules, so copy
// the *installed* sources (plus their one local import) into a scratch dir that
// still resolves the package's own `yaml` dependency by walking up to
// .pi/npm/node_modules. The copy is refreshed on every run; nothing is patched.
const stage = mkdtempSync(join(repo, ".pi", "npm", "fm-check-"));
for (const name of ["ralph.ts", "secret-paths.ts"]) {
  copyFileSync(join(srcDir, name), join(stage, name));
}
const { parseRalphMarkdown, validateFrontmatter, resolveCompletionGateMode } = await import(
  `file://${join(stage, "ralph.ts")}`
);

function defaultTargets() {
  const root = join(repo, "tasks");
  if (!existsSync(root)) return [];
  return readdirSync(root)
    .map((d) => join(root, d, "RALPH.md"))
    .filter((p) => existsSync(p) && statSync(p).isFile());
}

const targets = process.argv.slice(2).length ? process.argv.slice(2) : defaultTargets();
if (targets.length === 0) {
  console.error("validate-ralph-config: no RALPH.md targets found");
  process.exit(2);
}

let failures = 0;
try {
for (const target of targets) {
  const label = target.replace(`${repo}/`, "");
  let raw;
  try {
    raw = readFileSync(target, "utf8");
  } catch (error) {
    console.log(`FAIL ${label}: ${error.message}`);
    failures += 1;
    continue;
  }

  // The package's YAML parser rejects duplicate keys and out-of-range values;
  // validateFrontmatter adds the Ralph-specific rules on top of that.
  try {
    const { frontmatter, body } = parseRalphMarkdown(raw);
    const error = validateFrontmatter(frontmatter);
    if (error) throw new Error(error);
    if (!body.trim()) throw new Error("empty task body (workers receive no instructions)");
    const acceptance = (frontmatter.commands ?? []).filter((c) => c.acceptance);
    const gate = resolveCompletionGateMode(frontmatter);
    console.log(
      `OK   ${label}: ${frontmatter.maxIterations} iterations, ` +
        `${(frontmatter.commands ?? []).length} commands ` +
        `(${acceptance.length} acceptance), gate=${gate}, ` +
        `promise=${frontmatter.completionPromise ?? "none"}, ` +
        `outputs=${(frontmatter.requiredOutputs ?? []).join("|") || "none"}` +
        `${gate !== "disabled" ? ", OPEN_QUESTIONS P0/P1 enforced" : ""}`
    );
  } catch (error) {
    console.log(`FAIL ${label}: ${error.message}`);
    failures += 1;
  }
}
} finally {
  rmSync(stage, { recursive: true, force: true });
}

process.exit(failures === 0 ? 0 : 1);
