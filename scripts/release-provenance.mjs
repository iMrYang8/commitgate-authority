#!/usr/bin/env node
import { writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  createReleaseProvenanceManifest,
  RELEASE_PROVENANCE_FILE,
} from "./evidence-utils.mjs";

const root = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const manifest = await createReleaseProvenanceManifest(root);
const destination = path.join(root, RELEASE_PROVENANCE_FILE);
await writeFile(destination, JSON.stringify(manifest, null, 2) + "\n", { mode: 0o644 });
console.log(`release provenance: ${destination}`);
console.log(`source revision: ${manifest.sourceRevision}`);
console.log(`source tree: ${manifest.sourceTreeHash} (${manifest.sourceFileCount} files)`);
