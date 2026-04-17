import { pathToFileURL } from "node:url";

import { getConfig, processFindings } from "./process-findings-lib.mjs";

function isDirectRun() {
  return Boolean(process.argv[1]) && import.meta.url === pathToFileURL(process.argv[1]).href;
}

if (isDirectRun()) {
  processFindings(getConfig()).catch((error) => {
    console.error("repo-sentinel: fatal error", error);
    process.exit(1);
  });
}
