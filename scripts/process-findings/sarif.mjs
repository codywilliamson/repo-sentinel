import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";

export const SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"];

const SARIF_LEVEL_MAP = {
  error: "HIGH",
  warning: "MEDIUM",
  note: "LOW",
  none: "UNKNOWN",
};

function thresholdToIndex(threshold) {
  const index = SEVERITY_ORDER.indexOf(threshold);
  return index === -1 ? SEVERITY_ORDER.indexOf("MEDIUM") : index;
}

export function findSarifFiles(dir) {
  const files = [];

  try {
    const entries = readdirSync(dir);
    for (const entry of entries) {
      const full = join(dir, entry);
      const stat = statSync(full);
      if (stat.isDirectory()) {
        files.push(...findSarifFiles(full));
      } else if (entry.endsWith(".sarif")) {
        files.push(full);
      }
    }
  } catch {
    // The directory may not exist if a scan was skipped.
  }

  return files;
}

export function parseSarif(filePath, threshold = "MEDIUM") {
  const raw = JSON.parse(readFileSync(filePath, "utf-8"));
  const findings = [];
  const thresholdIndex = thresholdToIndex(threshold);

  for (const run of raw.runs || []) {
    const toolName = run.tool?.driver?.name || "unknown";
    const rules = new Map();

    for (const rule of run.tool?.driver?.rules || []) {
      rules.set(rule.id, rule);
    }

    for (const result of run.results || []) {
      const rule = rules.get(result.ruleId) || {};
      const severity = resolveSeverity(result, rule);
      const severityIndex = SEVERITY_ORDER.indexOf(severity);

      if (severityIndex > thresholdIndex) {
        continue;
      }

      const location = result.locations?.[0]?.physicalLocation;
      const fileLoc = location?.artifactLocation?.uri || "unknown";
      const line = location?.region?.startLine || 0;

      const finding = {
        id: result.ruleId || "unknown",
        tool: toolName,
        severity,
        message:
          result.message?.text || rule.shortDescription?.text || "No details",
        file: fileLoc,
        line,
        helpUri: rule.helpUri || "",
        help: rule.help?.text || rule.fullDescription?.text || "",
      };

      finding.title = `[${severity}] ${finding.id}: ${truncate(finding.message, 80)}`;
      finding.dedupKey = `${finding.id}::${finding.file}`;

      findings.push(finding);
    }
  }

  return findings;
}

export function resolveSeverity(result, rule) {
  const secSeverity =
    rule.properties?.["security-severity"] ||
    result.properties?.["security-severity"];

  if (secSeverity) {
    const score = Number.parseFloat(secSeverity);
    if (score >= 9.0) return "CRITICAL";
    if (score >= 7.0) return "HIGH";
    if (score >= 4.0) return "MEDIUM";
    if (score >= 0.1) return "LOW";
    return "UNKNOWN";
  }

  const level = result.level || "warning";
  return SARIF_LEVEL_MAP[level] || "MEDIUM";
}

export function truncate(value, max) {
  if (value.length <= max) {
    return value;
  }

  return `${value.slice(0, max - 3)}...`;
}

export function dedupeFindings(findings) {
  const unique = new Map();

  for (const finding of findings) {
    if (!unique.has(finding.dedupKey)) {
      unique.set(finding.dedupKey, finding);
    }
  }

  return [...unique.values()];
}
