import { SEVERITY_ORDER } from "./sarif.mjs";

const PACKAGE_PATTERN = /^Package: (.+)$/m;
const INSTALLED_PATTERN = /^Installed Version: (.+)$/m;
const FIXED_PATTERN = /^Fixed Version: (.+)$/m;

function bySeverityThenId(a, b) {
  return SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity) || a.id.localeCompare(b.id);
}

function parsePackage(finding) {
  if (finding.tool !== "Trivy") return null;
  const name = finding.message.match(PACKAGE_PATTERN)?.[1].trim();
  const version = finding.message.match(INSTALLED_PATTERN)?.[1].trim();
  return name && version ? { name, version } : null;
}

function buildGroup({ name, version }, members) {
  const vulnerabilities = members.map((finding) => ({
    id: finding.id,
    severity: finding.severity,
    fixedVersion: finding.message.match(FIXED_PATTERN)?.[1].trim() || "",
    helpUri: finding.helpUri,
  })).sort(bySeverityThenId);
  const [top] = vulnerabilities;
  const noun = vulnerabilities.length === 1 ? "vulnerability" : "vulnerabilities";

  return {
    id: `${name}@${version}`,
    tool: "Trivy",
    severity: top.severity,
    file: members[0].file,
    line: members[0].line,
    title: `[${top.severity}] ${name} ${version}: ${vulnerabilities.length} ${noun}`,
    message: `Package: ${name}\nInstalled Version: ${version}`,
    help: "",
    helpUri: "",
    vulnerabilities,
  };
}

// one issue per package+installed version+lockfile instead of one per cve
export function groupDependencyFindings(findings) {
  const groups = new Map();
  const result = [];

  for (const finding of findings) {
    const pkg = parsePackage(finding);
    if (!pkg) {
      result.push(finding);
      continue;
    }

    const key = `${pkg.name}@${pkg.version}::${finding.file}`;
    if (!groups.has(key)) groups.set(key, { pkg, members: [] });
    groups.get(key).members.push(finding);
  }

  for (const { pkg, members } of groups.values()) {
    result.push(buildGroup(pkg, members));
  }

  return result;
}
