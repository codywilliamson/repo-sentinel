import { buildIssueBody } from "./issues.mjs";

const ENCODED_AT_PATTERN = /&(?:#0*64|#x0*40|commat);/gi;
const MENTION_PATTERN = /@(?=[A-Za-z0-9])/g;
const URL_PREFIX_PATTERN = /(?:^|[\s(<])https?:\/\/\S*$/i;
const ZERO_WIDTH_SPACE = "\u200b";

function neutralizeMentions(value) {
  const text = value.replace(ENCODED_AT_PATTERN, "@");

  return text.replace(MENTION_PATTERN, (match, offset, source) => {
    const previousCharacter = source[offset - 1] || "";
    const isEmail = /[A-Za-z0-9_]/.test(previousCharacter);
    const isUrl = URL_PREFIX_PATTERN.test(source.slice(0, offset));

    return isEmail || isUrl ? match : `@${ZERO_WIDTH_SPACE}`;
  });
}

export function isGitHubIntegrationPermissionError(error) {
  const message = error?.message || "";

  return (
    message.includes("GitHub API 403") &&
    message.includes("Resource not accessible by integration")
  );
}

function getRepoParts(repoSlug) {
  const [owner, repo] = repoSlug.split("/");

  if (!owner || !repo) {
    throw new Error("GITHUB_REPOSITORY must be in owner/repo format");
  }

  return { owner, repo };
}

function createIssuePayload(finding, config, includeCopilotAssignee) {
  const payload = {
    title: neutralizeMentions(finding.title),
    body: neutralizeMentions(
      buildIssueBody(finding, {
        assignCopilot: includeCopilotAssignee,
      })
    ),
    labels: [config.label],
  };

  if (includeCopilotAssignee) {
    payload.assignees = ["copilot"];
  }

  return payload;
}

export function createGitHubClient(config, deps = {}) {
  if (!config.token) {
    throw new Error("GITHUB_TOKEN is required");
  }

  if (!config.repo) {
    throw new Error("GITHUB_REPOSITORY is required");
  }

  const { owner, repo } = getRepoParts(config.repo);
  const encodedLabel = encodeURIComponent(config.label);
  const fetchImpl = deps.fetch || fetch;

  async function ghApi(path, options = {}) {
    const url = path.startsWith("https")
      ? path
      : `https://api.github.com${path}`;
    const response = await fetchImpl(url, {
      ...options,
      headers: {
        Authorization: `token ${config.token}`,
        Accept: "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        ...options.headers,
      },
    });

    if (!response.ok) {
      const body = await response.text();
      throw new Error(`GitHub API ${response.status}: ${body}`);
    }

    return response.status === 204 ? null : response.json();
  }

  async function listPaginated(pathForPage) {
    const items = [];
    let page = 1;

    while (true) {
      const batch = await ghApi(pathForPage(page));
      items.push(...batch);

      if (batch.length < 100) {
        break;
      }

      page += 1;
    }

    return items;
  }

  async function createIssueFromPayload(payload) {
    return ghApi(`/repos/${owner}/${repo}/issues`, {
      method: "POST",
      body: JSON.stringify(payload),
    });
  }

  return {
    async ensureLabel() {
      try {
        await ghApi(`/repos/${owner}/${repo}/labels/${encodedLabel}`);
      } catch {
        await ghApi(`/repos/${owner}/${repo}/labels`, {
          method: "POST",
          body: JSON.stringify({
            name: config.label,
            color: "d73a4a",
            description: "Security vulnerability finding",
          }),
        });
      }
    },
    async getExistingIssues() {
      return listPaginated(
        (page) =>
          `/repos/${owner}/${repo}/issues?labels=${encodedLabel}&state=open&per_page=100&page=${page}`
      );
    },
    async createIssue(finding) {
      const payload = createIssuePayload(
        finding,
        config,
        config.assignCopilot
      );

      if (!config.assignCopilot) {
        return createIssueFromPayload(payload);
      }

      try {
        return await createIssueFromPayload(payload);
      } catch (error) {
        if (error.message.includes("422")) {
          return createIssueFromPayload(
            createIssuePayload(finding, config, false)
          );
        }

        throw error;
      }
    },
    async listPullRequestComments(pullRequestNumber) {
      return listPaginated(
        (page) =>
          `/repos/${owner}/${repo}/issues/${pullRequestNumber}/comments?per_page=100&page=${page}`
      );
    },
    async createPullRequestComment(pullRequestNumber, body) {
      return ghApi(`/repos/${owner}/${repo}/issues/${pullRequestNumber}/comments`, {
        method: "POST",
        body: JSON.stringify({ body }),
      });
    },
    async updatePullRequestComment(commentId, body) {
      return ghApi(`/repos/${owner}/${repo}/issues/comments/${commentId}`, {
        method: "PATCH",
        body: JSON.stringify({ body }),
      });
    },
  };
}
