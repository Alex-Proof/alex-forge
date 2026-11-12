/**
 * Static validation for standalone HTML repair artifacts (blueprint section 13, Phase 7). This
 * only checks the artifact's own text; it does not run a browser -- the real functional and
 * DOM-XSS/CSP-enforcement checks belong in a test that actually loads the page (see
 * src/modes/repair/html-fixture.test.ts), because a string-pattern check alone cannot prove a
 * browser will actually refuse to execute something.
 */

export interface HtmlValidationFinding {
  ruleId: string;
  message: string;
}

export interface HtmlValidationResult {
  valid: boolean;
  findings: HtmlValidationFinding[];
}

const FORBIDDEN_EXTERNAL_REFERENCE_PATTERNS: Array<{ ruleId: string; pattern: RegExp; message: string }> = [
  {
    ruleId: "html-external-script",
    pattern: /<script[^>]+\bsrc\s*=/i,
    message: "external <script src> is not allowed; the artifact must be fully self-contained",
  },
  {
    ruleId: "html-external-link",
    pattern: /<link[^>]+\bhref\s*=/i,
    message: "external <link href> is not allowed; the artifact must be fully self-contained",
  },
  {
    ruleId: "html-remote-url",
    pattern: /\b(?:src|href)\s*=\s*["']https?:\/\//i,
    message: "a remote http(s) URL was found; the artifact must work fully offline",
  },
  {
    ruleId: "html-network-api",
    pattern: /\b(fetch\s*\(|new\s+XMLHttpRequest\s*\(|new\s+WebSocket\s*\(|new\s+EventSource\s*\()/,
    message: "a network API (fetch/XMLHttpRequest/WebSocket/EventSource) was found; the artifact must stay offline",
  },
  {
    ruleId: "html-dynamic-import",
    pattern: /\bimport\s*\(/,
    message: "dynamic import() was found, which can load external code",
  },
  {
    ruleId: "html-javascript-uri",
    pattern: /\b(?:href|src)\s*=\s*["']javascript:/i,
    message: "a javascript: URI was found",
  },
  {
    ruleId: "html-inline-event-handler",
    pattern: /\son[a-z]+\s*=\s*["']/i,
    message: "an inline event handler attribute (onclick=, onerror=, ...) was found; use addEventListener instead",
  },
  {
    ruleId: "html-eval",
    pattern: /\beval\s*\(|new\s+Function\s*\(/,
    message: "eval() or new Function() was found",
  },
  {
    ruleId: "html-inner-html-assignment",
    pattern: /\.innerHTML\s*=/,
    message: "an innerHTML assignment was found; use textContent so untrusted strings can never become markup",
  },
  {
    ruleId: "html-document-write",
    pattern: /\bdocument\.write\s*\(/,
    message: "document.write() was found",
  },
];

const UNSAFE_CSP_TOKENS = ["'unsafe-inline'", "'unsafe-eval'", "*", "data:", "http:", "https:"];

function extractCsp(html: string): string | null {
  // The content attribute is delimited by a quote character that itself appears inside a CSP
  // value (e.g. 'none'), so the capture must stop at a matching closing quote of the SAME kind
  // that opened it, not at the first quote of either kind.
  const match = /<meta\s+http-equiv=["']Content-Security-Policy["']\s+content=(["'])((?:(?!\1).)*)\1/i.exec(html);
  return match?.[2] ?? null;
}

export function validateHtmlArtifact(html: string): HtmlValidationResult {
  const findings: HtmlValidationFinding[] = [];

  for (const check of FORBIDDEN_EXTERNAL_REFERENCE_PATTERNS) {
    if (check.pattern.test(html)) {
      findings.push({ ruleId: check.ruleId, message: check.message });
    }
  }

  const csp = extractCsp(html);
  if (!csp) {
    findings.push({ ruleId: "html-missing-csp", message: "no Content-Security-Policy meta tag was found" });
  } else {
    for (const token of UNSAFE_CSP_TOKENS) {
      if (csp.includes(token)) {
        findings.push({
          ruleId: "html-unsafe-csp-token",
          message: `CSP contains the unsafe/overly broad token "${token}"`,
        });
      }
    }
    if (!/default-src\s+'none'/.test(csp)) {
      findings.push({ ruleId: "html-csp-not-default-deny", message: "CSP does not set default-src 'none'" });
    }
  }

  return { valid: findings.length === 0, findings };
}
