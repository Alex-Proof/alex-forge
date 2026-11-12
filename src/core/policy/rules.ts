/** Pattern catalog for the policy engine. Kept data-only so rule changes are reviewable as a diff. */

export type RuleSeverity = "info" | "warning" | "block";

export interface SecretPattern {
  ruleId: string;
  message: string;
  severity: RuleSeverity;
  pattern: RegExp;
}

// Patterns with severity "block" indicate a known credential format with no legitimate reason to
// appear in an error log or diagnostic input. Patterns with "warning" are generic key=value style
// matches that can false-positive on documentation text, so they are redacted but not blocked.
export const SECRET_PATTERNS: SecretPattern[] = [
  {
    ruleId: "secret-pem-private-key",
    message: "PEM private key block detected",
    severity: "block",
    pattern:
      /-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----/g,
  },
  {
    ruleId: "secret-aws-access-key-id",
    message: "AWS access key ID detected",
    severity: "block",
    pattern: /\bAKIA[0-9A-Z]{16}\b/g,
  },
  {
    ruleId: "secret-aws-secret-access-key",
    message: "AWS secret access key assignment detected",
    severity: "block",
    pattern: /\baws_secret_access_key\s*=\s*['"]?[A-Za-z0-9/+]{40}['"]?/gi,
  },
  {
    ruleId: "secret-github-token",
    message: "GitHub access token detected",
    severity: "block",
    pattern: /\bgh[pousr]_[A-Za-z0-9]{30,}\b/g,
  },
  {
    ruleId: "secret-slack-token",
    message: "Slack token detected",
    severity: "block",
    pattern: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g,
  },
  {
    ruleId: "secret-bearer-token",
    message: "Bearer authorization token detected",
    severity: "block",
    pattern: /\bBearer\s+[A-Za-z0-9\-_.]{16,}\b/g,
  },
  {
    ruleId: "secret-generic-assignment",
    message: "Generic credential-like assignment detected",
    severity: "warning",
    pattern:
      /\b(?:api[_-]?key|apikey|secret|token|password|passwd|pwd|client[_-]?secret)\s*[:=]\s*['"]?[A-Za-z0-9_\-/+.=]{8,}['"]?/gi,
  },
];

// File-path fragments with no legitimate reason to be read or written by Forge. Matched against a
// forward-slash-normalized path, case-insensitively.
export interface PathRule {
  ruleId: string;
  message: string;
  severity: RuleSeverity;
  pattern: RegExp;
}

export const FORBIDDEN_PATH_RULES: PathRule[] = [
  {
    ruleId: "forbidden-path-dotenv",
    message: ".env file detected",
    severity: "block",
    pattern: /(^|\/)\.env(\.[^/]*)?$/i,
  },
  {
    ruleId: "forbidden-path-ssh-dir",
    message: "SSH credential directory detected",
    severity: "block",
    pattern: /(^|\/)\.ssh(\/|$)/i,
  },
  {
    ruleId: "forbidden-path-private-key-file",
    message: "Private key file detected",
    severity: "block",
    pattern: /(^|\/)id_(rsa|dsa|ecdsa|ed25519)$/i,
  },
  {
    ruleId: "forbidden-path-key-extension",
    message: "Private key / certificate bundle file extension detected",
    severity: "block",
    pattern: /\.(pem|pfx|p12|key)$/i,
  },
  {
    ruleId: "forbidden-path-aws-credentials",
    message: "AWS credential store detected",
    severity: "block",
    pattern: /(^|\/)\.aws\/credentials$/i,
  },
  {
    ruleId: "forbidden-path-kube-config",
    message: "Kubernetes credential store detected",
    severity: "block",
    pattern: /(^|\/)\.kube\/config$/i,
  },
  {
    ruleId: "forbidden-path-docker-config",
    message: "Docker credential store detected",
    severity: "block",
    pattern: /(^|\/)\.docker\/config\.json$/i,
  },
  {
    ruleId: "forbidden-path-gcloud-config",
    message: "gcloud credential store detected",
    severity: "block",
    pattern: /(^|\/)\.config\/gcloud(\/|$)/i,
  },
];

export interface InjectionPattern {
  ruleId: string;
  message: string;
  severity: RuleSeverity;
  pattern: RegExp;
}

// Logs and source files are treated as data, never as instructions. These patterns flag text that
// tries to redirect the model or hide content from a human reviewer.
export const INJECTION_PATTERNS: InjectionPattern[] = [
  {
    ruleId: "injection-ignore-previous-instructions",
    message: "Instruction-override phrase detected (ignore/disregard previous instructions)",
    severity: "block",
    pattern: /\b(ignore|disregard)\b[^.\n]{0,40}\b(previous|prior|above|earlier)\b[^.\n]{0,20}\binstructions?\b/i,
  },
  {
    ruleId: "injection-new-instructions",
    message: "New-instructions injection phrase detected",
    severity: "block",
    pattern: /\bnew\s+instructions?\s*:/i,
  },
  {
    ruleId: "injection-override-rules",
    message: "Attempt to override safety rules or policy detected",
    severity: "block",
    pattern: /\boverride\b[^.\n]{0,20}\b(your|the)\b[^.\n]{0,20}\b(instructions|rules|policy|safety)\b/i,
  },
  {
    ruleId: "injection-role-override",
    message: "Attempt to reassign the model's role detected",
    severity: "block",
    pattern: /\byou are now\b[^.\n]{0,40}\b(system|root|admin|developer mode)\b/i,
  },
  {
    ruleId: "injection-hidden-unicode",
    message: "Hidden/zero-width or bidi-override Unicode characters detected",
    severity: "block",
    pattern: /[​-‏‪-‮⁦-⁩﻿]/,
  },
  {
    ruleId: "injection-possible-encoded-payload",
    message: "Long base64-like blob detected (possible encoded payload)",
    severity: "warning",
    pattern: /(?:[A-Za-z0-9+/]{4}){20,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?/,
  },
];

export interface CommandRule {
  ruleId: string;
  message: string;
  severity: RuleSeverity;
  matches: (executableBaseName: string, args: string[]) => boolean;
}

function hasFlag(args: string[], short: RegExp, long: string): boolean {
  return args.some((arg) => short.test(arg) || arg === long);
}

export const COMMAND_RULES: CommandRule[] = [
  {
    ruleId: "destructive-rm-rf",
    message: "Recursive, forced delete detected (rm -rf style)",
    severity: "block",
    matches: (base, args) =>
      base === "rm" &&
      hasFlag(args, /^-[a-zA-Z]*r[a-zA-Z]*$/, "--recursive") &&
      hasFlag(args, /^-[a-zA-Z]*f[a-zA-Z]*$/, "--force"),
  },
  {
    ruleId: "destructive-dd",
    message: "Raw block-device copy tool (dd) detected",
    severity: "block",
    matches: (base) => base === "dd",
  },
  {
    ruleId: "destructive-mkfs",
    message: "Filesystem formatting tool detected",
    severity: "block",
    matches: (base) => /^mkfs(\.\w+)?$/.test(base),
  },
  {
    ruleId: "destructive-fork-bomb",
    message: "Fork-bomb pattern detected",
    severity: "block",
    matches: (base, args) => [base, ...args].some((part) => part.includes(":(){") || part.includes(":|:&")),
  },
  {
    ruleId: "system-power-action",
    message: "System power-state command detected",
    severity: "block",
    matches: (base) => ["shutdown", "reboot", "halt", "poweroff"].includes(base),
  },
  {
    ruleId: "account-privilege-command",
    message: "User/account privilege command detected",
    severity: "block",
    matches: (base) =>
      ["useradd", "userdel", "usermod", "adduser", "deluser", "passwd", "visudo", "chpasswd"].includes(base),
  },
  {
    ruleId: "network-privilege-command",
    message: "Firewall/network privilege command detected",
    severity: "block",
    matches: (base) => ["iptables", "ip6tables", "nft", "ufw", "firewall-cmd", "netsh"].includes(base),
  },
  {
    ruleId: "boot-config-command",
    message: "Boot configuration command detected",
    severity: "block",
    matches: (base) => ["grub-install", "grub-mkconfig", "bootctl", "bcdedit"].includes(base),
  },
  {
    ruleId: "security-software-command",
    message: "Security software disable command detected",
    severity: "block",
    matches: (base, args) =>
      base === "setenforce" ||
      (base === "apparmor_parser" && (args.includes("-R") || args.includes("--remove"))),
  },
  {
    ruleId: "download-and-execute",
    message: "Shell invocation combining a download tool with pipe-to-interpreter execution detected",
    severity: "block",
    matches: (base, args) => {
      if (!["sh", "bash", "zsh", "powershell", "pwsh", "cmd", "cmd.exe"].includes(base)) {
        return false;
      }
      const joined = args.join(" ").toLowerCase();
      const hasDownloader = /\b(curl|wget|invoke-webrequest|iwr)\b/.test(joined);
      const hasPipeToInterpreter = /\|\s*(sh|bash|zsh|powershell|pwsh)\b/.test(joined);
      return hasDownloader && hasPipeToInterpreter;
    },
  },
  {
    ruleId: "network-download-tool",
    message: "Network download tool invoked (network is disabled by default)",
    severity: "warning",
    matches: (base) => ["curl", "wget"].includes(base),
  },
];
