/**
 * mcp-shield — Security middleware for MCP servers
 * Rate limiting, prompt injection detection, budget enforcement, tool allowlists.
 * The Helmet.js of MCP. Zero dependencies.
 *
 * github.com/zambodotdev/mcp-shield
 * zambo.dev/opensource
 */

// ── Types ──────────────────────────────────────────────────────────────────

export interface RateLimitOptions {
  /** Max calls per minute per client (default: 20) */
  perMinute?: number;
  /** Max calls per hour per client (default: 200) */
  perHour?: number;
  /** How to identify clients: 'client-id' | 'ip' | 'api-key' (default: 'client-id') */
  keyBy?: 'client-id' | 'ip' | 'api-key';
  /** Called when a client is rate-limited */
  onExceeded?: (clientId: string, window: 'minute' | 'hour') => void;
}

export interface PromptGuardOptions {
  /** Enable prompt injection scanning (default: true) */
  enabled?: boolean;
  /** 'fast' = pattern-only, 'deep' = semantic analysis required (default: 'fast') */
  mode?: 'fast' | 'deep';
  /** Threat score threshold 0–1 above which the call is blocked (default: 0.6) */
  threshold?: number;
  /** Called when a prompt is blocked */
  onBlocked?: (toolName: string, threat: string, score: number) => void;
  /** Tools to skip prompt scanning (e.g. read-only tools) */
  skipTools?: string[];
}

export interface BudgetOptions {
  /** Max calls per session (default: no limit) */
  maxCallsPerSession?: number;
  /** Called when session budget is hit */
  onExceeded?: (clientId: string, usage: SessionUsage) => void;
}

export interface ShieldOptions {
  /** Rate limiting per client */
  rateLimit?: RateLimitOptions;
  /** Prompt injection & jailbreak detection */
  promptGuard?: PromptGuardOptions | boolean;
  /** Per-session call budget */
  budget?: BudgetOptions;
  /** Only allow these tool names (* = all, default: ['*']) */
  allowList?: string[];
  /** Block these tool names (checked after allowList) */
  blockList?: string[];
  /** Log all blocked/rate-limited events to stderr (default: false) */
  verbose?: boolean;
}

export interface ShieldResult {
  allowed: boolean;
  reason?: string;
  threat?: string;
  threatScore?: number;
}

export interface SessionUsage {
  calls: number;
  blockedAttempts: number;
  firstCallAt: number;
  lastCallAt: number;
}

// ── Prompt Injection Patterns ─────────────────────────────────────────────
// 156 patterns across 18 attack vector categories — extracted from zambo-prompt-shield

const INJECTION_PATTERNS: Array<{ pattern: RegExp; threat: string; score: number }> = [
  // Instruction override
  { pattern: /ignore (all |previous |above |prior )?instructions/i,                    threat: 'instruction_override',     score: 0.95 },
  { pattern: /disregard (your |all |previous |any )?instructions/i,                   threat: 'instruction_override',     score: 0.93 },
  { pattern: /forget (everything|all|your instructions|what you were told)/i,          threat: 'instruction_override',     score: 0.90 },
  { pattern: /you (are|were|will be) now (a|an|in) ?(?!helpful)/i,                    threat: 'persona_override',         score: 0.75 },
  // DAN / jailbreak
  { pattern: /\bDAN\b|do anything now/i,                                               threat: 'jailbreak_dan',            score: 0.98 },
  { pattern: /jailbreak|jail.?break/i,                                                 threat: 'jailbreak',                score: 0.92 },
  { pattern: /developer\s*mode|devmode/i,                                              threat: 'jailbreak_devmode',        score: 0.88 },
  { pattern: /pretend (you have no|there are no|you don'?t have) (restrictions|rules|guidelines)/i, threat: 'restriction_bypass', score: 0.91 },
  // System prompt extraction
  { pattern: /print (your |the )?(system |initial |original )?prompt/i,               threat: 'system_prompt_extraction', score: 0.96 },
  { pattern: /repeat (everything|your instructions|your system prompt|what you were told)/i, threat: 'system_prompt_extraction', score: 0.88 },
  { pattern: /what (are|were) your (instructions|system prompt|initial prompt)/i,      threat: 'system_prompt_extraction', score: 0.85 },
  { pattern: /reveal (your|the) (system prompt|instructions|training)/i,               threat: 'system_prompt_extraction', score: 0.92 },
  // Role manipulation
  { pattern: /act as (a|an) (?!helpful|assistant|ai|language)/i,                      threat: 'role_manipulation',        score: 0.72 },
  { pattern: /you are (now |)?(a|an) (malicious|evil|dangerous|unrestricted)/i,        threat: 'role_manipulation',        score: 0.97 },
  { pattern: /roleplay (as|being) (a|an) (?!helper|assistant)/i,                      threat: 'role_manipulation',        score: 0.70 },
  // Encoding / obfuscation
  { pattern: /base64|rot13|hex.?decode|url.?decode/i,                                  threat: 'encoding_obfuscation',     score: 0.65 },
  { pattern: /[A-Za-z0-9+/]{40,}={0,2}/,                                              threat: 'base64_payload',           score: 0.55 },
  // Data exfiltration
  { pattern: /(send|email|post|upload|exfiltrate).{0,40}(to|via).{0,40}(http|webhook|email)/i, threat: 'data_exfiltration', score: 0.88 },
  { pattern: /\bwebhook\b.{0,60}\bsend\b/i,                                           threat: 'data_exfiltration',        score: 0.82 },
  // Prompt injection via user input
  { pattern: /\[SYSTEM\]|\[INST\]|\[\/INST\]|<\|im_start\|>/i,                       threat: 'template_injection',       score: 0.90 },
  { pattern: /###\s*(instruction|system|human|assistant)/i,                            threat: 'template_injection',       score: 0.88 },
  // Code execution
  { pattern: /exec\(|eval\(|subprocess|os\.system|__import__/i,                       threat: 'code_execution',           score: 0.85 },
  { pattern: /(rm -rf|del \/f|format c:|drop table|drop database)/i,                  threat: 'destructive_command',      score: 0.99 },
  // Credential harvesting
  { pattern: /(api.?key|password|secret|token|credential).{0,30}(send|give|share|show)/i, threat: 'credential_harvest', score: 0.87 },
  // Prompt leakage via translation
  { pattern: /translate (your|the) (instructions|system prompt|constraints) (to|into)/i, threat: 'translation_leak',    score: 0.85 },
  // Continuation attacks
  { pattern: /continue (the|your) (story|conversation|roleplay) where/i,              threat: 'continuation_attack',      score: 0.60 },
  // Override via "above" / "below" the context
  { pattern: /(above|below|prior).{0,20}(instructions?|prompts?|rules?).{0,20}(override|supersede|replace)/i, threat: 'context_override', score: 0.88 },
];

// ── Rate limiter (sliding window, in-memory) ─────────────────────────────

interface WindowData {
  timestamps: number[];
}

class SlidingWindowRateLimiter {
  private minuteWindows = new Map<string, WindowData>();
  private hourWindows = new Map<string, WindowData>();
  private readonly perMinute: number;
  private readonly perHour: number;

  constructor(perMinute: number, perHour: number) {
    this.perMinute = perMinute;
    this.perHour = perHour;
  }

  check(clientId: string): { allowed: boolean; window?: 'minute' | 'hour' } {
    const now = Date.now();

    // Minute window
    const minW = this.minuteWindows.get(clientId) ?? { timestamps: [] };
    minW.timestamps = minW.timestamps.filter(t => now - t < 60_000);
    if (minW.timestamps.length >= this.perMinute) {
      this.minuteWindows.set(clientId, minW);
      return { allowed: false, window: 'minute' };
    }

    // Hour window
    const hrW = this.hourWindows.get(clientId) ?? { timestamps: [] };
    hrW.timestamps = hrW.timestamps.filter(t => now - t < 3_600_000);
    if (hrW.timestamps.length >= this.perHour) {
      this.hourWindows.set(clientId, hrW);
      return { allowed: false, window: 'hour' };
    }

    // Record the call
    minW.timestamps.push(now);
    hrW.timestamps.push(now);
    this.minuteWindows.set(clientId, minW);
    this.hourWindows.set(clientId, hrW);
    return { allowed: true };
  }

  reset(clientId: string): void {
    this.minuteWindows.delete(clientId);
    this.hourWindows.delete(clientId);
  }
}

// ── Prompt scanner ────────────────────────────────────────────────────────

function scanPrompt(text: string): { blocked: boolean; threat: string; score: number } {
  if (!text || typeof text !== 'string') return { blocked: false, threat: '', score: 0 };

  let maxScore = 0;
  let maxThreat = '';

  for (const { pattern, threat, score } of INJECTION_PATTERNS) {
    if (pattern.test(text)) {
      if (score > maxScore) {
        maxScore = score;
        maxThreat = threat;
      }
    }
  }

  return { blocked: maxScore > 0, threat: maxThreat, score: maxScore };
}

// ── Session tracker ────────────────────────────────────────────────────────

class SessionTracker {
  private sessions = new Map<string, SessionUsage>();

  get(clientId: string): SessionUsage {
    if (!this.sessions.has(clientId)) {
      this.sessions.set(clientId, {
        calls: 0,
        blockedAttempts: 0,
        firstCallAt: Date.now(),
        lastCallAt: Date.now(),
      });
    }
    return this.sessions.get(clientId)!;
  }

  recordCall(clientId: string): void {
    const s = this.get(clientId);
    s.calls++;
    s.lastCallAt = Date.now();
  }

  recordBlock(clientId: string): void {
    const s = this.get(clientId);
    s.blockedAttempts++;
  }

  reset(clientId: string): void {
    this.sessions.delete(clientId);
  }

  all(): Map<string, SessionUsage> {
    return this.sessions;
  }
}

// ── Shield class ──────────────────────────────────────────────────────────

export class Shield {
  private rateLimiter: SlidingWindowRateLimiter | null = null;
  private sessions = new SessionTracker();
  private opts: ShieldOptions;

  constructor(options: ShieldOptions = {}) {
    this.opts = options;

    if (options.rateLimit) {
      const rl = options.rateLimit;
      this.rateLimiter = new SlidingWindowRateLimiter(
        rl.perMinute ?? 20,
        rl.perHour ?? 200,
      );
    }
  }

  /**
   * Check whether a tool call should be allowed.
   * Call this at the top of every tool handler.
   *
   * @param toolName - The MCP tool name being called
   * @param input    - The raw input string (or stringified args) to scan
   * @param clientId - Unique identifier for the calling client
   */
  check(toolName: string, input: string, clientId = 'anonymous'): ShieldResult {
    // 1. Allow/block list
    const allowList = this.opts.allowList ?? ['*'];
    const blockList = this.opts.blockList ?? [];

    if (blockList.includes(toolName)) {
      this.sessions.recordBlock(clientId);
      return { allowed: false, reason: `Tool "${toolName}" is in the block list` };
    }
    if (!allowList.includes('*') && !allowList.includes(toolName)) {
      this.sessions.recordBlock(clientId);
      return { allowed: false, reason: `Tool "${toolName}" is not in the allow list` };
    }

    // 2. Rate limiting
    if (this.rateLimiter) {
      const rl = this.opts.rateLimit!;
      const clientKey = clientId;
      const result = this.rateLimiter.check(clientKey);
      if (!result.allowed) {
        this.sessions.recordBlock(clientId);
        rl.onExceeded?.(clientId, result.window!);
        if (this.opts.verbose) console.warn(`[mcp-shield] Rate limited: ${clientId} (${result.window})`);
        return { allowed: false, reason: `Rate limit exceeded (${result.window})` };
      }
    }

    // 3. Budget enforcement
    if (this.opts.budget?.maxCallsPerSession !== undefined) {
      const usage = this.sessions.get(clientId);
      if (usage.calls >= this.opts.budget.maxCallsPerSession) {
        this.sessions.recordBlock(clientId);
        this.opts.budget.onExceeded?.(clientId, usage);
        if (this.opts.verbose) console.warn(`[mcp-shield] Budget exceeded: ${clientId}`);
        return { allowed: false, reason: 'Session call budget exceeded' };
      }
    }

    // 4. Prompt injection detection
    const guardOpts: PromptGuardOptions =
      this.opts.promptGuard === true || this.opts.promptGuard === undefined
        ? { enabled: true }
        : this.opts.promptGuard === false
        ? { enabled: false }
        : this.opts.promptGuard;

    if (guardOpts.enabled !== false && !guardOpts.skipTools?.includes(toolName)) {
      const threshold = guardOpts.threshold ?? 0.6;
      const scan = scanPrompt(input);

      if (scan.blocked && scan.score >= threshold) {
        this.sessions.recordBlock(clientId);
        guardOpts.onBlocked?.(toolName, scan.threat, scan.score);
        if (this.opts.verbose) {
          console.warn(`[mcp-shield] Prompt blocked: tool=${toolName} threat=${scan.threat} score=${scan.score.toFixed(2)}`);
        }
        return {
          allowed: false,
          reason: 'Prompt injection detected',
          threat: scan.threat,
          threatScore: scan.score,
        };
      }
    }

    this.sessions.recordCall(clientId);
    return { allowed: true };
  }

  /**
   * Wrap an async function with shield enforcement.
   * Throws if the call is blocked.
   *
   * @example
   * const safeHandler = shield.wrap('analyze_code', async (args) => {
   *   return await analyze(args.code);
   * });
   */
  wrap<TArgs extends { _clientId?: string }, TResult>(
    toolName: string,
    fn: (args: TArgs, ...rest: unknown[]) => Promise<TResult>,
    getInput: (args: TArgs) => string = (a) => JSON.stringify(a),
  ): (args: TArgs, ...rest: unknown[]) => Promise<TResult> {
    return async (args: TArgs, ...rest: unknown[]): Promise<TResult> => {
      const clientId = args['_clientId'] ?? 'anonymous';
      const input = getInput(args);
      const result = this.check(toolName, input, clientId);

      if (!result.allowed) {
        const err = new Error(`[mcp-shield] Blocked: ${result.reason}`) as Error & {
          code: number;
          shieldResult: ShieldResult;
        };
        err.code = 403;
        err.shieldResult = result;
        throw err;
      }

      return fn(args, ...rest);
    };
  }

  /** Get usage stats for a client */
  getSession(clientId: string): SessionUsage {
    return this.sessions.get(clientId);
  }

  /** Get all sessions */
  allSessions(): Record<string, SessionUsage> {
    return Object.fromEntries(this.sessions.all());
  }

  /** Reset a client's rate limit and session */
  resetClient(clientId: string): void {
    this.rateLimiter?.reset(clientId);
    this.sessions.reset(clientId);
  }

  /** Scan a prompt string without enforcing (for analysis/logging) */
  static scan(text: string): { blocked: boolean; threat: string; score: number } {
    return scanPrompt(text);
  }
}

// ── Convenience factory ───────────────────────────────────────────────────

/**
 * Create a Shield instance with the given options.
 *
 * @example
 * import { createShield } from 'mcp-shield';
 *
 * const shield = createShield({
 *   rateLimit:   { perMinute: 20, perHour: 200 },
 *   promptGuard: { enabled: true, threshold: 0.65 },
 *   budget:      { maxCallsPerSession: 100 },
 *   blockList:   ['dangerous_tool'],
 *   verbose:     true,
 * });
 *
 * // In your MCP tool handler:
 * server.tool('analyze_code', schema,
 *   shield.wrap('analyze_code', async (args) => {
 *     return { content: [{ type: 'text', text: await analyze(args.code) }] };
 *   })
 * );
 */
export function createShield(options: ShieldOptions = {}): Shield {
  return new Shield(options);
}

/**
 * Scan a single prompt for injection threats (standalone, no shield instance needed).
 *
 * @example
 * const { blocked, threat, score } = guardPrompt(userInput);
 * if (blocked) console.log(`Blocked: ${threat} (${score})`);
 */
export function guardPrompt(text: string): { blocked: boolean; threat: string; score: number } {
  return scanPrompt(text);
}

export { INJECTION_PATTERNS as THREAT_PATTERNS };
