/**
 * Runner-speed calibration for wall-clock assertions in the unit suite.
 *
 * Timing bounds such as "under 5ms" are written for an unloaded machine. On a
 * shared CI runner or a busy dev box the same code can run several times
 * slower, which made those assertions flaky (issue #26). This helper measures a
 * fixed baseline workload on the current runner, compares it with a reference
 * cost, and scales the base bound by that factor, clamped to [1, 4]. A real
 * regression (for example a matcher going quadratic on 32KB input) costs far
 * more than 4x and still fails.
 *
 * Manual override: AGENTREEL_PERF_MULTIPLIER=<number>. It must be a finite
 * number and is clamped to [1, 10]. Anything else throws, so a typo can't
 * silently disable the bounds.
 */

/** Baseline cost in ms of `runBaselineWorkload()` on an unloaded machine (median of samples). */
export const REFERENCE_BASELINE_MS = 0.9;
export const MIN_FACTOR = 1;
export const MAX_FACTOR = 4;
export const MAX_ENV_MULTIPLIER = 10;
export const PERF_MULTIPLIER_ENV = "AGENTREEL_PERF_MULTIPLIER";

export interface PerfFactor {
  factor: number;
  source: "calibrated" | "env";
  baselineMs: number | null;
}

// Linear-time native regex scans over 32KB strings: the same kind of work the
// bounded tests time, but with no code from src/, so a regression under test
// can't inflate its own bound.
const BASELINE_INPUTS = ["a".repeat(32_768), " ".repeat(32_768), "x\n".repeat(16_384)];
const BASELINE_PATTERNS = [/curl\s+\|\s*sh/, /(DROP|TRUNCATE)\s+TABLE\s+\w+/, /rm\s+-rf\s+\//];

let sink = 0;

const BASELINE_ROUNDS = 10;

export function runBaselineWorkload(): void {
  for (let round = 0; round < BASELINE_ROUNDS; round++) {
    for (const re of BASELINE_PATTERNS) {
      for (const input of BASELINE_INPUTS) {
        if (re.test(input)) sink++;
      }
    }
  }
}

function median(values: number[]): number {
  const s = [...values].sort((a, b) => a - b);
  return s[Math.floor(s.length / 2)]!;
}

/** Median wall time in ms of the baseline workload on this runner, right now. */
export function measureBaselineMs(samples = 9): number {
  runBaselineWorkload(); // warm up JIT and regex compilation
  const times: number[] = [];
  for (let i = 0; i < samples; i++) {
    const t0 = performance.now();
    runBaselineWorkload();
    times.push(performance.now() - t0);
  }
  if (sink < 0) throw new Error("unreachable");
  return median(times);
}

export function clamp(value: number, lo: number, hi: number): number {
  return Math.min(hi, Math.max(lo, value));
}

/** Parses AGENTREEL_PERF_MULTIPLIER. Returns null when unset or empty; throws when invalid. */
export function parseEnvMultiplier(raw: string | undefined): number | null {
  if (raw === undefined || raw.trim() === "") return null;
  const n = Number(raw.trim());
  if (!Number.isFinite(n) || n <= 0) {
    throw new Error(
      `${PERF_MULTIPLIER_ENV} must be a positive finite number, got ${JSON.stringify(raw)}`,
    );
  }
  return clamp(n, MIN_FACTOR, MAX_ENV_MULTIPLIER);
}

/** Runner-speed factor: the env override if set, otherwise measured now and clamped to [1, 4]. */
export function perfFactor(env: NodeJS.ProcessEnv = process.env): PerfFactor {
  const fromEnv = parseEnvMultiplier(env[PERF_MULTIPLIER_ENV]);
  if (fromEnv !== null) return { factor: fromEnv, source: "env", baselineMs: null };
  const baselineMs = measureBaselineMs();
  return {
    factor: clamp(baselineMs / REFERENCE_BASELINE_MS, MIN_FACTOR, MAX_FACTOR),
    source: "calibrated",
    baselineMs,
  };
}

/** Base bound scaled by the runner factor. */
export function scaledBound(baseMs: number, pf: PerfFactor): number {
  return baseMs * pf.factor;
}

/** Message printed when a timing assertion fails. */
export function describeBound(
  what: string,
  measuredMs: number,
  baseMs: number,
  pf: PerfFactor,
): string {
  const baseline =
    pf.baselineMs === null ? `${PERF_MULTIPLIER_ENV}` : `baseline ${pf.baselineMs.toFixed(2)}ms vs reference ${REFERENCE_BASELINE_MS}ms`;
  return (
    `${what}: measured ${measuredMs.toFixed(2)}ms, effective bound ${scaledBound(baseMs, pf).toFixed(2)}ms ` +
    `(base ${baseMs}ms x factor ${pf.factor.toFixed(2)}, ${pf.source}: ${baseline})`
  );
}
