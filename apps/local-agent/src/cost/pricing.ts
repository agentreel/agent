// Anthropic published rates. Cents per million tokens.
//
// Update this table whenever Anthropic publishes new rates or releases
// a new model family. Rates are intentionally hardcoded here (vs a
// server fetch) so the agent works fully offline.

export interface ModelRates {
  /** Cents per million input tokens. */
  input: number;
  /** Cents per million output tokens. */
  output: number;
  /** Cents per million cache-read input tokens. */
  cacheRead: number;
  /** Cents per million cache-creation input tokens. */
  cacheCreation: number;
}

export const MODEL_RATES: Record<string, ModelRates> = {
  // Claude 4.x
  "claude-opus-4-7":    { input: 1500, output: 7500, cacheRead: 150, cacheCreation: 1875 },
  "claude-opus-4-6":    { input: 1500, output: 7500, cacheRead: 150, cacheCreation: 1875 },
  "claude-sonnet-4-6":  { input:  300, output: 1500, cacheRead:  30, cacheCreation:  375 },
  "claude-sonnet-4-5":  { input:  300, output: 1500, cacheRead:  30, cacheCreation:  375 },
  "claude-haiku-4-5":   { input:   80, output:  400, cacheRead:   8, cacheCreation:  100 },

  // Legacy 3.x (still seen in older transcripts)
  "claude-3-5-sonnet":  { input:  300, output: 1500, cacheRead:  30, cacheCreation:  375 },
  "claude-3-5-haiku":   { input:   80, output:  400, cacheRead:   8, cacheCreation:  100 },
  "claude-3-opus":      { input: 1500, output: 7500, cacheRead: 150, cacheCreation: 1875 },
};

const FALLBACK: ModelRates = MODEL_RATES["claude-sonnet-4-6"]!;

/**
 * Look up rates for a model id like `claude-sonnet-4-5-20250929`. We
 * match by prefix so date-stamped variants don't drop out of the table.
 */
export function ratesFor(model: string | undefined): ModelRates {
  if (!model) return FALLBACK;
  // Try exact, then strip a trailing date suffix.
  if (MODEL_RATES[model]) return MODEL_RATES[model];
  const stripped = model.replace(/-\d{8}$/, "");
  if (MODEL_RATES[stripped]) return MODEL_RATES[stripped];
  // Try ever-shorter prefixes — handles unknown date suffixes.
  for (const key of Object.keys(MODEL_RATES)) {
    if (model.startsWith(key)) return MODEL_RATES[key]!;
  }
  return FALLBACK;
}

export interface UsageBreakdown {
  inputTokens: number;
  outputTokens: number;
  cacheReadTokens: number;
  cacheCreationTokens: number;
}

/** Cost in cents. Rounded UP so we never under-report. */
export function costCentsFor(usage: UsageBreakdown, rates: ModelRates): number {
  const c =
    (usage.inputTokens * rates.input +
      usage.outputTokens * rates.output +
      usage.cacheReadTokens * rates.cacheRead +
      usage.cacheCreationTokens * rates.cacheCreation) /
    1_000_000;
  return Math.ceil(c);
}
