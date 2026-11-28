import { describe, expect, it } from "vitest";
import {
  describeBound,
  MAX_ENV_MULTIPLIER,
  MAX_FACTOR,
  MIN_FACTOR,
  parseEnvMultiplier,
  perfFactor,
  PERF_MULTIPLIER_ENV,
  scaledBound,
} from "./perf-calibration.js";

describe("perf calibration helper", () => {
  it("measures a calibrated factor clamped to [1, 4] when the env override is unset", () => {
    const pf = perfFactor({});
    expect(pf.source).toBe("calibrated");
    expect(pf.baselineMs).toBeGreaterThan(0);
    expect(pf.factor).toBeGreaterThanOrEqual(MIN_FACTOR);
    expect(pf.factor).toBeLessThanOrEqual(MAX_FACTOR);
  });

  it("uses a valid AGENTREEL_PERF_MULTIPLIER, clamped to [1, 10]", () => {
    expect(perfFactor({ [PERF_MULTIPLIER_ENV]: "2.5" })).toEqual({
      factor: 2.5,
      source: "env",
      baselineMs: null,
    });
    expect(parseEnvMultiplier("0.2")).toBe(MIN_FACTOR);
    expect(parseEnvMultiplier("500")).toBe(MAX_ENV_MULTIPLIER);
    expect(parseEnvMultiplier(undefined)).toBeNull();
    expect(parseEnvMultiplier("  ")).toBeNull();
  });

  it("rejects an invalid AGENTREEL_PERF_MULTIPLIER instead of silently ignoring it", () => {
    for (const bad of ["abc", "0", "-1", "Infinity", "NaN", "2x"]) {
      expect(() => parseEnvMultiplier(bad), bad).toThrow(PERF_MULTIPLIER_ENV);
    }
  });

  it("reports the effective bound, factor and measured value on failure", () => {
    const pf = { factor: 2, source: "calibrated" as const, baselineMs: 1.8 };
    expect(scaledBound(5, pf)).toBe(10);
    const msg = describeBound("too slow for x", 12.345, 5, pf);
    expect(msg).toContain("measured 12.35ms");
    expect(msg).toContain("effective bound 10.00ms");
    expect(msg).toContain("base 5ms x factor 2.00");
    expect(msg).toContain("baseline 1.80ms");
  });
});
