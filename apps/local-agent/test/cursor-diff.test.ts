import { describe, expect, it } from "vitest";
import { computeDiff } from "../src/cursor/diff.js";

describe("computeDiff", () => {
  const before = ["a", "b", "c", "d", "e", "f", "g", "h"].join("\n") + "\n";
  const after = ["a", "b", "c", "D", "e", "f", "g", "h", "i"].join("\n") + "\n";
  const r = computeDiff(before, after);

  it("counts line changes", () => {
    expect(r.added).toBe(2);
    expect(r.removed).toBe(1);
  });

  it("emits whole-line hunks with context", () => {
    expect(r.hunks.length).toBeGreaterThan(0);
    const first = r.hunks[0]!;
    expect(first.old).toContain("c\nd\ne");
    expect(first.new).toContain("c\nD\ne");
    expect(r.hunksTruncated).toBe(false);
  });

  it("caps very large rewrites", () => {
    const big = Array.from({ length: 5000 }, (_, i) => `line ${i}`).join("\n");
    const big2 = Array.from({ length: 5000 }, (_, i) => (i % 50 === 0 ? `changed ${i}` : `line ${i}`)).join("\n");
    const r2 = computeDiff(big, big2);
    expect(r2.hunks.length).toBeLessThanOrEqual(40);
    expect(r2.hunksTruncated).toBe(true);
  });
});
