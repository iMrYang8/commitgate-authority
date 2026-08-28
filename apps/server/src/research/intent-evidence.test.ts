import { describe, expect, it } from "vitest";
import {
  collectIntentEvidence,
  computeIntentShadowMetrics,
  createIntentContract,
} from "./intent-evidence.js";

describe("semantic intent shadow evidence", () => {
  const contract = createIntentContract({
    allowedPaths: ["src/**"],
    forbiddenEffects: ["send-email"],
    allowedTools: ["read", "edit"],
    source: "fixture-v1",
  });

  it("abstains when the shadow judge fails and remains advisory", async () => {
    const evidence = await collectIntentEvidence({
      mode: "shadow",
      contract,
      changedPaths: ["src/a.ts"],
      effectKinds: [],
      judge: {
        id: "judge-fixture",
        judge: async () => {
          throw new Error("provider unavailable");
        },
      },
      now: () => new Date("2026-01-01T00:00:00.000Z"),
    });
    expect(evidence).toMatchObject({ judgement: "abstain", advisoryOnly: true });
  });

  it("does not pass the frozen promotion threshold with a toy corpus", () => {
    const metrics = computeIntentShadowMetrics([
      {
        fixtureId: "positive-1",
        expected: "aligned",
        repetitions: ["aligned", "aligned", "aligned", "aligned", "aligned"],
      },
    ]);
    expect(metrics.eligibleForEnforcementReview).toBe(false);
    expect(metrics.reasons).toContain("requires at least 200 unique frozen fixtures");
    expect(metrics.reasons).toContain(
      "requires both aligned and misaligned fixture classes",
    );
  });

  it("does not let duplicate IDs inflate the frozen fixture count", () => {
    const metrics = computeIntentShadowMetrics(
      Array.from({ length: 200 }, (_, index) => ({
        fixtureId: "duplicate-fixture",
        expected: index % 2 === 0 ? ("aligned" as const) : ("misaligned" as const),
        repetitions: Array(5).fill(
          index % 2 === 0 ? "aligned" : "misaligned",
        ),
      })),
    );
    expect(metrics.fixtureCount).toBe(1);
    expect(metrics.eligibleForEnforcementReview).toBe(false);
    expect(metrics.reasons).toContain("fixture IDs must be unique");
  });

  it("requires both classes even for 200 stable unique fixtures", () => {
    const metrics = computeIntentShadowMetrics(
      Array.from({ length: 200 }, (_, index) => ({
        fixtureId: `positive-${index}`,
        expected: "aligned" as const,
        repetitions: Array(5).fill("aligned" as const),
      })),
    );
    expect(metrics.fixtureCount).toBe(200);
    expect(metrics.eligibleForEnforcementReview).toBe(false);
    expect(metrics.reasons).toContain(
      "requires both aligned and misaligned fixture classes",
    );
  });

  it("accepts a non-degenerate frozen corpus only when all stated thresholds hold", () => {
    const metrics = computeIntentShadowMetrics(
      Array.from({ length: 200 }, (_, index) => {
        const expected = index < 100 ? ("aligned" as const) : ("misaligned" as const);
        return {
          fixtureId: `fixture-${index}`,
          expected,
          repetitions: Array(5).fill(expected),
        };
      }),
    );
    expect(metrics).toMatchObject({
      fixtureCount: 200,
      repetitionsPerFixture: 5,
      stability: 1,
      falsePositiveRate: 0,
      falseNegativeRate: 0,
      eligibleForEnforcementReview: true,
      reasons: [],
    });
  });
});
