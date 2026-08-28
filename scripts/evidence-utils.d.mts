export interface EvidenceProvenance {
  sourceRevision: string | null;
  sourceTreeHash: string;
  sourceFileCount: number;
  workingTreeCleanAtCapture: boolean;
}

export function sourceTreeHash(root: string): Promise<{ hash: string; files: number }>;
export function evidenceProvenance(root: string): Promise<EvidenceProvenance>;
export function revisionIsAncestor(root: string, revision: unknown): boolean;
export function executionIdentity(
  root: string,
  options?: { environment?: NodeJS.ProcessEnv; providerId?: "ark" | "openrouter" },
): {
  schemaVersion: 1;
  containerEngine: string;
  runtimeImage: {
    reference: string;
    imageId: string | null;
    imageDigest: string | null;
    status: "verified" | "failed" | "unverified";
    reason: string | null;
  };
  verifierImage: {
    reference: string;
    imageId: string | null;
    imageDigest: string | null;
    status: "verified" | "failed" | "unverified";
    reason: string | null;
  };
  provider: {
    providerId: string;
    gateway: string;
    requestedModel: string | null;
    resolvedModel: null;
    wireApi: string;
    accessMode: string;
    credentialConfigured: boolean;
    credentialsRecorded: false;
  };
};
export function parseFlag(arguments_: string[], name: string): string | null;
