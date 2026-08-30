export interface EvidenceProvenance {
  sourceRevision: string | null;
  headRevision: string | null;
  sourceTreeHash: string;
  sourceFileCount: number;
  workingTreeCleanAtCapture: boolean;
  provenanceMode: "git" | "release-manifest";
}

export interface ReleaseProvenanceManifestV1 {
  schemaVersion: 1;
  sourceRevision: string;
  sourceTreeHash: string;
  sourceFileCount: number;
  files: Array<{ path: string; executable: boolean; sha256: string }>;
}

export function sourceTreeHash(root: string): Promise<{ hash: string; files: number }>;
export function frozenSourceRevision(root: string): string | null;
export function evidenceProvenance(root: string): Promise<EvidenceProvenance>;
export function createReleaseProvenanceManifest(root: string): Promise<ReleaseProvenanceManifestV1>;
export const RELEASE_PROVENANCE_FILE: "RELEASE_PROVENANCE.json";
export function revisionIsAncestor(root: string, revision: unknown): boolean;
export function executionIdentity(
  root: string,
  options?: { environment?: NodeJS.ProcessEnv; providerId?: "ark" | "openrouter" },
): {
  schemaVersion: 2;
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
  workerImage: {
    reference: string;
    imageId: string | null;
    imageDigest: string | null;
    status: "verified" | "failed" | "unverified";
    reason: string | null;
  };
  brokerImage: {
    reference: string;
    imageId: string | null;
    imageDigest: string | null;
    status: "verified" | "failed" | "unverified";
    reason: string | null;
  };
  provider: {
    providerId: string;
    gateway: string | null;
    requestedModel: string | null;
    resolvedModel: null;
    wireApi: string | null;
    accessMode: string | null;
    credentialConfigured: boolean;
    credentialsRecorded: false;
  };
};
export function parseFlag(arguments_: string[], name: string): string | null;
