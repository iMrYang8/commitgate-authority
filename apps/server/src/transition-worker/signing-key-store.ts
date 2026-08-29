import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  randomUUID,
  type KeyObject,
} from "node:crypto";
import { constants as fsConstants } from "node:fs";
import { chmod, mkdir, open, rename, writeFile } from "node:fs/promises";
import path from "node:path";
import {
  receiptSigningKeyId,
  signAuthorityReceiptProof,
  type AuthorityTerminalEventEnvelope,
  type AuthorityReceiptProofBundle,
  type AuthorityReceiptRecord,
} from "../research/receipt-proof.js";

/** Worker-only Ed25519 key material. Public keys are safe to export in proofs. */
export class WorkerSigningKeyStore {
  private privateKeyPem: string | null = null;
  private publicKeyPem: string | null = null;

  constructor(private readonly controlRoot: string) {}

  async initialize(): Promise<void> {
    const directory = path.join(this.controlRoot, "signing");
    const privatePath = path.join(directory, "ed25519-private.pem");
    const publicPath = path.join(directory, "ed25519-public.pem");
    await mkdir(directory, { recursive: true, mode: 0o700 });
    await chmod(directory, 0o700);
    let privatePem: string;
    try {
      privatePem = await this.readPrivateKey(privatePath);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      const generated = generateKeyPairSync("ed25519");
      const candidate = generated.privateKey
        .export({ type: "pkcs8", format: "pem" })
        .toString();
      try {
        await writeFile(privatePath, candidate, {
          encoding: "utf8",
          mode: 0o600,
          flag: "wx",
        });
        privatePem = candidate;
      } catch (writeError) {
        if ((writeError as NodeJS.ErrnoException).code !== "EEXIST") throw writeError;
        privatePem = await this.readPrivateKey(privatePath);
      }
    }
    await chmod(privatePath, 0o600);
    // Validate generated material through the same inode-bound read path used
    // after restart before it is trusted for signing.
    privatePem = await this.readPrivateKey(privatePath);
    const publicPem = this.publicFromPrivate(privatePem);
    const temporary = `${publicPath}.tmp-${process.pid}-${randomUUID()}`;
    await writeFile(temporary, publicPem, {
      encoding: "utf8",
      mode: 0o644,
      flag: "wx",
    });
    await rename(temporary, publicPath);
    await chmod(publicPath, 0o644);
    this.privateKeyPem = privatePem;
    this.publicKeyPem = publicPem;
  }

  get keyId(): string {
    return receiptSigningKeyId(this.requirePublicKey());
  }

  get publicKey(): string {
    return this.requirePublicKey();
  }

  sign(
    receipt: AuthorityReceiptRecord,
    event: AuthorityTerminalEventEnvelope,
    eventChain: readonly AuthorityTerminalEventEnvelope[],
  ): AuthorityReceiptProofBundle {
    if (!this.privateKeyPem) throw new Error("WORKER_SIGNING_KEY_NOT_INITIALIZED");
    return signAuthorityReceiptProof(
      receipt,
      event,
      eventChain,
      this.privateKeyPem,
      this.requirePublicKey(),
    );
  }

  private publicFromPrivate(privatePem: string): string {
    return (createPublicKey(privatePem) as KeyObject)
      .export({ type: "spki", format: "pem" })
      .toString();
  }

  private async readPrivateKey(privatePath: string): Promise<string> {
    const handle = await open(
      privatePath,
      fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0),
    );
    try {
      const before = await handle.stat();
      if (!before.isFile() || before.nlink !== 1) {
        throw new Error("WORKER_SIGNING_KEY_FILE_INVALID");
      }
      if ((before.mode & 0o777) !== 0o600) {
        throw new Error("WORKER_SIGNING_KEY_MODE_INVALID");
      }
      if (before.size <= 0 || before.size > 16 * 1024) {
        throw new Error("WORKER_SIGNING_KEY_SIZE_INVALID");
      }
      const privatePem = await handle.readFile("utf8");
      const after = await handle.stat();
      if (
        before.dev !== after.dev ||
        before.ino !== after.ino ||
        before.size !== after.size ||
        before.mtimeMs !== after.mtimeMs ||
        before.ctimeMs !== after.ctimeMs
      ) {
        throw new Error("WORKER_SIGNING_KEY_CHANGED_DURING_READ");
      }
      const key = createPrivateKey(privatePem);
      if (key.asymmetricKeyType !== "ed25519") {
        throw new Error("WORKER_SIGNING_KEY_ALGORITHM_INVALID");
      }
      return privatePem;
    } finally {
      await handle.close();
    }
  }

  private requirePublicKey(): string {
    if (!this.publicKeyPem) throw new Error("WORKER_SIGNING_KEY_NOT_INITIALIZED");
    return this.publicKeyPem;
  }
}
