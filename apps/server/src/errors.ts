export class HttpError extends Error {
  constructor(
    public readonly statusCode: number,
    message: string,
    public readonly code?: string,
  ) {
    super(message);
    this.name = "HttpError";
  }
}

export class RunCancelledError extends Error {
  constructor() {
    super("Run cancelled");
    this.name = "RunCancelledError";
  }
}

export class CommitGateRecoveryRequiredError extends Error {
  constructor(message: string, readonly originalError?: unknown) {
    super(message);
    this.name = "CommitGateRecoveryRequiredError";
  }
}
