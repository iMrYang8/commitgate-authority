export const ALLOWED_MIRROR_ONLY_AUDIT_PATHS = Object.freeze([
  "scripts/check-drawio.py",
  "scripts/check-public-copy.mjs",
  "scripts/render-drawio-preview.py",
]);

export function sourceProductPath(relative) {
  return (
    relative.startsWith("apps/") ||
    relative.startsWith("scripts/") ||
    relative.startsWith("eval/fixtures/") ||
    relative.startsWith("eval/trusted-checks/") ||
    relative === "eval/demo-policy.json" ||
    relative === "package.json" ||
    relative === "package-lock.json" ||
    relative === "tsconfig.base.json" ||
    relative === ".dockerignore" ||
    relative === ".env.example" ||
    relative === ".env.local.example" ||
    relative === "docker-compose.yml" ||
    /^docker-compose(?:\.[^/]+)?\.ya?ml$/.test(relative) ||
    relative === "Dockerfile" ||
    relative === "Dockerfile.runtime" ||
    relative.startsWith("Dockerfile.")
  );
}
