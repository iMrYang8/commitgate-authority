import type { TransitionAuthority } from "./transition-authority.js";
import { WorkspaceTransitionWriter } from "./workspace-transition-writer.js";
import { WorkspaceManager } from "./workspace.js";

export function createInProcessTransitionAuthority(
  workspace: string | WorkspaceManager,
  controlRoot?: string,
): TransitionAuthority {
  return new WorkspaceTransitionWriter(
    typeof workspace === "string" ? new WorkspaceManager(workspace) : workspace,
    controlRoot,
  );
}
