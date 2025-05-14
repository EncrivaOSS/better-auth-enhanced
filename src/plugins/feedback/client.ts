import type { BetterAuthClientPlugin } from "better-auth";
import { feedback } from "./index";

export const feedbackClient = () => {
	return {
		id: "feedback",
		$InferServerPlugin: {} as ReturnType<typeof feedback>,
	} satisfies BetterAuthClientPlugin;
}; 