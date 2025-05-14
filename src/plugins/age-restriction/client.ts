import type { BetterAuthClientPlugin } from "better-auth";
import { ageRestriction } from "./index";

export const ageRestrictionClient = () => {
	return {
		id: "ageRestriction",
		$InferServerPlugin: {} as ReturnType<typeof ageRestriction>
	} satisfies BetterAuthClientPlugin;
}; 