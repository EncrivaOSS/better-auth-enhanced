import type { BetterAuthClientPlugin } from "better-auth";
import { username } from "./index";

/**
 * Validates if a username meets the requirements
 * @param username The username to validate
 * @returns Whether the username is valid
 */
export const validateUsername = (username: string) => {
	// Basic validation: username must be 3-30 characters and contain only alphanumeric, underscore, or dot
	return username.length >= 3 &&
		username.length <= 30 &&
		/^[a-zA-Z0-9_.]+$/.test(username);
};

/**
 * Formats a username according to standard rules
 * @param username The username to format
 * @returns The formatted username
 */
export const formatUsername = (username: string) => {
	// Convert to lowercase and replace spaces with underscores
	return username.toLowerCase().replace(/\s+/g, '_');
};

/**
 * Username client plugin for Better Auth
 * Provides client-side functionality for the username plugin
 */
export const usernameClient = () => {
	return {
		id: "username",
		$InferServerPlugin: {} as ReturnType<typeof username>,
	} satisfies BetterAuthClientPlugin;
}; 