import { z } from "zod";
import { createAuthEndpoint, createAuthMiddleware, sessionMiddleware } from "better-auth/api";
import type { AuthPluginSchema, BetterAuthPlugin, GenericEndpointContext, User } from "better-auth";
import { APIError } from "better-call";
import { mergeSchema } from "better-auth/db";

/**
 * Error codes for the age restriction plugin
 */
export const AGE_RESTRICTION_ERROR_CODES = {
	AGE_VERIFICATION_REQUIRED: "Age verification is required.",
	MINIMUM_AGE_REQUIRED: "You must meet the minimum age requirement to use this service.",
	BIRTHDATE_REQUIRED: "Birthdate information is required.",
	INVALID_BIRTHDATE: "Invalid birthdate.",
	VERIFICATION_FAILED: "Age verification failed.",
	SYSTEM_DISABLED: "Age restriction system is currently disabled.",
} as const;

type UserWithAgeVerification = User & {
	birthdate: Date;
	ageVerified: boolean;
	ageVerificationDate: Date;
};

/**
 * Schema definition for the age restriction plugin
 */
const schema = {
	user: {
		fields: {
			birthdate: {
				type: "date" as const,
				required: false,
			},
			ageVerified: {
				type: "boolean" as const,
				required: false,
			},
			ageVerificationDate: {
				type: "date" as const,
				required: false,
			},
		},
	},
	ageVerification: {
		fields: {
			_id: {
				type: "string" as const,
				required: true,
			},
			user: {
				type: "string" as const,
				references: {
					model: "user",
					field: "id"
				},
				required: true,
			},
			birthdate: {
				type: "date" as const,
				required: true,
			},
			verificationMethod: {
				type: "string" as const,
				required: false,
			},
			verificationData: {
				type: "string" as const,
				required: false,
			},
			isVerified: {
				type: "boolean" as const,
				required: true,
			},
			createdAt: {
				type: "date" as const,
				required: true,
			},
			verifiedAt: {
				type: "date" as const,
				required: false,
			},
		},
	},
} satisfies AuthPluginSchema;

/**
 * Options for the age restriction plugin
 */
export interface AgeRestrictionOptions {
	/**
	 * Custom schema definitions
	 */
	schema?: Record<string, any>;

	/**
	 * Enable/disable the age restriction system
	 * @default true
	 */
	enabled?: boolean;

	/**
	 * Minimum age required for the service
	 * @default 18
	 */
	minimumAge?: number;

	/**
	 * Require verification on sign up
	 * @default false
	 */
	requireOnSignUp?: boolean;

	/**
	 * Available verification methods
	 * @default ["birthdate"]
	 */
	verificationMethods?: string[];

	/**
	 * Number of days until re-verification is required
	 * @default 365
	 */
	reverificationPeriod?: number;
}

/**
 * Calculates the age from birthdate
 */
function calculateAge(birthdate: Date): number {
	const today = new Date();
	let age = today.getFullYear() - birthdate.getFullYear();
	const monthDiff = today.getMonth() - birthdate.getMonth();

	if (monthDiff < 0 || (monthDiff === 0 && today.getDate() < birthdate.getDate())) {
		age--;
	}

	return age;
}

/**
 * Verifies if user meets the minimum age requirement
 */
function verifyMinimumAge(birthdate: Date, minimumAge: number): boolean {
	const age = calculateAge(birthdate);
	return age >= minimumAge;
}

/**
 * Updates user's age verification status
 */
async function updateUserAgeVerification(
	userId: string,
	birthdate: Date,
	isVerified: boolean,
	ctx: GenericEndpointContext
) {
	await ctx.context.adapter.update({
		model: "user",
		where: [
			{
				field: "id",
				value: userId,
				operator: "eq",
			},
		],
		update: {
			birthdate,
			ageVerified: isVerified,
			ageVerificationDate: isVerified ? new Date() : undefined,
		},
	});
}

/**
 * Creates a verification record
 */
async function createVerificationRecord(
	userId: string,
	birthdate: Date,
	verificationMethod: string,
	verificationData: string | undefined,
	isVerified: boolean,
	ctx: GenericEndpointContext
) {
	return await ctx.context.adapter.create({
		model: "ageVerification",
		data: {
			_id: crypto.randomUUID(),
			userId,
			birthdate,
			verificationMethod,
			verificationData,
			isVerified,
			createdAt: new Date(),
			verifiedAt: isVerified ? new Date() : undefined,
		},
	});
}

/**
 * Checks if user needs to verify age
 */
async function checkAgeVerificationStatus(
	userId: string,
	minimumAge: number,
	reverificationPeriod: number,
	ctx: GenericEndpointContext
) {
	const user = await ctx.context.adapter.findOne({
		model: "user",
		where: [
			{
				field: "id",
				value: userId,
				operator: "eq",
			},
		],
	}) as UserWithAgeVerification;

	if (!user) return { needsVerification: true, reason: "USER_NOT_FOUND" };

	// If user has no birthdate, verification is needed
	if (!user.birthdate) return { needsVerification: true, reason: "NO_BIRTHDATE" };

	// If user is not verified, verification is needed
	if (!user.ageVerified) return { needsVerification: true, reason: "NOT_VERIFIED" };

	// Check if verification is still valid
	if (user.ageVerificationDate) {
		const verificationDate = new Date(user.ageVerificationDate);
		const today = new Date();
		const daysSinceVerification = Math.floor(
			(today.getTime() - verificationDate.getTime()) / (1000 * 60 * 60 * 24)
		);

		if (daysSinceVerification > reverificationPeriod) {
			return { needsVerification: true, reason: "VERIFICATION_EXPIRED" };
		}
	}

	// Check if user meets minimum age requirement
	const birthdate = new Date(user.birthdate);
	if (!verifyMinimumAge(birthdate, minimumAge)) {
		return { needsVerification: true, reason: "UNDER_AGE" };
	}

	return { needsVerification: false };
}

/**
 * Age verification endpoint
 */
function createVerifyAgeEndpoint(
	enabled: boolean,
	minimumAge: number,
	verificationMethods: string[]
) {
	return createAuthEndpoint(
		"/age-restriction/verify",
		{
			method: "POST",
			body: z.object({
				birthdate: z.string().transform((val) => new Date(val)),
				verificationMethod: z.string().optional(),
				verificationData: z.string().optional(),
			}),
			use: [sessionMiddleware],
			metadata: {
				openapi: {
					summary: "Verify age",
					description: "Verifies user age through provided birthdate and optional verification",
					responses: {
						200: {
							description: "Success",
							content: {
								"application/json": {
									schema: {
										type: "object",
										properties: {
											success: { type: "boolean" },
											isVerified: { type: "boolean" },
											meetsMinimumAge: { type: "boolean" },
										},
										required: ["success", "isVerified", "meetsMinimumAge"],
									},
								},
							},
						},
					},
				},
			},
		},
		async (ctx) => {
			if (!enabled) {
				throw new APIError("FORBIDDEN", {
					message: AGE_RESTRICTION_ERROR_CODES.SYSTEM_DISABLED,
				});
			}

			if (!ctx.context.session?.user?.id) {
				throw new APIError("UNAUTHORIZED", {
					message: "You must be logged in to verify your age",
				});
			}

			// Validate birthdate
			if (!ctx.body.birthdate || isNaN(ctx.body.birthdate.getTime())) {
				throw new APIError("BAD_REQUEST", {
					message: AGE_RESTRICTION_ERROR_CODES.INVALID_BIRTHDATE,
				});
			}

			// Check verification method
			const verificationMethod = ctx.body.verificationMethod || "birthdate";
			if (!verificationMethods.includes(verificationMethod)) {
				throw new APIError("BAD_REQUEST", {
					message: `Invalid verification method. Available methods: ${verificationMethods.join(", ")}`,
				});
			}

			// Check minimum age
			const meetsMinimumAge = verifyMinimumAge(ctx.body.birthdate, minimumAge);

			// Simple verification based on birthdate only for now
			const isVerified = meetsMinimumAge;

			// Update user record
			await updateUserAgeVerification(
				ctx.context.session.user.id,
				ctx.body.birthdate,
				isVerified,
				ctx
			);

			// Create verification record
			await createVerificationRecord(
				ctx.context.session.user.id,
				ctx.body.birthdate,
				verificationMethod,
				ctx.body.verificationData,
				isVerified,
				ctx
			);

			return ctx.json({
				success: true,
				isVerified,
				meetsMinimumAge,
			});
		}
	);
}

/**
 * Check age verification status endpoint
 */
function createCheckAgeStatusEndpoint(
	enabled: boolean,
	minimumAge: number,
	reverificationPeriod: number
) {
	return createAuthEndpoint(
		"/age-restriction/status",
		{
			method: "GET",
			use: [sessionMiddleware],
			metadata: {
				openapi: {
					summary: "Check age verification status",
					description: "Checks if user's age is verified and meets requirements",
					responses: {
						200: {
							description: "Success",
							content: {
								"application/json": {
									schema: {
										type: "object",
										properties: {
											verified: { type: "boolean" },
											needsVerification: { type: "boolean" },
											reason: { type: "string" },
											minimumAge: { type: "number" },
										},
										required: ["verified", "needsVerification", "minimumAge"],
									},
								},
							},
						},
					},
				},
			},
		},
		async (ctx) => {
			if (!enabled) {
				return ctx.json({
					verified: false,
					needsVerification: false,
					minimumAge,
				});
			}

			if (!ctx.context.session?.user?.id) {
				throw new APIError("UNAUTHORIZED", {
					message: "You must be logged in to check your age verification status",
				});
			}

			const { needsVerification, reason } = await checkAgeVerificationStatus(
				ctx.context.session.user.id,
				minimumAge,
				reverificationPeriod,
				ctx
			);

			return ctx.json({
				verified: !needsVerification,
				needsVerification,
				reason,
				minimumAge,
			});
		}
	);
}

/**
 * Age restriction hook for protected routes
 */
function createAgeRestrictionHook(
	enabled: boolean,
	minimumAge: number,
	reverificationPeriod: number,
	protectedPaths: RegExp[]
) {
	return {
		matcher(context: any) {
			// Skip verification for the age restriction endpoints themselves
			if (
				context.path === "/age-restriction/verify" ||
				context.path === "/age-restriction/status"
			) {
				return false;
			}

			// Check if the path matches any of the protected paths
			return protectedPaths.some(pattern => pattern.test(context.path));
		},
		handler: createAuthMiddleware(async (ctx: any) => {
			if (!enabled) return;

			if (!ctx.context.session?.user?.id) {
				throw new APIError("UNAUTHORIZED", {
					message: "You must be logged in to access this resource",
				});
			}

			const { needsVerification, reason } = await checkAgeVerificationStatus(
				ctx.context.session.user.id,
				minimumAge,
				reverificationPeriod,
				ctx
			);

			if (needsVerification) {
				if (reason === "UNDER_AGE") {
					throw new APIError("FORBIDDEN", {
						message: AGE_RESTRICTION_ERROR_CODES.MINIMUM_AGE_REQUIRED,
						ageVerification: {
							needsVerification,
							reason,
							minimumAge,
						},
					});
				} else {
					throw new APIError("FORBIDDEN", {
						message: AGE_RESTRICTION_ERROR_CODES.AGE_VERIFICATION_REQUIRED,
						ageVerification: {
							needsVerification,
							reason,
							minimumAge,
						},
					});
				}
			}
		}),
	};
}

/**
 * Age restriction sign-up hook
 */
function createSignUpAgeRestrictionHook(
	enabled: boolean,
	minimumAge: number,
	requireOnSignUp: boolean
) {
	return {
		matcher(context: any) {
			return context.path === "/sign-up/email";
		},
		handler: createAuthMiddleware(async (ctx: any) => {
			if (!enabled || !requireOnSignUp) return;

			// If birthdate is provided, check minimum age
			if (ctx.body.birthdate) {
				const birthdate = new Date(ctx.body.birthdate);

				if (isNaN(birthdate.getTime())) {
					throw new APIError("BAD_REQUEST", {
						message: AGE_RESTRICTION_ERROR_CODES.INVALID_BIRTHDATE,
					});
				}

				const meetsMinimumAge = verifyMinimumAge(birthdate, minimumAge);

				if (!meetsMinimumAge) {
					throw new APIError("FORBIDDEN", {
						message: AGE_RESTRICTION_ERROR_CODES.MINIMUM_AGE_REQUIRED,
					});
				}
			} else if (requireOnSignUp) {
				throw new APIError("BAD_REQUEST", {
					message: AGE_RESTRICTION_ERROR_CODES.BIRTHDATE_REQUIRED,
				});
			}
		}),
	};
}

/**
 * Age restriction plugin
 */
export const ageRestriction = (options?: AgeRestrictionOptions) => {
	const opts = {
		enabled: options?.enabled ?? true,
		minimumAge: options?.minimumAge ?? 18,
		requireOnSignUp: options?.requireOnSignUp ?? false,
		verificationMethods: options?.verificationMethods ?? ["birthdate"],
		reverificationPeriod: options?.reverificationPeriod ?? 365,
		schema: options?.schema,
	};

	// Define protected paths (can be customized via options)
	const protectedPaths = [/^\/restricted\/.*/];

	return {
		id: "ageRestriction",

		schema: mergeSchema(schema, opts.schema),

		endpoints: {
			verifyAge: createVerifyAgeEndpoint(
				opts.enabled,
				opts.minimumAge,
				opts.verificationMethods
			),
			checkAgeStatus: createCheckAgeStatusEndpoint(
				opts.enabled,
				opts.minimumAge,
				opts.reverificationPeriod
			),
		},

		hooks: {
			before: [
				// Age restriction hook for protected routes
				createAgeRestrictionHook(
					opts.enabled,
					opts.minimumAge,
					opts.reverificationPeriod,
					protectedPaths
				),
				// Sign-up hook for age verification
				createSignUpAgeRestrictionHook(
					opts.enabled,
					opts.minimumAge,
					opts.requireOnSignUp
				),
			],
		},

		$ERROR_CODES: AGE_RESTRICTION_ERROR_CODES,
	} satisfies BetterAuthPlugin;
};