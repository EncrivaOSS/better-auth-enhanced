import { z } from "zod";
import { createAuthEndpoint, sessionMiddleware } from "better-auth/api";
import type { AuthPluginSchema, BetterAuthPlugin, GenericEndpointContext } from "better-auth";
import { APIError } from "better-call";
import { mergeSchema } from "better-auth/db";
import { randomUUID } from "crypto";

/**
 * Error codes for the feedback plugin
 */
export const FEEDBACK_ERROR_CODES = {
	FEEDBACK_NOT_FOUND: "Feedback not found.",
	SYSTEM_DISABLED: "Feedback system is currently disabled.",
	UNAUTHORIZED: "You must be logged in to view feedbacks.",
	UNAUTHORIZED_SUBMIT: "You must be logged in to submit feedbacks.",
	ADMIN_REQUIRED: "You must be an admin to perform this action.",
} as const;

/**
 * Schema definition for the feedback plugin
 */
const schema: AuthPluginSchema = {
	feedback: {
		fields: {
			_id: {
				type: "string" as const,
				required: true,
				input: false
			},
			user: {
				type: "string" as const,
				references: {
					model: "user",
					field: "id"
				},
				required: false,
				input: false
			},
			response: {
				type: "string" as const,
				required: true,
				input: false
			},
			location: {
				type: "string" as const,
				required: false,
				input: false
			},
			createdAt: {
				type: "date" as const,
				required: true,
				input: false,
				defaultValue: () => new Date()
			}
		},
	},
};

interface Feedback {
	_id: string;
	user: string | undefined;
	response: string;
	location: string | undefined;
	createdAt: Date;
};

/**
 * Options for the feedback plugin
 */
export interface FeedbackOptions {
	/**
	 * Custom schema definitions
	 */
	schema?: Record<string, any>;

	/**
	 * Enable/disable the feedback system
	 * @default true
	 */
	enabled?: boolean;

	/**
	 * Admin roles
	 */
	adminRoles?: string[];

	/**
	 * Auth required for the feedback system
	 * @default true
	 */
	authRequired?: boolean;

	/**
	 * Trigger callback after feedback is created
	 */
	onSubmit?: (feedback: Feedback) => Promise<void>;
}

/**
 * Creates a new feedback
 */
async function createFeedback(
	userId: string | undefined,
	response: string,
	location: string | undefined,
	ctx: GenericEndpointContext,
	options: FeedbackOptions
) {
	const data = {
		_id: randomUUID(),
		user: userId ?? undefined,
		response,
		location,
		createdAt: new Date(),
	};

	const feedback = await ctx.context.adapter.create({
		model: "feedback",
		data
	});

	if (options?.onSubmit) {
		await options.onSubmit(data);
	}

	return feedback;
}

/**
 * Feedback system plugin
 */
export const feedback = (options?: FeedbackOptions) => {
	const opts = {
		enabled: options?.enabled ?? true,
		schema: options?.schema,
		authRequired: options?.authRequired ?? true,
		adminRoles: (typeof options?.adminRoles === "string" ? [options.adminRoles] : options?.adminRoles ?? []),
		onSubmit: options?.onSubmit
	};

	return {
		id: "feedback",

		schema: mergeSchema(schema, opts.schema),

		endpoints: {
			submitFeedback: createAuthEndpoint(
				"/feedback/submit",
				{
					method: "POST",
					body: z.object({
						response: z.string().min(1).max(1000),
						location: z.string().optional(),
					}),
					use: opts.authRequired ? [sessionMiddleware] : [],
					metadata: {
						openapi: {
							summary: "Create feedback",
							description: "Creates a new feedback",
							responses: {
								200: {
									description: "Success",
									content: {
										"application/json": {
											schema: {
												type: "object",
												properties: {
													success: {
														type: "boolean",
													},
													feedbackId: {
														type: "string",
													},
												},
												required: ["success", "feedbackId"],
											},
										},
									},
								},
							},
						},
					},
				},
				async (ctx) => {
					if (!opts.enabled) {
						throw new APIError("FORBIDDEN", {
							message: FEEDBACK_ERROR_CODES.SYSTEM_DISABLED,
						});
					}

					if (opts.authRequired && !ctx.context.session?.user) {
						throw new APIError("UNAUTHORIZED", {
							message: FEEDBACK_ERROR_CODES.UNAUTHORIZED_SUBMIT,
						});
					}
					// Create feedback
					const feedback = await createFeedback(
						opts.authRequired ? ctx.context.session?.user?.id : undefined,
						ctx.body.response,
						ctx.body.location,
						ctx,
						opts
					);

					return ctx.json({
						success: true,
						feedbackId: feedback._id,
					});
				}
			),
			listAllFeedbacks: createAuthEndpoint(
				"/feedback/list",
				{
					method: "GET",
					query: z.object({
						limit: z.string().optional(),
						offset: z.string().optional(),
					}),
					use: [sessionMiddleware],
					metadata: {
						openapi: {
							summary: "List feedbacks",
							description: "Lists all feedbacks (admin only)",
							responses: {
								200: {
									description: "Success",
									content: {
										"application/json": {
											schema: {
												type: "object",
												properties: {
													feedback: {
														type: "array",
														items: {
															type: "object",
															properties: {
																_id: { type: "string" },
																userId: { type: "string" },
																response: { type: "string" },
																location: { type: "string" },
																createdAt: { type: "string", format: "date-time" },
															},
														},
													},
													total: { type: "number" },
												},
												required: ["feedback", "total"],
											},
										},
									},
								},
							},
						},
					},
				},
				async (ctx) => {
					if (!opts.enabled) {
						return ctx.json({ feedback: [], total: 0 });
					}

					if (!ctx.context.session?.user?._id) {
						throw new APIError("UNAUTHORIZED", {
							message: FEEDBACK_ERROR_CODES.UNAUTHORIZED,
						});
					}

					// Check if the user is an admin
					const user = await ctx.context.adapter.findOne({
						model: "user",
						where: [
							{
								field: "_id",
								value: ctx.context.session.user._id,
								operator: "eq",
							},
						],
					});

					const isAdmin = opts.adminRoles.includes(ctx.context.session?.user?.role ?? "");

					if (!isAdmin) {
						throw new APIError("FORBIDDEN", {
							message: FEEDBACK_ERROR_CODES.ADMIN_REQUIRED,
						});
					}

					// Sorgu parametrelerini al
					const limit = ctx.query.limit ? parseInt(ctx.query.limit, 10) : 20;
					const offset = ctx.query.offset ? parseInt(ctx.query.offset, 10) : 0;

					// Geri bildirimleri getir
					const feedbackList = await ctx.context.adapter.findMany({
						model: "feedback",
						limit,
						offset,
						sortBy: {
							field: "createdAt",
							direction: "desc",
						},
					});

					// Toplam geri bildirim sayısını getir
					const total = await ctx.context.adapter.count({
						model: "feedback",
					});

					return ctx.json({
						feedback: feedbackList.map((feedback: any) => ({
							_id: feedback._id,
							userId: feedback.userId,
							response: feedback.response,
							location: feedback.location,
							createdAt: feedback.createdAt,
						})),
						total,
					});
				}
			)
		},

		$ERROR_CODES: FEEDBACK_ERROR_CODES,
	} satisfies BetterAuthPlugin;
}; 