import { z } from "zod";
import { createAuthEndpoint, createAuthMiddleware, sessionMiddleware } from "better-auth/api";
import type { AuthPluginSchema, BetterAuthPlugin, GenericEndpointContext } from "better-auth";
import { APIError } from "better-call";
import { setSessionCookie } from "better-auth/cookies";
import { sendVerificationEmailFn } from "better-auth/api";
import { mergeSchema } from "better-auth/db";

// Extending Better Auth's User type with username field
interface UserWithUsername {
	id: string;
	name: string;
	email: string;
	emailVerified: boolean;
	username: string;
	createdAt: Date;
	updatedAt: Date;
	image?: string | null;
}

// We'll use UserWithUsername where User type is needed
type User = UserWithUsername;

/**
 * Error codes for the username plugin
 */
export const USERNAME_ERROR_CODES = {
	INVALID_USERNAME_OR_PASSWORD: "Invalid username or password.",
	USERNAME_TOO_SHORT: "Username is too short.",
	USERNAME_TOO_LONG: "Username is too long.",
	INVALID_USERNAME: "Invalid username format.",
	USERNAME_IS_ALREADY_TAKEN: "Username is already taken.",
	EMAIL_NOT_VERIFIED: "Email is not verified.",
} as const;

/**
 * Schema definition for the username plugin
 * Assumes Better-Auth FieldType definition
 */
const schema = {
	user: {
		fields: {
			username: {
				type: "string",
				required: false,
				returned: true
			}
		},
	},
} satisfies AuthPluginSchema;

// Base error codes
const BASE_ERROR_CODES = {
	FAILED_TO_CREATE_SESSION: "Session creation failed.",
};

/**
 * Username plugin options
 */
export interface UsernameOptions {
	/**
	 * Custom schema definitions
	 */
	schema?: Record<string, any>;

	/**
	 * Minimum username length
	 * @default 3
	 */
	minUsernameLength?: number;

	/**
	 * Maximum username length
	 * @default 30
	 */
	maxUsernameLength?: number;

	/**
	 * Username validation function
	 * 
	 * By default, username can only contain alphanumeric characters, underscores and dots
	 */
	validator?: (username: string) => boolean | Promise<boolean>;

	/**
	 * Text transform function
	 * @default (username: string) => username
	 * @example (username: string) => username.toLowerCase()
	 */
	transform?: (username: string) => string;
}

/**
 * Default username validation function
 * Can only contain alphanumeric characters, underscores and dots
 */
function defaultUsernameValidator(username: string) {
	return /^[a-zA-Z0-9_.]+$/.test(username);
}

/**
 * Validate username length
 */
function validateUsernameLength(
	username: string,
	minLength: number,
	maxLength: number,
	ctx: any
) {
	if (username.length < minLength) {
		ctx.context.logger.error("Username is too short", {
			username: username,
		});
		throw new APIError("UNPROCESSABLE_ENTITY", {
			message: USERNAME_ERROR_CODES.USERNAME_TOO_SHORT,
		});
	}

	if (username.length > maxLength) {
		ctx.context.logger.error("Username is too long", {
			username: username,
		});
		throw new APIError("UNPROCESSABLE_ENTITY", {
			message: USERNAME_ERROR_CODES.USERNAME_TOO_LONG,
		});
	}
}

/**
 * Validate username format
 */
async function validateUsernameFormat(
	username: string,
	validator: (username: string) => boolean | Promise<boolean>
) {
	if (!(await validator(username))) {
		throw new APIError("UNPROCESSABLE_ENTITY", {
			message: USERNAME_ERROR_CODES.INVALID_USERNAME,
		});
	}
}

/**
 * Check if username is unique
 * Case-insensitive check
 * @param username Username to check
 * @param ctx Context object
 * @param currentUserId Current user's ID (if updating)
 */
async function checkUsernameUniqueness(username: string, ctx: any, currentUserId?: string) {
	// Tüm eşleşen kullanıcıları getir, sonra kontrol et
	const users = await ctx.context.adapter.findMany({
		model: "user",
		where: [
			{
				field: "username",
				value: username.toLowerCase(),
				operator: "contains" // closest option for case-insensitive search
			}
		]
	});

	// Tam eşleşmeyi kontrol et (sadece lowercase içermesi yeterli değil)
	const existingUser = users.find((user: any) =>
		user.username && user.username.toLowerCase() === username.toLowerCase()
	);

	// Eğer kullanıcı varsa ve bu kullanıcı mevcut kullanıcıdan farklıysa hata fırlat
	if (existingUser && (!currentUserId || existingUser.id !== currentUserId)) {
		throw new APIError("UNPROCESSABLE_ENTITY", {
			message: USERNAME_ERROR_CODES.USERNAME_IS_ALREADY_TAKEN,
		});
	}
}

/**
 * Find user by username
 */
async function findUserByUsername(username: string, ctx: GenericEndpointContext) {
	// Tüm eşleşen kullanıcıları getir, sonra kontrol et
	const users = await ctx.context.adapter.findMany({
		model: "user",
		where: [
			{
				field: "username",
				value: username.toLowerCase(),
				operator: "contains" // closest option for case-insensitive search
			}
		]
	});

	// Tam eşleşme için kontrol et
	return users.find((user: any) =>
		user.username && user.username.toLowerCase() === username.toLowerCase()
	) as User;
}

/**
 * Find user account
 */
async function findUserAccount(userId: string, ctx: any) {
	return await ctx.context.adapter.findOne({
		model: "account",
		where: [
			{
				field: "userId",
				value: userId,
			},
			{
				field: "providerId",
				value: "credential",
			},
		],
	});
}

/**
 * Verify password
 */
async function verifyPassword(hash: string, password: string, ctx: any) {
	return await ctx.context.password.verify({
		hash: hash,
		password: password,
	});
}

/**
 * Create session
 */
async function createUserSession(userId: string, ctx: any, isExpirable: boolean) {
	return await ctx.context.internalAdapter.createSession(
		userId,
		ctx,
		isExpirable
	);
}

/**
 * Check email verification
 */
async function checkEmailVerification(
	user: User,
	ctx: GenericEndpointContext
) {
	if (
		user.emailVerified !== undefined &&
		!user.emailVerified &&
		ctx.context.options.emailAndPassword?.requireEmailVerification
	) {
		await sendVerificationEmailFn(ctx, user);
		throw new APIError("FORBIDDEN", {
			message: USERNAME_ERROR_CODES.EMAIL_NOT_VERIFIED,
		});
	}
}

/**
 * Create sign in username endpoint
 */
function createSignInUsernameEndpoint(
	minUsernameLength: number,
	maxUsernameLength: number,
	validator: (username: string) => boolean | Promise<boolean>
) {
	return createAuthEndpoint(
		"/sign-in/username",
		{
			method: "POST",
			body: z.object({
				username: z.string({
					description: "User's username",
				}),
				password: z.string({
					description: "User's password",
				}),
				rememberMe: z
					.boolean({
						description: "Remember user session",
					})
					.optional(),
			}),
			metadata: {
				openapi: {
					summary: "Sign in with username",
					description: "Sign in with username and password",
					responses: {
						200: {
							description: "Success",
							content: {
								"application/json": {
									schema: {
										type: "object",
										properties: {
											token: {
												type: "string",
												description: "Token information for session",
											},
											user: {
												$ref: "#/components/schemas/User",
											},
										},
										required: ["token", "user"],
									},
								},
							},
						},
					},
				},
			},
		},
		async (ctx) => {
			// Gerekli alanların kontrolü
			if (!ctx.body.username || !ctx.body.password) {
				ctx.context.logger.error("Username or password not found");
				throw new APIError("UNAUTHORIZED", {
					message: USERNAME_ERROR_CODES.INVALID_USERNAME_OR_PASSWORD,
				});
			}

			// Kullanıcı adı validasyonları
			validateUsernameLength(ctx.body.username, minUsernameLength, maxUsernameLength, ctx);
			await validateUsernameFormat(ctx.body.username, validator);

			// Kullanıcıyı bul
			const user = await findUserByUsername(ctx.body.username, ctx);

			if (!user) {
				// Zamanlama saldırılarını önlemek için şifreyi hash'leme
				// Geçersiz kullanıcı adlarında da şifreleri hashliyerek tutarlı yanıt süresi sağlama
				await ctx.context.password.hash(ctx.body.password);

				ctx.context.logger.error("User not found", {
					username: ctx.body.username,
				});

				throw new APIError("UNAUTHORIZED", {
					message: USERNAME_ERROR_CODES.INVALID_USERNAME_OR_PASSWORD,
				});
			}

			// E-posta doğrulama kontrolü
			await checkEmailVerification(user, ctx);

			// Kullanıcı hesabını bulma
			const account = await findUserAccount(user.id, ctx);

			if (!account) {
				throw new APIError("UNAUTHORIZED", {
					message: USERNAME_ERROR_CODES.INVALID_USERNAME_OR_PASSWORD,
				});
			}

			// Şifre kontrolü
			const currentPassword = account.password;
			if (!currentPassword) {
				ctx.context.logger.error("Password not found", {
					username: ctx.body.username,
				});
				throw new APIError("UNAUTHORIZED", {
					message: USERNAME_ERROR_CODES.INVALID_USERNAME_OR_PASSWORD,
				});
			}

			// Şifre doğrulama
			const validPassword = await verifyPassword(currentPassword, ctx.body.password, ctx);

			if (!validPassword) {
				ctx.context.logger.error("Invalid password", {
					username: ctx.body.username,
				});
				throw new APIError("UNAUTHORIZED", {
					message: USERNAME_ERROR_CODES.INVALID_USERNAME_OR_PASSWORD,
				});
			}

			// Oturum oluşturma
			const session = await createUserSession(
				user.id,
				ctx,
				ctx.body.rememberMe === false
			);

			if (!session) {
				return ctx.json(null, {
					status: 500,
					body: {
						message: BASE_ERROR_CODES.FAILED_TO_CREATE_SESSION,
					},
				});
			}

			// Oturum cookie'si ayarlama
			await setSessionCookie(
				ctx,
				{ session, user },
				ctx.body.rememberMe === false
			);

			// Başarılı giriş yanıtı
			return ctx.json({
				token: session.token,
				user: {
					id: user.id,
					email: user.email,
					emailVerified: user.emailVerified,
					username: user.username,
					name: user.name,
					image: user.image,
					createdAt: user.createdAt,
					updatedAt: user.updatedAt,
				},
			});
		}
	);
}

/**
 * Create username validation hook
 */
function createUsernameValidationHook(
	minUsernameLength: number,
	maxUsernameLength: number,
	validator: (username: string) => boolean | Promise<boolean>,
	transform?: (username: string) => string
) {
	return {
		matcher(context: any) {
			return (
				context.path === "/sign-up/email" ||
				context.path === "/update-user"
			);
		},
		handler: createAuthMiddleware(async (ctx) => {
			const username = transform ? transform(ctx.body.username) : ctx.body.username;
			if (username !== undefined && typeof username === "string") {
				await validateUsernameLength(username, minUsernameLength, maxUsernameLength, ctx);
				await validateUsernameFormat(username, validator);
				if (ctx.path === "/update-user") {
					const auth = await sessionMiddleware(ctx);
					const { session } = auth;
					await checkUsernameUniqueness(username, ctx, session?.user?.id);
				} else {
					await checkUsernameUniqueness(username, ctx);
				}
			}
			ctx.body.test = username;
			ctx.body.username = username;
		})
	};
}

/**
 * Username authorization plugin
 */
export const username = (options?: UsernameOptions) => {
	// Varsayılan değerler ile ayarları birleştir
	const minUsernameLength = options?.minUsernameLength ?? 3;
	const maxUsernameLength = options?.maxUsernameLength ?? 30;
	const validator = options?.validator ?? defaultUsernameValidator;

	return {
		id: "username",

		// API endpoint'leri
		endpoints: {
			signInUsername: createSignInUsernameEndpoint(minUsernameLength, maxUsernameLength, validator),
		},

		// Şema ayarları
		schema: mergeSchema(schema, options?.schema),

		// Hook'lar
		hooks: {
			before: [
				// Kullanıcı adı doğrulama hook'u - Kayıt ve güncelleme için
				createUsernameValidationHook(minUsernameLength, maxUsernameLength, validator, options?.transform),
			],
		},

		// Hata kodları
		$ERROR_CODES: USERNAME_ERROR_CODES,
	} satisfies BetterAuthPlugin;
};

