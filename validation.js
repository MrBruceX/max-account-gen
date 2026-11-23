import { z } from 'zod';

export const emailSchema = z.string().trim().email().max(254);
export const passwordSchema = z.string().min(12).max(128);
export const discordIdSchema = z.string().regex(/^[0-9]{15,20}$/);
export const stockTypeSchema = z.enum(['discord','steam','rockstar','rockstar_code']);
export const tierSchema = z.enum(['weekly','monthly','lifetime']);

export const stockAddSchema = z.object({
  type: stockTypeSchema,
  lines: z.array(z.string().trim().min(1).max(2000)).min(1).max(500)
}).strict();

export const generateSchema = z.object({
  type: stockTypeSchema,
  count: z.number().int().min(1).max(10)
}).strict();

export const licenseCreateSchema = z.object({
  label: z.string().trim().max(100).default(''),
  tier: tierSchema,
  days: z.number().int().min(1).max(3650),
  discordId: discordIdSchema.optional(),
  rockstarCodeAccess: z.boolean().default(false)
}).strict();

export const bugSchema = z.object({
  discordId: discordIdSchema,
  username: z.string().trim().max(100).default(''),
  category: z.string().trim().max(80).default(''),
  title: z.string().trim().min(3).max(120),
  body: z.string().trim().min(5).max(3000)
}).strict();
