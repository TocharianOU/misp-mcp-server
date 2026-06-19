// Licensed under the Apache License, Version 2.0
// SPDX-License-Identifier: Apache-2.0

import { z } from "zod";

export const MispConfigSchema = z.object({
  url: z.string().trim().min(1, "MISP URL cannot be empty").url("Invalid MISP URL format"),
  apiKey: z.string().min(1, "MISP API key cannot be empty"),
  verifySsl: z.boolean().optional().default(true),
  timeout: z.number().optional().default(30000),
});

export type MispConfig = z.infer<typeof MispConfigSchema>;

export interface ToolResponse {
  content: Array<{ type: "text"; text: string }>;
  isError?: boolean;
}

export interface ResourceResponse {
  contents: Array<{
    uri: string;
    mimeType: string;
    text?: string;
  }>;
}

export interface PromptResponse {
  description?: string;
  messages: Array<{
    role: "user" | "assistant";
    content: { type: "text"; text: string };
  }>;
}

export interface MispClient {
  get: (url: string, options?: { params?: any }) => Promise<any>;
  post: (url: string, data?: any) => Promise<any>;
  put: (url: string, data?: any) => Promise<any>;
  delete: (url: string) => Promise<any>;
}

export interface ServerBase {
  tool: {
    (name: string, cb: (extra: RequestHandlerExtra) => Promise<ToolResponse> | ToolResponse): void;
    (name: string, description: string, schema: any, handler: (args: any, extra: RequestHandlerExtra) => Promise<ToolResponse> | ToolResponse): void;
  };
}

export interface RequestHandlerExtra {
  [key: string]: unknown;
  signal: AbortSignal;
}

export class MispError extends Error {
  constructor(
    message: string,
    public statusCode?: number,
    public details?: any
  ) {
    super(message);
    this.name = "MispError";
  }
}

export interface ServerCreationOptions {
  name: string;
  version: string;
  transport?: any;
  config: MispConfig;
  description?: string;
}
