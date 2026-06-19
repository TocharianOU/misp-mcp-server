#!/usr/bin/env node
// Licensed under the Apache License, Version 2.0
// SPDX-License-Identifier: Apache-2.0

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import axios, { AxiosError } from "axios";
import https from "https";
import {
  ServerBase,
  RequestHandlerExtra,
  ToolResponse,
  MispConfig,
  MispClient,
  MispConfigSchema,
  MispError,
  ServerCreationOptions,
} from "./src/types.js";
import { registerTools } from "./src/tools.js";

function createMispClient(config: MispConfig): MispClient {
  const axiosInstance = axios.create({
    baseURL: config.url,
    timeout: config.timeout,
    headers: {
      Authorization: config.apiKey,
      Accept: "application/json",
      "Content-Type": "application/json",
    },
    httpsAgent: config.verifySsl ? undefined : new https.Agent({ rejectUnauthorized: false }),
  });

  axiosInstance.interceptors.response.use(
    (res) => res.data,
    (error) => {
      console.error("MISP API error:", error.message);
      return Promise.reject(error);
    }
  );

  const wrap = async (fn: () => Promise<any>, label: string) => {
    try {
      return await fn();
    } catch (e) {
      const ae = e as AxiosError;
      throw new MispError(`${label} failed: ${ae.message}`, ae.response?.status, ae.response?.data);
    }
  };

  return {
    get: (url, options) =>
      wrap(() => axiosInstance.get(url, { params: options?.params }), `GET ${url}`),
    post: (url, data) =>
      wrap(() => axiosInstance.post(url, data), `POST ${url}`),
    put: (url, data) =>
      wrap(() => axiosInstance.put(url, data), `PUT ${url}`),
    delete: (url) =>
      wrap(() => axiosInstance.delete(url), `DELETE ${url}`),
  };
}

export async function createMispMcpServer(options: ServerCreationOptions): Promise<McpServer> {
  const { name, version, config, description } = options;

  const validatedConfig = MispConfigSchema.parse(config);
  const mispClient = createMispClient(validatedConfig);

  const server = new McpServer({
    name,
    version,
    capabilities: { tools: {}, prompts: { listChanged: false }, resources: {} },
    description,
  });

  const serverBase: ServerBase = {
    tool: (name: string, ...args: any[]) => {
      if (args.length === 1) {
        const [cb] = args;
        server.tool(name, async (extra: RequestHandlerExtra) => {
          try {
            return await Promise.resolve(cb(extra));
          } catch (e) {
            return { content: [{ type: "text", text: `Error: ${e instanceof Error ? e.message : String(e)}` }], isError: true };
          }
        });
      } else {
        const [description, schema, handler] = args;
        server.tool(name, description, schema.shape, async (args: any, extra: RequestHandlerExtra) => {
          try {
            return await Promise.resolve(handler(args, extra));
          } catch (e) {
            const detail = e instanceof MispError && e.details ? `\nDetails: ${JSON.stringify(e.details)}` : "";
            return { content: [{ type: "text", text: `Error: ${e instanceof Error ? e.message : String(e)}${detail}` }], isError: true };
          }
        });
      }
    },
  };

  await registerTools(serverBase, mispClient);

  return server;
}

async function main() {
  const config: MispConfig = {
    url: process.env.MISP_URL || "https://localhost",
    apiKey: process.env.MISP_API_KEY || "",
    verifySsl: process.env.MISP_VERIFY_SSL !== "false",
    timeout: parseInt(process.env.MISP_TIMEOUT || "30000", 10),
  };

  process.stderr.write(`Starting MISP MCP Server → ${config.url}\n`);

  const server = await createMispMcpServer({
    name: "misp-mcp-server",
    version: "0.1.0",
    config,
    description: "MISP Threat Intelligence Platform MCP Server",
  });

  const transport = new StdioServerTransport();
  await server.connect(transport);

  process.on("SIGINT", async () => {
    await server.close();
    process.exit(0);
  });
}

main().catch(() => process.exit(1));
