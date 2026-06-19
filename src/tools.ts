// Licensed under the Apache License, Version 2.0
// SPDX-License-Identifier: Apache-2.0

import { z } from "zod";
import type { ServerBase, MispClient, ToolResponse } from "./types.js";
import fs from "fs";
import path from "path";
import yaml from "js-yaml";
import { fileURLToPath } from "url";
import { dirname } from "path";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

interface ApiEndpoint {
  path: string;
  method: string;
  description?: string;
  summary?: string;
  parameters?: any[];
  requestBody?: any;
  tags?: string[];
}

let apiIndex: ApiEndpoint[] = [];
let indexBuilt = false;
let openApiDoc: any = null;

async function buildIndex(): Promise<void> {
  if (indexBuilt) return;

  const candidates = [
    process.env.MISP_OPENAPI_YAML_PATH,
    path.join(process.cwd(), "openapi.yaml"),
    path.join(__dirname, "openapi.yaml"),
    path.resolve(__dirname, "..", "openapi.yaml"),
    path.join(process.cwd(), "dist", "openapi.yaml"),
  ].filter((p): p is string => typeof p === "string" && p.length > 0);

  let yamlPath = "";
  for (const p of candidates) {
    if (fs.existsSync(p)) {
      yamlPath = p;
      break;
    }
  }

  if (!yamlPath) {
    console.error("Could not find openapi.yaml");
    indexBuilt = true;
    return;
  }

  const content = fs.readFileSync(yamlPath, "utf8");
  openApiDoc = yaml.load(content);

  if (!openApiDoc?.paths) throw new Error("Invalid openapi.yaml: missing paths");

  for (const [pathStr, pathObj] of Object.entries(openApiDoc.paths)) {
    for (const [method, methodObj] of Object.entries(pathObj as Record<string, any>)) {
      if (["get", "post", "put", "delete", "patch"].includes(method)) {
        apiIndex.push({
          path: pathStr,
          method: method.toUpperCase(),
          description: (methodObj as any).description,
          summary: (methodObj as any).summary,
          parameters: (methodObj as any).parameters,
          requestBody: (methodObj as any).requestBody,
          tags: (methodObj as any).tags,
        });
      }
    }
  }

  indexBuilt = true;
}

function resolveRef(obj: any, doc: any, seen = new Set<string>()): any {
  if (!obj || typeof obj !== "object") return obj;
  if (Array.isArray(obj)) return obj.map((i) => resolveRef(i, doc, seen));
  if (obj.$ref) {
    if (seen.has(obj.$ref)) return { circularRef: obj.$ref };
    seen.add(obj.$ref);
    const parts = obj.$ref.replace(/^#\//, "").split("/");
    let target = doc;
    for (const p of parts) target = target?.[p];
    return resolveRef(target, doc, seen);
  }
  const result: any = {};
  for (const k of Object.keys(obj)) result[k] = resolveRef(obj[k], doc, seen);
  return result;
}

function ok(text: string): ToolResponse {
  return { content: [{ type: "text", text }] };
}

function err(text: string): ToolResponse {
  return { content: [{ type: "text", text }], isError: true };
}

export async function registerTools(server: ServerBase, client: MispClient): Promise<void> {
  await buildIndex();

  // ── CREATE ────────────────────────────────────────────────────────────────

  server.tool(
    "create_event",
    "Create a new MISP threat intelligence event",
    z.object({
      info: z.string().describe("Short description / title of the event"),
      threat_level_id: z.enum(["1", "2", "3", "4"]).describe("1=High 2=Medium 3=Low 4=Undefined"),
      distribution: z.enum(["0", "1", "2", "3", "4", "5"]).optional().default("0")
        .describe("0=Org only 1=Community 2=Connected 3=All 4=Sharing group 5=Inherit"),
      analysis: z.enum(["0", "1", "2"]).optional().default("0")
        .describe("0=Initial 1=Ongoing 2=Completed"),
      date: z.string().optional().describe("Event date YYYY-MM-DD, defaults to today"),
      published: z.boolean().optional().default(false),
    }),
    async ({ info, threat_level_id, distribution, analysis, date, published }): Promise<ToolResponse> => {
      try {
        const response = await client.post("/events/add", {
          Event: { info, threat_level_id, distribution, analysis, date, published },
        });
        return ok(JSON.stringify(response, null, 2));
      } catch (e) {
        return err(`Failed to create event: ${e instanceof Error ? e.message : String(e)}`);
      }
    }
  );

  server.tool(
    "create_attribute",
    "Add an attribute (indicator) to an existing MISP event",
    z.object({
      event_id: z.string().describe("ID of the event to add the attribute to"),
      type: z.string().describe("Attribute type, e.g. ip-dst, domain, md5, url, email-src"),
      value: z.string().describe("Attribute value"),
      category: z.string().optional().describe("Category e.g. Network activity, Payload delivery, External analysis"),
      to_ids: z.boolean().optional().default(false).describe("Flag as indicator for detection"),
      comment: z.string().optional(),
      distribution: z.enum(["0", "1", "2", "3", "4", "5"]).optional().default("5"),
    }),
    async ({ event_id, type, value, category, to_ids, comment, distribution }): Promise<ToolResponse> => {
      try {
        const response = await client.post(`/attributes/add/${event_id}`, {
          Attribute: { type, value, category, to_ids, comment, distribution },
        });
        return ok(JSON.stringify(response, null, 2));
      } catch (e) {
        return err(`Failed to create attribute: ${e instanceof Error ? e.message : String(e)}`);
      }
    }
  );

  server.tool(
    "create_object",
    "Add a MISP object (structured composite indicator) to an event",
    z.object({
      event_id: z.string().describe("ID of the event"),
      name: z.string().describe("Object template name, e.g. file, network-traffic, domain-ip"),
      attributes: z.array(z.object({
        object_relation: z.string().describe("Relation key defined by the template, e.g. filename, md5"),
        type: z.string(),
        value: z.string(),
        to_ids: z.boolean().optional().default(false),
      })).describe("List of object attributes"),
      comment: z.string().optional(),
      distribution: z.enum(["0", "1", "2", "3", "4", "5"]).optional().default("5"),
    }),
    async ({ event_id, name, attributes, comment, distribution }): Promise<ToolResponse> => {
      try {
        const response = await client.post(`/objects/add/${event_id}`, {
          Object: { name, comment, distribution, Attribute: attributes },
        });
        return ok(JSON.stringify(response, null, 2));
      } catch (e) {
        return err(`Failed to create object: ${e instanceof Error ? e.message : String(e)}`);
      }
    }
  );

  // ── QUERY ─────────────────────────────────────────────────────────────────

  server.tool(
    "search_events",
    "Search MISP events using flexible filters (restSearch)",
    z.object({
      value: z.string().optional().describe("Search term matched against event info and attributes"),
      tags: z.array(z.string()).optional().describe("Filter by tag names"),
      from: z.string().optional().describe("Start date YYYY-MM-DD"),
      to: z.string().optional().describe("End date YYYY-MM-DD"),
      threat_level_id: z.enum(["1", "2", "3", "4"]).optional(),
      published: z.boolean().optional(),
      limit: z.number().optional().default(50),
      page: z.number().optional().default(1),
    }),
    async ({ value, tags, from, to, threat_level_id, published, limit, page }): Promise<ToolResponse> => {
      try {
        const response = await client.post("/events/restSearch", {
          returnFormat: "json",
          value,
          tags,
          from,
          to,
          threat_level_id,
          published,
          limit,
          page,
        });
        return ok(JSON.stringify(response, null, 2));
      } catch (e) {
        return err(`Failed to search events: ${e instanceof Error ? e.message : String(e)}`);
      }
    }
  );

  server.tool(
    "search_attributes",
    "Search MISP attributes / indicators using restSearch",
    z.object({
      value: z.string().optional().describe("Exact or partial attribute value to search"),
      type: z.string().optional().describe("Attribute type filter, e.g. ip-dst, domain, md5"),
      category: z.string().optional(),
      tags: z.array(z.string()).optional(),
      to_ids: z.boolean().optional().describe("Only return detection indicators"),
      event_id: z.string().optional().describe("Restrict search to a specific event"),
      limit: z.number().optional().default(100),
      page: z.number().optional().default(1),
    }),
    async ({ value, type, category, tags, to_ids, event_id, limit, page }): Promise<ToolResponse> => {
      try {
        const response = await client.post("/attributes/restSearch", {
          returnFormat: "json",
          value,
          type,
          category,
          tags,
          to_ids,
          eventid: event_id,
          limit,
          page,
        });
        return ok(JSON.stringify(response, null, 2));
      } catch (e) {
        return err(`Failed to search attributes: ${e instanceof Error ? e.message : String(e)}`);
      }
    }
  );

  server.tool(
    "get_event",
    "Get full details of a single MISP event by ID, including all attributes and objects",
    z.object({
      event_id: z.string().describe("MISP event ID or UUID"),
    }),
    async ({ event_id }): Promise<ToolResponse> => {
      try {
        const response = await client.get(`/events/view/${event_id}`);
        return ok(JSON.stringify(response, null, 2));
      } catch (e) {
        return err(`Failed to get event: ${e instanceof Error ? e.message : String(e)}`);
      }
    }
  );

  // ── PUBLISH ───────────────────────────────────────────────────────────────

  server.tool(
    "publish_event",
    "Publish a MISP event to make it visible to other organisations based on its distribution setting",
    z.object({
      event_id: z.string().describe("MISP event ID to publish"),
    }),
    async ({ event_id }): Promise<ToolResponse> => {
      try {
        const response = await client.post(`/events/publish/${event_id}`);
        return ok(JSON.stringify(response, null, 2));
      } catch (e) {
        return err(`Failed to publish event: ${e instanceof Error ? e.message : String(e)}`);
      }
    }
  );

  // ── EXECUTE (generic) ─────────────────────────────────────────────────────

  server.tool(
    "execute_misp_api",
    "Execute any MISP REST API endpoint directly. Use search_misp_api / get_misp_api_detail first to discover the right path and body schema.",
    z.object({
      method: z.enum(["GET", "POST", "PUT", "DELETE"]),
      path: z.string().describe("API path e.g. /events/view/42 or /attributes/restSearch"),
      body: z.any().optional().describe("Request body for POST/PUT"),
      params: z.record(z.union([z.string(), z.number(), z.boolean()])).optional().describe("Query string parameters"),
    }),
    async ({ method, path: apiPath, body, params }): Promise<ToolResponse> => {
      try {
        let url = apiPath;
        if (params && Object.keys(params).length > 0) {
          const qs = new URLSearchParams();
          for (const [k, v] of Object.entries(params)) qs.append(k, String(v));
          url += "?" + qs.toString();
        }
        let response: any;
        switch (method) {
          case "GET":    response = await client.get(url); break;
          case "POST":   response = await client.post(url, body); break;
          case "PUT":    response = await client.put(url, body); break;
          case "DELETE": response = await client.delete(url); break;
        }
        return ok(JSON.stringify(response, null, 2));
      } catch (e) {
        return err(`API call failed: ${e instanceof Error ? e.message : String(e)}`);
      }
    }
  );

  // ── API DISCOVERY helpers (bonus, not counted in the 8) ──────────────────

  server.tool(
    "search_misp_api",
    "Search MISP OpenAPI spec by keyword to find the right endpoint before calling execute_misp_api",
    z.object({
      query: z.string().describe("Keyword to search path / summary / description / tags"),
    }),
    async ({ query }): Promise<ToolResponse> => {
      const q = query.toLowerCase();
      const hits = apiIndex.filter(
        (e) =>
          e.path.toLowerCase().includes(q) ||
          e.summary?.toLowerCase().includes(q) ||
          e.description?.toLowerCase().includes(q) ||
          e.tags?.some((t) => t.toLowerCase().includes(q))
      );
      if (!hits.length) return ok(`No endpoints found matching "${query}"`);
      const lines = hits.slice(0, 30).map(
        (e) => `${e.method} ${e.path}${e.summary ? " — " + e.summary : ""}`
      );
      return ok(lines.join("\n") + (hits.length > 30 ? `\n… (${hits.length - 30} more)` : ""));
    }
  );

  server.tool(
    "get_misp_api_detail",
    "Get full OpenAPI schema detail for a specific MISP endpoint (parameters, request body, responses)",
    z.object({
      method: z.enum(["GET", "POST", "PUT", "DELETE", "PATCH"]),
      path: z.string().describe("Exact API path e.g. /events/restSearch"),
    }),
    async ({ method, path: apiPath }): Promise<ToolResponse> => {
      const endpoint = apiIndex.find(
        (e) => e.path === apiPath && e.method === method.toUpperCase()
      );
      if (!endpoint) return err(`Endpoint ${method} ${apiPath} not found in spec`);
      const raw = (openApiDoc?.paths?.[apiPath] as any)?.[method.toLowerCase()];
      const resolved = resolveRef(raw, openApiDoc);
      return ok(JSON.stringify(resolved, null, 2));
    }
  );
}
