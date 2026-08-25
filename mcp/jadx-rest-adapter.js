const READ_ONLY = { readOnlyHint: true, destructiveHint: false };

const TOOLS = [
  {
    name: "fetch_current_class",
    description: "Fetch the currently selected class and its decompiled code from JADX.",
    endpoint: "current-class",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
  },
  {
    name: "get_class_source",
    description: "Fetch the Java source of a class from the open JADX project.",
    endpoint: "class-source",
    inputSchema: {
      type: "object",
      properties: { class_name: { type: "string" } },
      required: ["class_name"],
      additionalProperties: false,
    },
  },
  {
    name: "get_all_classes",
    description: "List every class in the open JADX project with pagination.",
    endpoint: "all-classes",
    inputSchema: {
      type: "object",
      properties: { offset: { type: "integer", default: 0 }, count: { type: "integer", default: 0 } },
      additionalProperties: false,
    },
  },
  {
    name: "search_classes_by_keyword",
    description: "Search class names, methods, fields, or decompiled code across the open JADX project.",
    endpoint: "search-classes-by-keyword",
    inputSchema: {
      type: "object",
      properties: {
        search_term: { type: "string" },
        package: { type: "string", default: "" },
        search_in: { type: "string", default: "code" },
        offset: { type: "integer", default: 0 },
        count: { type: "integer", default: 100 },
      },
      required: ["search_term"],
      additionalProperties: false,
    },
  },
  {
    name: "get_android_manifest",
    description: "Read AndroidManifest.xml from the open JADX project.",
    endpoint: "manifest",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
  },
  {
    name: "get_strings",
    description: "Read strings.xml resources from the open JADX project.",
    endpoint: "strings",
    inputSchema: {
      type: "object",
      properties: { offset: { type: "integer", default: 0 }, count: { type: "integer", default: 0 } },
      additionalProperties: false,
    },
  },
  {
    name: "get_all_resource_file_names",
    description: "List every resource path in the open APK.",
    endpoint: "list-all-resource-files-names",
    inputSchema: {
      type: "object",
      properties: { offset: { type: "integer", default: 0 }, count: { type: "integer", default: 0 } },
      additionalProperties: false,
    },
  },
  {
    name: "get_resource_file",
    description: "Read a resource from the open APK by its exact resource path.",
    endpoint: "get-resource-file",
    inputSchema: {
      type: "object",
      properties: { resource_name: { type: "string" } },
      required: ["resource_name"],
      additionalProperties: false,
    },
    mapArguments: ({ resource_name }) => ({ file_name: resource_name }),
  },
  {
    name: "get_main_application_classes_names",
    description: "List classes belonging to the APK's main application package.",
    endpoint: "main-application-classes-names",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
  },
  {
    name: "get_main_application_classes_code",
    description: "Read decompiled code for classes in the APK's main application package.",
    endpoint: "main-application-classes-code",
    inputSchema: {
      type: "object",
      properties: { offset: { type: "integer", default: 0 }, count: { type: "integer", default: 0 } },
      additionalProperties: false,
    },
  },
  {
    name: "get_main_activity_class",
    description: "Read the APK's main activity class from JADX.",
    endpoint: "main-activity",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
  },
  {
    name: "get_package_tree",
    description: "List APK packages and class counts to distinguish application code from libraries.",
    endpoint: "package-tree",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
  },
];

function endpointUrl(baseUrl, endpoint, args = {}) {
  const url = new URL(`/${endpoint}`, baseUrl.origin);
  for (const [key, value] of Object.entries(args)) {
    if (value !== undefined && value !== null) url.searchParams.set(key, String(value));
  }
  return url;
}

async function readJson(response) {
  const body = await response.text();
  if (!response.ok) throw new Error(`JADX connector HTTP ${response.status}: ${body.slice(0, 500)}`);
  try {
    return JSON.parse(body);
  } catch {
    return { response: body };
  }
}

export async function connectJadxRest(config, { fetchImpl = fetch } = {}) {
  const configured = new URL(config.url);
  const baseUrl = new URL(configured.origin);
  const health = await readJson(await fetchImpl(endpointUrl(baseUrl, "health"), {
    headers: { Accept: "application/json" },
  }));
  if (health?.status && String(health.status).toLowerCase() !== "running") {
    throw new Error(`JADX connector is not running: ${health.status}`);
  }
  const toolMap = new Map(TOOLS.map((tool) => [tool.name, tool]));
  return {
    transportKind: "jadx-rest",
    tools: TOOLS.map(({ endpoint: _endpoint, mapArguments: _mapArguments, ...tool }) => ({
      ...tool,
      annotations: READ_ONLY,
    })),
    async listTools() {
      return this.tools;
    },
    async callTool(name, args = {}) {
      const tool = toolMap.get(String(name));
      if (!tool) throw new Error(`Unknown JADX read-only tool: ${name}`);
      const query = tool.mapArguments ? tool.mapArguments(args) : args;
      const value = await readJson(await fetchImpl(endpointUrl(baseUrl, tool.endpoint, query), {
        headers: { Accept: "application/json" },
      }));
      return {
        content: [{ type: "text", text: JSON.stringify(value) }],
        structuredContent: value,
        isError: Boolean(value?.error),
      };
    },
    async close() {},
  };
}

