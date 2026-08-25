import { readFile, rename, unlink, writeFile } from "node:fs/promises";
import path from "node:path";

function validateValue(value) {
  const text = String(value || "");
  if (!text || /[\r\n\0]/.test(text)) throw new Error("Refusing to persist an empty or multiline environment value.");
  return text;
}

export function upsertEnvText(source, key, value) {
  if (!/^[A-Z][A-Z0-9_]*$/.test(key)) throw new Error("Invalid environment variable name.");
  const safeValue = validateValue(value);
  const input = String(source || "");
  const newline = input.includes("\r\n") ? "\r\n" : "\n";
  const lines = input ? input.split(/\r?\n/) : [];
  // split() leaves a sentinel empty item when the file already ends in a
  // newline. Remove only that sentinel so the final join adds exactly one.
  if (lines.length && lines.at(-1) === "") lines.pop();
  const matcher = new RegExp(`^\\s*${key}\\s*=`);
  let replaced = false;
  for (let index = 0; index < lines.length; index += 1) {
    if (!matcher.test(lines[index])) continue;
    lines[index] = `${key}=${safeValue}`;
    replaced = true;
  }
  if (!replaced) {
    while (lines.length && lines.at(-1) === "") lines.pop();
    lines.push(`${key}=${safeValue}`);
  }
  return `${lines.join(newline)}${newline}`;
}

export async function persistEnvValue(key, value, { envPath = path.resolve(".env") } = {}) {
  let source = "";
  try {
    source = await readFile(envPath, "utf8");
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
  const updated = upsertEnvText(source, key, value);
  const temporaryPath = path.join(path.dirname(envPath), `.${path.basename(envPath)}.matkap-${process.pid}-${Date.now()}.tmp`);
  try {
    await writeFile(temporaryPath, updated, { encoding: "utf8", mode: 0o600 });
    await rename(temporaryPath, envPath);
  } catch (error) {
    await unlink(temporaryPath).catch(() => {});
    throw error;
  }
  process.env[key] = String(value);
  return envPath;
}
