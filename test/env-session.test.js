import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { persistEnvValue, upsertEnvText } from "../env-session.js";

test("session persistence replaces an existing env value without touching comments or other secrets", () => {
  const source = "# TELEGRAM_STRING_SESSION=example\r\nANTHROPIC_API_KEY=secret\r\nTELEGRAM_STRING_SESSION=old\r\n";
  const updated = upsertEnvText(source, "TELEGRAM_STRING_SESSION", "new-session-value");
  assert.equal(updated, "# TELEGRAM_STRING_SESSION=example\r\nANTHROPIC_API_KEY=secret\r\nTELEGRAM_STRING_SESSION=new-session-value\r\n");
});

test("session persistence appends a missing env value", () => {
  assert.equal(
    upsertEnvText("PORT=3000\n", "TELEGRAM_STRING_SESSION", "saved"),
    "PORT=3000\nTELEGRAM_STRING_SESSION=saved\n"
  );
});

test("session persistence rejects multiline values", () => {
  assert.throws(() => upsertEnvText("", "TELEGRAM_STRING_SESSION", "bad\nvalue"), /multiline/i);
});

test("session persistence atomically updates an env file on disk", async (t) => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "matkap-env-test-"));
  const envPath = path.join(directory, ".env");
  const previous = process.env.TELEGRAM_STRING_SESSION;
  t.after(async () => {
    if (previous === undefined) delete process.env.TELEGRAM_STRING_SESSION;
    else process.env.TELEGRAM_STRING_SESSION = previous;
    await rm(directory, { recursive: true, force: true });
  });
  await writeFile(envPath, "PORT=4000\nTELEGRAM_STRING_SESSION=old\n", "utf8");

  await persistEnvValue("TELEGRAM_STRING_SESSION", "persisted-session", { envPath });

  assert.equal(await readFile(envPath, "utf8"), "PORT=4000\nTELEGRAM_STRING_SESSION=persisted-session\n");
  assert.equal(process.env.TELEGRAM_STRING_SESSION, "persisted-session");
});
