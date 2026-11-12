import { mkdtemp, readFile, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import AdmZip from "adm-zip";
import { afterEach, describe, expect, it } from "vitest";
import { safelyUnpackVsixExtensionEntries } from "./verify-extension.js";

// Red-team self-test coverage (blueprint section 15, category 7: "manipulierte Archive,
// doppelte Dateinamen und Symlinks") for the one place in this codebase that writes files to
// disk directly from zip entry names: the .vsix unpacking step the extension format's runtime
// check depends on. This is tested directly against a hand-crafted malicious zip rather than one
// produced by @vscode/vsce, because the real packaging pipeline never produces a traversal entry
// today -- the point of this test is that the *unpacking* code refuses one anyway, in case a
// future bug upstream of it ever produces one.

const tempDirs: string[] = [];
async function freshDir(): Promise<string> {
  const dir = await mkdtemp(path.join(tmpdir(), "forge-vsix-unpack-test-"));
  tempDirs.push(dir);
  return dir;
}
afterEach(async () => {
  await Promise.all(tempDirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

describe("safelyUnpackVsixExtensionEntries", () => {
  it("writes a well-formed extension/ entry as a plain file inside the destination directory", async () => {
    const zip = new AdmZip();
    zip.addFile("extension/package.json", Buffer.from('{"name":"x"}'));
    const destDir = await freshDir();

    const result = await safelyUnpackVsixExtensionEntries(zip, destDir);
    expect(result.ok).toBe(true);
    expect(await readFile(path.join(destDir, "package.json"), "utf-8")).toBe('{"name":"x"}');
  });

  it("refuses a zip-slip entry name that tries to escape the destination directory via '..'", async () => {
    const zip = new AdmZip();
    // adm-zip's own writer normalizes ".." out of entry names on write (see
    // src/core/policy/policy.test.ts for the same observation), so the malicious entry is
    // appended directly to the zip's raw central directory after writing, bypassing that
    // normalization -- exactly what a hand-crafted malicious archive would do.
    zip.addFile("extension/package.json", Buffer.from('{"name":"x"}'));
    const buffer = zip.toBuffer();
    const reopened = new AdmZip(buffer);
    const traversalEntry = reopened.getEntries()[0];
    if (!traversalEntry) {
      throw new Error("test setup failed: no entry in freshly-built zip");
    }
    // Force the in-memory entry name to a traversal path directly, simulating what a
    // byte-crafted malicious zip (built without adm-zip's own writer) would present on read.
    Object.defineProperty(traversalEntry, "entryName", { value: "extension/../../etc/forge-zip-slip-poc", writable: true });

    const destDir = await freshDir();
    const result = await safelyUnpackVsixExtensionEntries(reopened, destDir);

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toMatch(/unsafe vsix entry name/);
    }
    // Nothing was written anywhere, inside or outside destDir, for this entry.
    expect(await readdir(destDir)).toEqual([]);
  });

  it("never recreates a symlink-flagged entry as an actual symlink -- it writes the raw bytes as a plain file", async () => {
    const zip = new AdmZip();
    // The entry's *content* is a symlink target string, mimicking what a naive extractor would
    // use to recreate a real symlink via fs.symlink(). safelyUnpackVsixExtensionEntries must
    // never do that -- it only ever calls writeFile with the entry's raw bytes.
    zip.addFile("extension/suspicious-link", Buffer.from("/etc/passwd"));
    const destDir = await freshDir();

    const result = await safelyUnpackVsixExtensionEntries(zip, destDir);
    expect(result.ok).toBe(true);

    const written = path.join(destDir, "suspicious-link");
    const { lstat } = await import("node:fs/promises");
    const stats = await lstat(written);
    expect(stats.isSymbolicLink()).toBe(false);
    expect(stats.isFile()).toBe(true);
    expect(await readFile(written, "utf-8")).toBe("/etc/passwd");
  });
});
