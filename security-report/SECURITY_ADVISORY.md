# Security Advisory: AspectJ — 4 Unsafe Deserialization Sinks, Code Injection via aop.xml, XXE

## Summary

AspectJ contains 3 CRITICAL and 6 HIGH-severity vulnerabilities. The most severe are four independent `ObjectInputStream.readObject()` calls with no type filtering across the cache subsystem, structure model persistence, and class file attribute parsing (3 CRITICAL RCE). The aop.xml `<concrete-aspect>` element enables arbitrary static method invocation via classpath poisoning. Additionally, XXE mitigation in DocumentParser is incomplete with silently swallowed exceptions.

**Verified against:** AspectJ latest HEAD (7,143 Java source files)

---

## Finding 1: Unsafe Deserialization in SimpleCache (CRITICAL)

At `SimpleCache.java:169-171`, `ObjectInputStream.readObject()` reads `cache.idx` with zero filtering. Attacker who writes to cache directory → RCE via gadget chain.

## Finding 2: Unsafe Deserialization in AbstractIndexedFileCacheBacking (CRITICAL)

At `AbstractIndexedFileCacheBacking.java:131-132`, second independent `ObjectInputStream.readObject()` on `cache.idx`. Same cache directory → same RCE vector.

## Finding 3: Unsafe Deserialization in AsmManager Structure Model (CRITICAL)

At `AsmManager.java:252-256`, deserializes `.ajsym` files (compiler structure model) via unfiltered `ObjectInputStream`. Two objects deserialized from same stream. Compromised CI build cache → RCE.

## Finding 4: Path Traversal in Class Dump (HIGH)

At `WeavingAdaptor.java:672-695`, class names used to construct file paths without sanitization. `dir.mkdirs()` creates arbitrary directories, `FileOutputStream` writes bytecode. Class name `../../../etc/cron.d/exploit` → write-anywhere primitive.

## Finding 5: Path Traversal in SimpleCache writeToPath (HIGH)

At `SimpleCache.java:268-274`, cache key (from class name + CRC) concatenated to folder path without validation. Arbitrary file write via crafted class names.

## Finding 6: Arbitrary Code Injection via aop.xml concrete-aspect (HIGH)

At `ConcreteAspectCodeGen.java:791-925`, `<concrete-aspect>` elements accept `invokeClass` and `invokeMethod` specifying arbitrary static method. Any JAR on classpath can supply `META-INF/aop.xml` injecting method calls into woven application.

## Finding 7: Incomplete XXE Mitigation in DocumentParser (HIGH)

At `DocumentParser.java:132-158`, `external-general-entities=false` set but exceptions silently swallowed. `disallow-doctype-decl` never set. `LightXMLParser` has zero XXE protection.

## Finding 8: Unsafe Deserialization in ResolvedTypeMunger (HIGH)

At `ResolvedTypeMunger.java:214-219`, `ObjectInputStream` on class file attributes. Crafted `.class` file in dependency → RCE during weaving.

## Finding 9: WeavingURLClassLoader Arbitrary Class Loading from URLs (HIGH)

At `WeavingURLClassLoader.java:51-85`, class/aspect paths from system properties `aj.class.path` and `aj.aspect.path` without URL validation. Remote URLs accepted.

---

## Disclosure Timeline

- **2026-06-27:** Vulnerabilities discovered and verified in latest source
