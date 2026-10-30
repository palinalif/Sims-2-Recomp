// Ghidra headless query script for the authorized private Legacy analysis image.
//
// Bounded, read-only, machine-readable inspection of ONE address: it emits a
// single JSON object to the file named by out=<path>. It never dumps the whole
// program, and this file itself contains no recovered bytes, strings or
// addresses from the image (the tool is versioned; its output is not).
//
// Invocation (see scripts/ghidra-query.sh):
//   analyzeHeadless <proj> <name> -process <program> -readOnly \
//     -scriptPath scripts/ghidra -postScript Sims2Query.java -- \
//     out=/abs/path.json rva=1070 maxInstructions=120 maxPseudoLines=40
//
// Keys: out (required) | rva | va | maxInstructions | maxRefs | maxCallers |
//       maxCallees | maxPseudoLines | decompileOnFail | includeInstructions
// Pseudocode is opt-in (maxPseudoLines > 0) and is a HYPOTHESIS, never a
// reconstruction oracle: compare against pinned pcrecomp / Unicorn evidence.
//
// Ghidra 12.2 API notes (verified with javap against the shipped jars):
//   Program.getImageBase()/getExecutableSHA256(), Function.getEntryPoint()/
//   getCallingFunctions(m)/getCalledFunctions(m) (no getBody()), Reference has
//   getFromAddress()/getToAddress()/getReferenceType()/getSource().
// Function extent is therefore derived by a CAPPED linear instruction walk and
// is labelled as such; basic-block flow recovery is not part of this schema.

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.util.task.TaskMonitor;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

public class Sims2Query extends GhidraScript {

  private static final String SCHEMA = "sims2-ghidra-query/1";
  private static final int HARD_CAP = 2000; // absolute ceiling per list

  private final StringBuilder json = new StringBuilder(1 << 16);
  private final java.util.List<String> warnings = new java.util.ArrayList<String>();

  private Program program;
  private Listing listing;
  private ReferenceManager refMgr;
  private long imageBase;
  private final Map<String, String> args = new HashMap<String, String>();

  // truncation flags, reported verbatim in the JSON envelope
  private boolean truncInstructions, truncRefs, truncCallers, truncCallees, truncPseudo,
      truncData;
  private int instrCount, refCount, callerCount, calleeCount;

  @Override
  public void run() throws Exception {
    for (String raw : getScriptArgs()) {
      if (raw == null) {
        continue;
      }
      int eq = raw.indexOf('=');
      if (eq > 0) {
        args.put(raw.substring(0, eq).trim(), raw.substring(eq + 1).trim());
      }
    }

    String out = args.get("out");
    if (out == null || out.length() == 0) {
      // Nothing else we can do: the caller is waiting on this file.
      System.out.println("Sims2Query: ERROR missing out=<path>");
      return;
    }

    try {
      program = getState().getCurrentProgram();
      if (program == null) {
        throw new IllegalStateException("no program bound to this script");
      }
      listing = program.getListing();
      refMgr = program.getReferenceManager();
      Address base = program.getImageBase();
      imageBase = base == null ? 0L : base.getOffset();
      emitProgram();
      emitQuery();
    } catch (Throwable t) {
      // Emit whatever we have plus the error so the caller never has to parse
      // a half-written object.
      json.setLength(0);
      append("{\"schema\":\"" + SCHEMA + "\",\"error\":");
      append(quote(t.getClass().getName() + ": " + t.getMessage()));
      append(",\"args\":");
      append(mapJson(args));
      append('}');
    } finally {
      writeOut(out);
    }
  }

  // ---------------------------------------------------------------- program

  private void emitProgram() throws IOException {
    append("{\"schema\":\"" + SCHEMA + "\"");
    append(",\"tool\":{\"name\":\"Ghidra\",\"version\":");
    String ghidraVersion;
    try {
      ghidraVersion = ghidra.framework.Application.getApplicationVersion();
    } catch (Throwable t) {
      ghidraVersion = null;
    }
    append(quote(ghidraVersion == null || ghidraVersion.isEmpty()
        ? "unknown"
        : ghidraVersion));
    append(",\"script\":\"Sims2Query.java\"}");

    append(",\"program\":{\"name\":");
    append(quote(program.getName()));
    append(",\"executableFormat\":");
    append(quote(program.getExecutableFormat()));
    append(",\"executableSha256\":");
    append(quote(program.getExecutableSHA256()));
    append(",\"executableMd5\":");
    append(quote(program.getExecutableMD5()));
    append(",\"languageId\":");
    append(quote(program.getLanguageID() == null ? null : program.getLanguageID().getIdAsString()));
    append(",\"compilerSpec\":");
    append(quote(program.getCompilerSpec() == null ? null
        : program.getCompilerSpec().getCompilerSpecID().getIdAsString()));
    append(",\"imageBaseVa\":\"" + hex(imageBase) + "\"");
    append(",\"addressSpace\":");
    append(quote(program.getAddressFactory().getDefaultAddressSpace().getName()));
    append(",\"functionCount\":").append(program.getFunctionManager().getFunctionCount());
    append(",\"maxFunctionsCapped\":false");
    append("}");
  }

  // ------------------------------------------------------------------ query

  private void emitQuery() throws Exception {
    String rvaArg = args.get("rva");
    String vaArg = args.get("va");
    if (rvaArg == null && vaArg == null) {
      throw new IllegalArgumentException("need rva=<hex> or va=<hex>");
    }
    long va;
    long rva;
    if (vaArg != null) {
      va = Long.parseUnsignedLong(vaArg.replace("0x", "").replace("0X", ""), 16);
      rva = va - imageBase;
    } else {
      rva = Long.parseUnsignedLong(rvaArg.replace("0x", "").replace("0X", ""), 16);
      va = imageBase + rva;
    }
    Address addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(va);

    append(",\"query\":{\"requested\":");
    append(quote(vaArg != null ? ("va=" + vaArg) : ("rva=" + rvaArg)));
    append(",\"va\":\"" + hex(va) + "\"");
    append(",\"rva\":\"" + hex(rva) + "\"");
    append(",\"addressSpace\":");
    append(quote(program.getAddressFactory().getDefaultAddressSpace().getName()));

    int maxInstr = limit("maxInstructions", 160);
    int maxRefs = limit("maxRefs", 60);
    int maxCallers = limit("maxCallers", 40);
    int maxCallees = limit("maxCallees", 60);
    int maxPseudo = limit("maxPseudoLines", 0);
    boolean includeInstr = !"false".equals(args.get("includeInstructions"));

    append(",\"limits\":");
    append("{\"maxInstructions\":" + maxInstr + ",\"maxRefs\":" + maxRefs + ",\"maxCallers\":"
        + maxCallers + ",\"maxCallees\":" + maxCallees + ",\"maxPseudoLines\":" + maxPseudo
        + ",\"hardCap\":" + HARD_CAP + "}");
    append("}");

    FunctionManager fm = program.getFunctionManager();
    Function fn = fm.getFunctionAt(addr);
    String resolution = "function-at";
    if (fn == null) {
      fn = fm.getFunctionContaining(addr);
      resolution = "function-containing";
    }
    if (fn == null) {
      resolution = "address-only";
    }

    // Data present at the queried address (data RVAs are first-class here).
    Data at = listing.getDataAt(addr);
    // Bounded raw bytes: read-only, and the only honest way to tell "no code
    // here" apart from "Ghidra left this executable region undecoded".
    append(",\"bytes32\":").append(quote(hexBytes(addr, 32)));
    append(",\"addressData\":");
    if (at == null) {
      append("null");
    } else {
      append("{\"dataType\":");
      append(quote(at.getDataType().getName()));
      append(",\"isStructure\":").append(at.isStructure());
      append(",\"isPointer\":").append(at.isPointer());
      append(",\"length\":").append(at.getLength());
      append(",\"value\":");
      append(quote(String.valueOf(at.getValue())));
      append("}");
    }

    append(",\"function\":");
    if (fn == null) {
      append("{\"resolution\":\"address-only\",\"entry\":null");
      emitRefsTo(addr, maxRefs, "referencesToAddress");
      // An unanalyzed region must stay inspectable: report what the memory says
      // and decode instructions linearly instead of silently returning nothing.
      boolean mapped = program.getMemory().contains(addr);
      boolean executable = mapped && program.getMemory().getExecuteSet().contains(addr);
      append(",\"mapped\":").append(mapped ? "true" : "false");
      append(",\"executable\":").append(executable ? "true" : "false");
      Function near = null;
      FunctionIterator backwards = fm.getFunctions(addr, false);
      if (backwards.hasNext()) {
        near = backwards.next();
      }
      if (near != null && near.getEntryPoint().compareTo(addr) < 0) {
        append(",\"nearestPrecedingFunction\":{\"name\":").append(quote(near.getName()));
        append(",\"entryVa\":\"" + hex(near.getEntryPoint().getOffset()) + "\"");
        append(",\"entryRva\":\"" + hex(near.getEntryPoint().getOffset() - imageBase) + "\"");
        append(",\"bytesBeforeTarget\":").append(addr.getOffset() - near.getEntryPoint().getOffset());
        append("}");
      } else {
        append(",\"nearestPrecedingFunction\":null");
      }
      append(",\"rawDisassemblyNote\":");
      append(quote("no function body analyzed here; instructions, if any, are a raw "
          + "linear decode and NOT a verified function boundary"));
      if (executable) {
        emitInstructions(addr, null, maxInstr == 0 ? 0 : Math.min(maxInstr, 32));
      }
      append(",\"note\":");
      append(quote("no function analyzed at this address; either data or an unanalyzed "
          + "code region - do not read absence of a function as absence of code"));
      append("}");
      emitTruncation();
      append("}");
      return;
    }

    append("{\"resolution\":").append(quote(resolution));
    Address entry = fn.getEntryPoint();
    append(",\"entryVa\":\"" + hex(entry.getOffset()) + "\"");
    append(",\"entryRva\":\"" + hex(entry.getOffset() - imageBase) + "\"");
    append(",\"name\":").append(quote(fn.getName()));
    append(",\"nameLooksAutoDerived\":").append(autoName(fn.getName()) ? "true" : "false");
    append(",\"source\":").append(quote(String.valueOf(fn.getSignatureSource())));
    append(",\"signature\":").append(quote(String.valueOf(fn.getSignature())));
    append(",\"external\":").append(fn.isExternal() ? "true" : "false");
    append(",\"thunk\":").append(fn.isThunk() ? "true" : "false");
    append(",\"noReturn\":").append(fn.hasNoReturn() ? "true" : "false");
    append(",\"callingConvention\":");
    append(quote(fn.getCallingConventionName()));
    if (fn.isThunk() && fn.getThunkedFunction(true) != null) {
      Function th = fn.getThunkedFunction(true);
      append(",\"thunkTarget\":");
      append("{\"name\":" + quote(th.getName()) + ",\"va\":\"" + hex(th.getEntryPoint().getOffset())
          + "\"}");
    }
    append(",\"parameters\":").append(fn.getParameterCount());
    append(",\"comment\":").append(quote(fn.getComment()));

    if (includeInstr) {
      emitInstructions(entry, fn, maxInstr);
    }

    emitRefsTo(entry, maxRefs, "referencesToEntry");
    emitCallers(fn, maxCallers);
    emitCallees(fn, maxCallees);
    if (maxPseudo > 0) {
      emitPseudocode(fn, maxPseudo);
    } else {
      append(",\"pseudocode\":{\"requested\":false");
      append(",\"note\":").append(quote("opt in with maxPseudoLines=N; pseudocode is a "
          + "hypothesis, not a reconstruction oracle"));
      append("}");
    }
    append("}"); // function
    emitTruncation();
    append("}"); // root
  }

  // ------------------------------------------------------------ sub-emitters

  private void emitInstructions(Address entry, Function fn, int max) {
    append(",\"disassembly\":{\"from\":\"" + hex(entry.getOffset()) + "\"");
    append(",\"extentMethod\":");
    append(quote("capped-linear-instruction-walk (Ghidra 12 Function has no getBody; "
        + "extent is a lower bound for non-contiguous bodies)"));
    append(",\"items\":[");
    Address cur = entry;
    int n = 0;
    long last = entry.getOffset();
    boolean first = true;
    while (cur != null) {
      Instruction ins = listing.getInstructionAt(cur);
      if (ins == null) {
        break;
      }
      if (n >= max) {
        // max == 0 means "not requested", which is not truncation.
        if (max > 0) {
          truncInstructions = true;
        }
        break;
      }
      if (n >= HARD_CAP) {
        truncInstructions = true;
        break;
      }
      if (fn != null) {
        Function owner = program.getFunctionManager().getFunctionContaining(cur);
        if (n > 0 && (owner == null || !owner.getEntryPoint().equals(fn.getEntryPoint()))) {
          break; // walked out of the function
        }
      }
      if (!first) {
        append(',');
      }
      first = false;
      last = cur.getOffset();
      append("{\"va\":\"" + hex(cur.getOffset()) + "\"");
      append(",\"rva\":\"" + hex(cur.getOffset() - imageBase) + "\"");
      append(",\"flow\":").append(quote(String.valueOf(ins.getFlowType())));
      append(",\"text\":").append(quote(ins.toString()));
      append("}");
      n++;
      instrCount = n;
      // Advance by instruction length (CodeUnit.getLength) rather than
      // getInstructionAfter(...).getAddress(): Ghidra 12 moved CodeUnit address
      // accessors, so this keeps the script compiling without guessing APIs.
      int len = ins.getLength();
      if (len <= 0) {
        break;
      }
      last = cur.getOffset() + len - 1;
      cur = cur.add(len);
    }
    append("],\"instructionCount\":").append(instrCount);
    append(",\"extentEndVa\":\"" + hex(last) + "\"");
    append(",\"extentBytes\":").append(instrCount == 0 ? 0 : (last - entry.getOffset() + 1));
    append("}");
  }

  private String hexBytes(Address addr, int count) {
    try {
      byte[] buf = new byte[count];
      int got = program.getMemory().getBytes(addr, buf);
      StringBuilder sb = new StringBuilder();
      for (int i = 0; i < got; i++) {
        if (i > 0) {
          sb.append(' ');
        }
        sb.append(String.format("%02x", buf[i] & 0xff));
      }
      return sb.toString();
    } catch (Throwable t) {
      return "unavailable: " + t.getClass().getSimpleName();
    }
  }

  private void emitRefsTo(Address addr, int max, String key) {
    append(",\"" + key + "\":[");
    int n = 0;
    boolean first = true;
    for (Reference r : refMgr.getReferencesTo(addr)) {
      if (n >= max || n >= HARD_CAP) {
        truncRefs = true;
        break;
      }
      if (!first) {
        append(',');
      }
      first = false;
      Address from = r.getFromAddress();
      append("{\"fromVa\":\"" + hex(from.getOffset()) + "\"");
      append(",\"fromRva\":\"" + hex(from.getOffset() - imageBase) + "\"");
      append(",\"type\":").append(quote(String.valueOf(r.getReferenceType())));
      append(",\"source\":").append(quote(String.valueOf(r.getSource())));
      append(",\"primary\":").append(r.isPrimary() ? "true" : "false");
      append(",\"external\":").append(r.isExternalReference() ? "true" : "false");
      // vtable / structure evidence: is the referring site defined data?
      Data origin = listing.getDataAt(from);
      if (origin != null) {
        DataType dt = origin.getDataType();
        append(",\"originIsData\":true");
        append(",\"originDataType\":").append(quote(dt == null ? null : dt.getName()));
        append(",\"originIsStructure\":").append(origin.isStructure() ? "true" : "false");
        truncData = truncData || origin.isStructure();
      } else {
        Instruction oi = listing.getInstructionAt(from);
        append(",\"originIsData\":").append(oi == null ? "true" : "false");
      }
      append("}");
      n++;
      refCount = n;
    }
    append("]");
  }

  private void emitCallers(Function fn, int max) {
    append(",\"callers\":[");
    int n = 0;
    boolean first = true;
    try {
      Set<Function> set = fn.getCallingFunctions(TaskMonitor.DUMMY);
      for (Function c : set) {
        if (n >= max || n >= HARD_CAP) {
          truncCallers = true;
          break;
        }
        if (!first) {
          append(',');
        }
        first = false;
        append("{\"name\":").append(quote(c.getName()));
        append(",\"va\":\"" + hex(c.getEntryPoint().getOffset()) + "\"");
        append(",\"rva\":\"" + hex(c.getEntryPoint().getOffset() - imageBase) + "\"");
        append(",\"nameLooksAutoDerived\":").append(autoName(c.getName()) ? "true" : "false");
        append("}");
        n++;
        callerCount = n;
      }
    } catch (Exception e) {
      warn("callers: " + e);
    }
    append("],\"callerTotal\":").append(callerCount);
    append(",\"callersTruncated\":").append(truncCallers ? "true" : "false");
  }

  private void emitCallees(Function fn, int max) {
    append(",\"callees\":[");
    int n = 0;
    boolean first = true;
    try {
      Set<Function> set = fn.getCalledFunctions(TaskMonitor.DUMMY);
      for (Function c : set) {
        if (n >= max || n >= HARD_CAP) {
          truncCallees = true;
          break;
        }
        if (!first) {
          append(',');
        }
        first = false;
        append("{\"name\":").append(quote(c.getName()));
        append(",\"va\":");
        if (c.isExternal()) {
          append("null");
        } else {
          append("\"" + hex(c.getEntryPoint().getOffset()) + "\"");
        }
        append(",\"rva\":");
        if (c.isExternal()) {
          append("null");
        } else {
          append("\"" + hex(c.getEntryPoint().getOffset() - imageBase) + "\"");
        }
        append(",\"external\":").append(c.isExternal() ? "true" : "false");
        append(",\"thunk\":").append(c.isThunk() ? "true" : "false");
        append(",\"externalEntryPoint\":");
        if (c.isExternal() && c.getThunkedFunction(true) != null) {
          Function th = c.getThunkedFunction(true);
          append("{\"name\":" + quote(th.getName()) + ",\"va\":\""
              + hex(th.getEntryPoint().getOffset()) + "\"}");
        } else {
          append("null");
        }
        append("}");
        n++;
        calleeCount = n;
      }
    } catch (Exception e) {
      warn("callees: " + e);
    }
    append("],\"calleeTotal\":").append(calleeCount);
    append(",\"calleesTruncated\":").append(truncCallees ? "true" : "false");
  }

  private void emitPseudocode(Function fn, int maxLines) {
    append(",\"pseudocode\":{\"requested\":true,\"lineLimit\":").append(maxLines);
    DecompInterface dec = null;
    try {
      dec = new DecompInterface();
      if (!dec.openProgram(program)) {
        append(",\"error\":").append(quote("openProgram failed"));
      } else {
        DecompileResults res = dec.decompileFunction(fn, 120, null);
        if (!res.decompileCompleted()) {
          append(",\"error\":").append(quote("decompileCompleted=false: " + res.getErrorMessage()));
        } else if (res.getDecompiledFunction() == null) {
          append(",\"error\":").append(quote("no DecompiledFunction"));
        } else {
          String c = res.getDecompiledFunction().getC();
          String[] lines = c.split("\n", -1);
          append(",\"totalLines\":").append(lines.length);
          append(",\"c\":");
          int keep = Math.min(lines.length, Math.min(maxLines, HARD_CAP));
          StringBuilder sb = new StringBuilder();
          for (int i = 0; i < keep; i++) {
            if (i > 0) {
              sb.append('\n');
            }
            sb.append(lines[i]);
          }
          append(quote(sb.toString()));
          truncPseudo = lines.length > keep;
          append(",\"status\":\"excerpt\"");
          append(",\"interpretation\":");
          append(quote("HYPOTHESIS only; reconcile with pinned pcrecomp and Unicorn evidence"));
        }
      }
    } catch (Throwable t) {
      append(",\"error\":").append(quote(String.valueOf(t)));
    } finally {
      append("}");
    }
  }

  private void emitTruncation() {
    append(",\"truncation\":{\"instructions\":").append(truncInstructions ? "true" : "false");
    append(",\"references\":").append(truncRefs ? "true" : "false");
    append(",\"callers\":").append(truncCallers ? "true" : "false");
    append(",\"callees\":").append(truncCallees ? "true" : "false");
    append(",\"pseudocode\":").append(truncPseudo ? "true" : "false");
    append(",\"structureRefsSeen\":").append(truncData ? "true" : "false");
    append(",\"counts\":{\"instructions\":").append(instrCount);
    append(",\"references\":").append(refCount);
    append(",\"callers\":").append(callerCount);
    append(",\"callees\":").append(calleeCount);
    append("}}");
    if (!warnings.isEmpty()) {
      append(",\"warnings\":[");
      for (int i = 0; i < warnings.size(); i++) {
        if (i > 0) {
          append(',');
        }
        append(quote(warnings.get(i)));
      }
      append("]");
    }
  }

  // ----------------------------------------------------------------- helpers

  private int limit(String key, int dflt) {
    String v = args.get(key);
    if (v == null) {
      return dflt;
    }
    try {
      int n = Integer.parseInt(v);
      if (n < 0) {
        return 0;
      }
      return Math.min(n, HARD_CAP);
    } catch (NumberFormatException e) {
      warn("bad " + key + "=" + v + ", using " + dflt);
      return dflt;
    }
  }

  private void warn(String msg) {
    warnings.add(msg);
  }

  private static String hex(long v) {
    return "0x" + Long.toHexString(v);
  }

  /**
   * Ghidra 12 has no Function.isDefaultName(); classify IDEAUTO-style names by shape and
   * report the result under an explicitly heuristic key instead of implying certainty.
   */
  private static boolean autoName(String name) {
    return name != null && name.matches("(?i)^(FUN|thunk|lambda|stub|caseentry)_[0-9a-f]+.*");
  }

  private StringBuilder append(String s) {
    json.append(s);
    return json;
  }

  private StringBuilder append(char c) {
    json.append(c);
    return json;
  }

  private static String quote(String s) {
    if (s == null) {
      return "null";
    }
    StringBuilder sb = new StringBuilder(s.length() + 16);
    sb.append('"');
    for (int i = 0; i < s.length(); i++) {
      char c = s.charAt(i);
      switch (c) {
        case '"':
          sb.append("\\\"");
          break;
        case '\\':
          sb.append("\\\\");
          break;
        case '\n':
          sb.append("\\n");
          break;
        case '\r':
          sb.append("\\r");
          break;
        case '\t':
          sb.append("\\t");
          break;
        default:
          if (c < 0x20) {
            sb.append(String.format("\\u%04x", (int) c));
          } else {
            sb.append(c);
          }
      }
    }
    sb.append('"');
    return sb.toString();
  }

  private static String mapJson(Map<String, String> m) {
    StringBuilder sb = new StringBuilder("{");
    boolean first = true;
    for (Map.Entry<String, String> e : m.entrySet()) {
      if (!first) {
        sb.append(',');
      }
      first = false;
      sb.append(quote(e.getKey())).append(':').append(quote(e.getValue()));
    }
    sb.append('}');
    return sb.toString();
  }

  private void writeOut(String path) {
    BufferedWriter w = null;
    try {
      w = new BufferedWriter(new FileWriter(path));
      w.write(json.toString());
      w.write("\n");
      System.out.println("Sims2Query: wrote " + path + " (" + json.length() + " chars)");
    } catch (IOException e) {
      System.out.println("Sims2Query: ERROR cannot write " + path + ": " + e);
    } finally {
      if (w != null) {
        try {
          w.close();
        } catch (IOException ignored) {
          // nothing useful left to do
        }
      }
    }
  }
}
