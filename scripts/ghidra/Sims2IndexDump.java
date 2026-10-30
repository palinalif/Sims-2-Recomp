// One-pass, resumable whole-image function index for the private Legacy
// analysis project. Emits JSON Lines (one function per line) so workers can
// grep a local index instead of paying a headless JVM start per query.
//
// Run ONLY through scripts/ghidra-index-dump.sh, which points this at a
// disposable COPY of the project; the original stays untouched and lock-free.
//
// Args (key=value):
//   out=<dir>             output directory (created)            [required]
//   decompile=1|0         include pseudocode (default 1)
//   maxPseudoLines=N      per-function pseudocode cap (default 600)
//   start=<hexVa>         override resume cursor (default: cursor.txt)
//
// Output files:
//   <out>/functions.jsonl   append-only records, one per function
//   <out>/cursor.txt        last fully-written entry VA (resume point)
//   <out>/done.txt          written only on clean completion
//
// Contract inherited from GHIDRA_WORKFLOW.md: pseudocode and auto names are
// hypotheses; nothing here is a reconstruction oracle. Read-only by design.

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Iterator;
import java.util.List;

public class Sims2IndexDump extends GhidraScript {

  private static final int CALLER_CAP = 64;
  private static final int CALLEE_CAP = 64;
  private static final int SIZE_WALK_CAP = 6000; // instructions walked per function body
  private static final int DECOMPILE_TIMEOUT_S = 60;

  private BufferedWriter out;
  private long imageBase;
  private long cursor;
  private String cursorPath;
  private int written;
  private int skipped;

  @Override
  public void run() throws Exception {
    Program program = currentProgram;
    TaskMonitor mon = getMonitor();
    imageBase = program.getImageBase() == null ? 0L : program.getImageBase().getOffset();

    String outDir = getScriptArg("out", null);
    if (outDir == null || outDir.isEmpty()) {
      println("INDEXDUMP: out=<dir> is required; nothing done");
      return;
    }
    boolean decompile = !"0".equals(getScriptArg("decompile", "1"));
    int maxPseudo = Integer.parseInt(getScriptArg("maxPseudoLines", "600"));

    File dir = new File(outDir);
    if (!dir.isDirectory() && !dir.mkdirs()) {
      throw new IOException("cannot create out dir " + outDir);
    }
    cursorPath = outDir + File.separator + "cursor.txt";
    String start = getScriptArg("start", null);
    if (start != null) {
      cursor = Long.parseUnsignedLong(start.replace("0x", ""), 16);
    } else if (new File(cursorPath).isFile()) {
      String txt = new String(java.nio.file.Files.readAllBytes(new File(cursorPath).toPath())).trim();
      cursor = Long.parseUnsignedLong(txt.replace("0x", ""), 16);
      // Resume strictly after the cursor record.
      cursor -= 1;
    }
    new File(outDir, "done.txt").delete();

    // Collect and sort entry points so cursor resume is deterministic.
    List<Function> fns = new ArrayList<>();
    FunctionIterator it = program.getFunctionManager().getFunctions(true);
    while (it.hasNext()) {
      Function f = it.next();
      if (!f.isExternal()) {
        fns.add(f);
      }
    }
    Collections.sort(fns, new Comparator<Function>() {
      public int compare(Function a, Function b) {
        return Long.compareUnsigned(a.getEntryPoint().getOffset(), b.getEntryPoint().getOffset());
      }
    });
    printf("INDEXDUMP: %d internal functions, resume cursor=%s, decompile=%b%n",
        fns.size(), hex(cursor), decompile);

    out = new BufferedWriter(new FileWriter(outDir + File.separator + "functions.jsonl", true));
    // Append mode: a hard crash can leave at most one partial line; the cursor
    // rewrites that function, so consumers take the LAST record per rva.
    out.flush();

    DecompInterface dec = null;
    if (decompile) {
      dec = new DecompInterface();
      dec.openProgram(program);
    }

    long lastCursorWrite = System.currentTimeMillis();
    for (Function f : fns) {
      if (mon.isCancelled()) {
        break;
      }
      long entryVa = f.getEntryPoint().getOffset();
      if (Long.compareUnsigned(entryVa, cursor) <= 0) {
        skipped++;
        continue;
      }
      String line = render(f, dec, maxPseudo);
      out.write(line);
      out.write("\n");
      out.flush(); // record-level flush; a crash costs at most one function
      cursor = entryVa;
      written++;
      if (written % 25 == 0) {
        writeCursor();
      }
      if (written % 500 == 0) {
        printf("INDEXDUMP: written=%d skipped=%d at %s%n", written, skipped, hex(entryVa));
      }
      if (System.currentTimeMillis() - lastCursorWrite > 300_000L) {
        writeCursor();
        lastCursorWrite = System.currentTimeMillis();
      }
    }

    out.flush();
    writeCursor();
    out.close();
    if (dec != null) {
      dec.dispose();
    }
    java.nio.file.Files.write(new File(outDir, "done.txt").toPath(),
        ("written=" + written + " skipped=" + skipped + "\n").getBytes());
    printf("INDEXDUMP: DONE written=%d skipped=%d%n", written, skipped);
  }

  private void writeCursor() throws IOException {
    java.nio.file.Files.write(new File(cursorPath).toPath(),
        Long.toHexString(cursor).getBytes());
  }

  private String render(Function f, DecompInterface dec, int maxPseudo) {
    StringBuilder s = new StringBuilder(1024);
    long entryVa = f.getEntryPoint().getOffset();
    long entryRva = entryVa - imageBase;
    Listing listing = currentProgram.getListing();
    s.append("{\"rva\":\"").append(hex(entryRva))
        .append("\",\"va\":\"").append(hex(entryVa))
        .append("\",\"name\":").append(quote(f.getName()))
        .append(",\"autoNamed\":").append(isAutoName(f.getName()) ? "true" : "false")
        .append(",\"thunk\":").append(f.isThunk() ? "true" : "false");
    if (f.isThunk() && f.getThunkedFunction(true) != null) {
      Function th = f.getThunkedFunction(true);
      s.append(",\"thunkTargetRva\":\"").append(hex(th.getEntryPoint().getOffset() - imageBase))
          .append("\"");
    }
    s.append(",\"sig\":").append(quote(String.valueOf(f.getSignature())))
        .append(",\"cc\":").append(quote(f.getCallingConventionName()))
        .append(",\"params\":").append(f.getParameterCount())
        .append(",\"noReturn\":").append(f.hasNoReturn() ? "true" : "false")
        .append(",\"comment\":").append(quote(f.getComment()));

    // Body size by capped linear walk (same lower-bound semantics as Sims2Query).
    long bytes = -1;
    Instruction ins = listing.getInstructionAt(f.getEntryPoint());
    long first = entryVa;
    long last = entryVa;
    int n = 0;
    while (ins != null && n < SIZE_WALK_CAP) {
      last = ins.getMinAddress().getOffset();
      Instruction nxt = listing.getInstructionAfter(ins.getMaxAddress());
      if (nxt == null) {
        break;
      }
      Function owner = currentProgram.getFunctionManager().getFunctionContaining(nxt.getMinAddress());
      if (owner == null || !owner.getEntryPoint().equals(f.getEntryPoint())) {
        break;
      }
      ins = nxt;
      n++;
    }
    if (n >= 0 && last >= first) {
      bytes = last - first + 1;
    }
    s.append(",\"sizeBytes\":").append(bytes).append(",\"instrWalked\":").append(n + 1);

    emitTargets(s, "callees", f.getCalledFunctions(monitor), CALLEE_CAP);
    long callerTotal = 0;
    Iterator<Function> callers = f.getCallingFunctions(monitor).iterator();
    s.append(",\"callers\":[");
    boolean firstCaller = true;
    while (callers.hasNext()) {
      Function c = callers.next();
      callerTotal++;
      if (callerTotal <= CALLER_CAP) {
        if (!firstCaller) {
          s.append(',');
        }
        firstCaller = false;
        s.append("{\"rva\":\"").append(hex(c.getEntryPoint().getOffset() - imageBase))
            .append("\",\"name\":").append(quote(c.getName())).append('}');
      }
    }
    s.append("],\"callerTotal\":").append(callerTotal);

    if (dec != null) {
      try {
        DecompileResults res = dec.decompileFunction(f, DECOMPILE_TIMEOUT_S * 1000, monitor);
        if (res != null && res.decompileCompleted() && res.getDecompiledFunction() != null) {
          String c = res.getDecompiledFunction().getC();
          int lines = 0;
          boolean trunc = false;
          if (c != null) {
            String[] ls = c.split("\n", -1);
            lines = ls.length;
            if (lines > maxPseudo) {
              StringBuilder jb = new StringBuilder();
              for (int i = 0; i < maxPseudo; i++) {
                jb.append(ls[i]).append('\n');
              }
              c = jb.toString();
              trunc = true;
              lines = maxPseudo;
            }
          }
          s.append(",\"pseudo\":").append(quote(c == null ? "" : c))
              .append(",\"pseudoLines\":").append(lines)
              .append(",\"pseudoTruncated\":").append(trunc ? "true" : "false");
        } else {
          s.append(",\"decompileError\":")
              .append(quote(res == null ? "null" : String.valueOf(res.getErrorMessage())));
        }
      } catch (Exception e) {
        s.append(",\"decompileError\":").append(quote(String.valueOf(e.getMessage())));
      }
    }
    s.append('}');
    return s.toString();
  }

  private void emitTargets(StringBuilder s, String key, java.util.Collection<Function> targetSet,
      int cap) {
    s.append(",\"").append(key).append("\":[");
    boolean first = true;
    int n = 0;
    for (Function t : targetSet) {
      if (n >= cap) {
        s.append(",\"_truncated\":true");
        break;
      }
      if (!first) {
        s.append(',');
      }
      first = false;
      n++;
      s.append("{\"rva\":\"").append(hex(t.getEntryPoint().getOffset() - imageBase))
          .append("\",\"name\":").append(quote(t.getName())).append('}');
    }
    s.append(']');
  }

  private static boolean isAutoName(String name) {
    return name != null && name.matches("(?i)^(FUN|thunk|lambda|stub|caseentry)_[0-9a-f]+.*");
  }

  private static String hex(long v) {
    return "0x" + Long.toHexString(v).toUpperCase();
  }

  private static String quote(String v) {
    if (v == null) {
      return "null";
    }
    StringBuilder b = new StringBuilder(v.length() + 16);
    b.append('"');
    for (int i = 0; i < v.length(); i++) {
      char c = v.charAt(i);
      switch (c) {
        case '"': b.append("\\\""); break;
        case '\\': b.append("\\\\"); break;
        case '\n': b.append("\\n"); break;
        case '\r': b.append("\\r"); break;
        case '\t': b.append("\\t"); break;
        default:
          if (c < 0x20) {
            b.append(String.format("\\u%04x", (int) c));
          } else {
            b.append(c);
          }
      }
    }
    b.append('"');
    return b.toString();
  }

  private String getScriptArg(String key, String dflt) {
    String[] args = getScriptArgs();
    if (args != null) {
      for (String a : args) {
        if (a.startsWith(key + "=")) {
          return a.substring(key.length() + 1);
        }
      }
    }
    return dflt;
  }
}
