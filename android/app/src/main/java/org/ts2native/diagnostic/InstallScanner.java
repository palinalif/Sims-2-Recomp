package org.ts2native.diagnostic;

import android.content.Context;
import android.database.Cursor;
import android.net.Uri;
import android.provider.DocumentsContract;
import org.json.JSONArray;
import org.json.JSONObject;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayDeque;
import java.util.HashSet;
import java.util.Locale;

/** Bounded, read-only SAF inventory. It never translates URIs into guessed paths. */
final class InstallScanner {
    private static final long MAX_EXE=256L*1024*1024;
    private static final long MAX_TOTAL=1024L*1024*1024;
    private InstallScanner() {}
    static String scan(Context context,Uri tree) throws Exception {
        ArrayDeque<String> pending=new ArrayDeque<>();HashSet<String> visited=new HashSet<>();
        pending.add(DocumentsContract.getTreeDocumentId(tree));
        JSONArray executables=new JSONArray();int entries=0,packages=0;long total=0;boolean limited=false;
        while(!pending.isEmpty() && !limited) {
            if(Thread.currentThread().isInterrupted()) throw new java.io.InterruptedIOException();
            String id=pending.remove();if(!visited.add(id)) continue;
            Uri children=DocumentsContract.buildChildDocumentsUriUsingTree(tree,id);
            try(Cursor cursor=context.getContentResolver().query(children,new String[]{
                    DocumentsContract.Document.COLUMN_DOCUMENT_ID,DocumentsContract.Document.COLUMN_DISPLAY_NAME,
                    DocumentsContract.Document.COLUMN_MIME_TYPE,DocumentsContract.Document.COLUMN_SIZE},null,null,null)) {
                if(cursor==null) throw new java.io.IOException("Provider returned no listing");
                while(cursor.moveToNext()) {
                    if(++entries>50000) {limited=true;break;}
                    String child=cursor.getString(0),name=cursor.getString(1),mime=cursor.getString(2);
                    if(DocumentsContract.Document.MIME_TYPE_DIR.equals(mime)) {pending.add(child);continue;}
                    if(name==null) continue;
                    String lower=name.toLowerCase(Locale.ROOT);
                    if(lower.endsWith(".package")) packages++;
                    if(!lower.startsWith("sims2") || !lower.endsWith(".exe")) continue;
                    if(executables.length()>=64 || total>=MAX_TOTAL) {limited=true;break;}
                    long declared=cursor.isNull(3)?-1:cursor.getLong(3);
                    if(declared>MAX_EXE) {executables.put(new JSONObject().put("name",name).put("error","Executable exceeds inspection budget"));continue;}
                    Uri file=DocumentsContract.buildDocumentUriUsingTree(tree,child);
                    MessageDigest hash=MessageDigest.getInstance("SHA-256");byte[] header=new byte[65536];int headerSize=0;long bytes=0;
                    try(InputStream stream=context.getContentResolver().openInputStream(file)) {
                        if(stream==null) throw new java.io.IOException("Provider returned no stream");
                        byte[] buffer=new byte[65536];int n;
                        while((n=stream.read(buffer))!=-1) {
                            if(Thread.currentThread().isInterrupted()) throw new java.io.InterruptedIOException();
                            bytes+=n;total+=n;if(bytes>MAX_EXE || total>MAX_TOTAL) throw new java.io.IOException("Scan byte budget exceeded");
                            hash.update(buffer,0,n);int copy=Math.min(n,header.length-headerSize);
                            if(copy>0) {System.arraycopy(buffer,0,header,headerSize,copy);headerSize+=copy;}
                        }
                    }
                    StringBuilder digest=new StringBuilder();for(byte b:hash.digest()) digest.append(String.format(Locale.ROOT,"%02x",b&255));
                    JSONObject report=new JSONObject().put("name",name).put("bytes",bytes).put("sha256",digest)
                            .put("status","unknown").put("execution_supported",false);
                    ByteBuffer pe=ByteBuffer.wrap(header).order(ByteOrder.LITTLE_ENDIAN);
                    boolean valid=false;
                    if(headerSize>=64 && pe.getShort(0)==0x5a4d) {
                        long offset=Integer.toUnsignedLong(pe.getInt(0x3c));
                        if(offset<=headerSize-26 && pe.getInt((int)offset)==0x00004550) {
                            int machine=Short.toUnsignedInt(pe.getShort((int)offset+4));
                            report.put("machine",machine==0x14c?"x86":machine==0x8664?"x86_64":"other");
                            report.put("pe_magic",Short.toUnsignedInt(pe.getShort((int)offset+24)));valid=true;
                        }
                    }
                    if(!valid) report.put("error","PE header invalid or beyond 64 KiB inspection window");
                    executables.put(report);
                }
            }
        }
        JSONObject report=new JSONObject().put("schema",1).put("entries_scanned",entries).put("package_count",packages)
            .put("truncated",limited).put("executables",executables).put("execution_supported",false);
        // Private diagnostic output only. No original asset or save is written.
        try(OutputStream out=context.openFileOutput("installation-report.json",Context.MODE_PRIVATE)) {
            out.write(report.toString(2).getBytes(StandardCharsets.UTF_8));
        }
        return executables.length()+" executable(s), "+packages+" packages"+(limited?" · scan limited":"")+" · Unknown builds; execution disabled";
    }
}
