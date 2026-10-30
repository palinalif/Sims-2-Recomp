package org.ts2native.diagnostic;

import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.net.Uri;
import org.json.JSONObject;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Locale;

/** One small user-selected package through the portable native reader. No asset writes. */
final class PackageInspector {
    private static native byte[][] nativeProbe(byte[] bytes);
    static final class Result {
        final String summary;
        final Bitmap preview;
        Result(String summary,Bitmap preview) { this.summary=summary;this.preview=preview; }
    }
    private PackageInspector() {}
    static Result inspect(Context context,Uri uri) throws Exception {
        byte[] bytes;
        try(InputStream input=context.getContentResolver().openInputStream(uri)) {
            if(input==null) throw new IOException("Provider returned no stream");
            bytes=BoundedInput.read(input,16*1024*1024);
        }
        byte[][] output=nativeProbe(bytes);
        if(output==null || output.length!=2) throw new IOException("Native package probe returned no result");
        JSONObject report=new JSONObject(new String(output[0],StandardCharsets.UTF_8));
        StringBuilder digest=new StringBuilder();
        for(byte b:MessageDigest.getInstance("SHA-256").digest(output[1]))
            digest.append(String.format(Locale.ROOT,"%02x",b&255));
        report.put("payload_sha256",digest.toString());
        // Report only; the package and decoded proprietary payload are never written.
        try(OutputStream file=context.openFileOutput("package-report.json",Context.MODE_PRIVATE)) {
            file.write(report.toString(2).getBytes(StandardCharsets.UTF_8));
        }
        Bitmap preview=null;
        byte[] payload=output[1];
        if(payload.length>=8 && payload[0]==(byte)0x89 && payload[1]=='P' && payload[2]=='N' && payload[3]=='G') {
            BitmapFactory.Options bounds=new BitmapFactory.Options();bounds.inJustDecodeBounds=true;
            BitmapFactory.decodeByteArray(payload,0,payload.length,bounds);
            if(bounds.outWidth>0 && bounds.outHeight>0 && bounds.outWidth<=2048 && bounds.outHeight<=2048) {
                preview=BitmapFactory.decodeByteArray(payload,0,payload.length);
            }
        }
        JSONObject selected=report.getJSONObject("selected");
        String summary=report.getInt("entry_count")+" resources · "+report.getInt("compressed_count")+" compressed\n"
            +"Selected "+selected.getString("type")+":"+selected.getString("group")+":"+selected.getString("instance")
            +"\nDecoded "+payload.length+" bytes\nSHA-256 "+digest;
        return new Result(summary,preview);
    }
}
