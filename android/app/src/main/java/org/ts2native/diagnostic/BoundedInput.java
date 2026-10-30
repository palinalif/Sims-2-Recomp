package org.ts2native.diagnostic;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;

/** Stream actual bytes; never trust a document provider's declared size. */
final class BoundedInput {
    private BoundedInput() {}
    static byte[] read(InputStream stream,int limit) throws IOException {
        if(limit<0) throw new IllegalArgumentException("Negative stream limit");
        ByteArrayOutputStream out=new ByteArrayOutputStream(Math.min(limit,65536));
        byte[] buffer=new byte[65536];
        for(;;) {
            if(Thread.currentThread().isInterrupted()) throw new InterruptedIOException();
            int length=stream.read(buffer,0,(int)Math.min(buffer.length,(long)limit-out.size()+1));
            if(length<0) return out.toByteArray();
            if(length==0) {
                int next=stream.read();
                if(next<0) return out.toByteArray();
                buffer[0]=(byte)next;length=1;
            }
            if(length>limit-out.size()) throw new IOException("Stream exceeds configured byte budget");
            out.write(buffer,0,length);
        }
    }
}
