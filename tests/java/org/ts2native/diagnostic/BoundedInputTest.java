package org.ts2native.diagnostic;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;

public final class BoundedInputTest {
    private static int checks;
    private static void check(boolean result) {
        checks++;if(!result) throw new AssertionError("Bounded stream check failed");
    }
    private static void rejects(InputStream stream,int budget) throws Exception {
        boolean rejected=false;
        try { BoundedInput.read(stream,budget); } catch(IOException e) { rejected=true; }
        check(rejected);
    }
    public static void main(String[] args) throws Exception {
        byte[] bytes={1,2,3,4};
        check(Arrays.equals(BoundedInput.read(new ByteArrayInputStream(bytes),4),bytes));
        check(BoundedInput.read(new ByteArrayInputStream(new byte[0]),0).length==0);
        rejects(new ByteArrayInputStream(bytes),3);
        rejects(new ByteArrayInputStream(bytes),0);
        check(Arrays.equals(BoundedInput.read(new ByteArrayInputStream(bytes) {
            @Override public synchronized int read(byte[] b,int off,int len) { return super.read(b,off,Math.min(len,1)); }
        },4),bytes));
        check(Arrays.equals(BoundedInput.read(new ByteArrayInputStream(bytes) {
            boolean first=true;
            @Override public synchronized int read(byte[] b,int off,int len) {
                if(first) { first=false;return 0; }return super.read(b,off,len);
            }
        },4),bytes));
        rejects(new InputStream() { @Override public int read() throws IOException { throw new IOException("provider failed"); } },4);
        Thread.currentThread().interrupt();
        rejects(new ByteArrayInputStream(bytes),4);
        check(Thread.interrupted());
        System.out.println("PASS "+checks+" Java bounded stream checks");
    }
}
