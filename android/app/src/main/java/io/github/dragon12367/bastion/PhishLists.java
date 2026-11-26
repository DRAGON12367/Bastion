package io.github.dragon12367.bastion;

import android.content.Context;
import android.net.ConnectivityManager;

import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.BufferedOutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Scanner;
import java.util.Set;

/** The phishing-site lists, kept on the phone. The big list (~400,000 sites) is only downloaded on Wi-Fi or another unmetered connection. */
public final class PhishLists implements Links.Lists {
    static final String BIG = "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-domains-ACTIVE.txt";
    static final String LIVE = "https://openphish.com/feed.txt";
    static final long DAY = 86_400_000L;

    private final Context ctx;
    private long[] big;
    private Set<String> live = new HashSet<>();

    public PhishLists(Context c) {
        ctx = c.getApplicationContext();
        load();
    }

    private File file(String name) { return new File(ctx.getFilesDir(), name); }

    public int size() { return (big == null ? 0 : big.length) + live.size(); }

    @Override
    public String badSite(String host) {
        if (live.contains(host)) return "live phishing list (OpenPhish)";
        if (Links.contains(big, host)) return "phishing site list (Phishing.Database)";
        return null;
    }

    /** Refreshes the lists that are out of date. Never raises; returns a short note for the screen. */
    public synchronized String refresh(boolean force) {
        StringBuilder note = new StringBuilder();
        try {
            if (force || age("phish-live.txt") > 6 * 3_600_000L) {
                byte[] d = get(LIVE, 2_000_000);
                write("phish-live.txt", d);
            }
        } catch (Exception e) { note.append("Live phishing list could not be updated. "); }
        ConnectivityManager cm = (ConnectivityManager) ctx.getSystemService(Context.CONNECTIVITY_SERVICE);
        boolean metered = cm == null || cm.isActiveNetworkMetered();
        if (age("phish-big.bin") > DAY && (!metered || !file("phish-big.bin").exists())) {
            if (metered) {
                note.append("The large phishing list will download on Wi-Fi. ");
            } else {
                try {
                    HttpURLConnection c = open(BIG);
                    long[] a;
                    try (InputStream in = c.getInputStream()) {
                        a = Links.buildList(new InputStreamReader(new LimitedStream(in, 40_000_000), StandardCharsets.UTF_8));
                    } finally {
                        c.disconnect();
                    }
                    if (a.length > 1000) {
                        File tmp = file("phish-big.tmp");
                        try (DataOutputStream out = new DataOutputStream(new BufferedOutputStream(new FileOutputStream(tmp)))) {
                            out.writeInt(a.length);
                            for (long x : a) out.writeLong(x);
                        }
                        if (!tmp.renameTo(file("phish-big.bin"))) { file("phish-big.bin").delete(); tmp.renameTo(file("phish-big.bin")); }
                    }
                } catch (Exception e) { note.append("Large phishing list could not be updated. "); }
            }
        }
        load();
        return note.toString().trim();
    }

    private synchronized void load() {
        File b = file("phish-big.bin");
        if (b.exists()) {
            try (DataInputStream in = new DataInputStream(new BufferedInputStream(new FileInputStream(b), 1 << 16))) {
                int n = in.readInt();
                if (n >= 0 && n < 5_000_000) {
                    long[] a = new long[n];
                    for (int i = 0; i < n; i++) a[i] = in.readLong();
                    big = a;
                }
            } catch (Exception ignored) { }
        }
        File l = file("phish-live.txt");
        Set<String> s = new HashSet<>();
        if (l.exists()) {
            try (Scanner sc = new Scanner(l, "UTF-8")) {
                while (sc.hasNextLine()) {
                    String h = Links.hostOf(sc.nextLine());
                    if (h != null) s.add(h);
                }
            } catch (Exception ignored) { }
        }
        live = s;
    }

    private long age(String name) {
        File f = file(name);
        return f.exists() ? System.currentTimeMillis() - f.lastModified() : Long.MAX_VALUE;
    }

    private void write(String name, byte[] d) throws Exception {
        File tmp = file(name + ".tmp");
        try (FileOutputStream out = new FileOutputStream(tmp)) { out.write(d); }
        if (!tmp.renameTo(file(name))) { file(name).delete(); tmp.renameTo(file(name)); }
    }

    private static HttpURLConnection open(String url) throws Exception {
        HttpURLConnection c = (HttpURLConnection) new URL(url).openConnection();
        c.setConnectTimeout(15_000);
        c.setReadTimeout(60_000);
        c.setRequestProperty("User-Agent", "blocklist-client/1.0");
        if (c.getResponseCode() != 200) throw new java.io.IOException("HTTP " + c.getResponseCode());
        return c;
    }

    private static byte[] get(String url, int limit) throws Exception {
        HttpURLConnection c = open(url);
        try (InputStream in = new LimitedStream(c.getInputStream(), limit)) {
            java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
            byte[] b = new byte[16384];
            int n;
            while ((n = in.read(b)) > 0) out.write(b, 0, n);
            return out.toByteArray();
        } finally {
            c.disconnect();
        }
    }

    /** Stops reading after `limit` bytes, whatever a server sends. */
    static final class LimitedStream extends java.io.FilterInputStream {
        private long left;
        LimitedStream(InputStream in, long limit) { super(in); left = limit; }
        @Override public int read() throws java.io.IOException {
            if (left <= 0) throw new java.io.IOException("download too large");
            int b = super.read();
            if (b >= 0) left--;
            return b;
        }
        @Override public int read(byte[] b, int off, int len) throws java.io.IOException {
            if (left <= 0) throw new java.io.IOException("download too large");
            int n = super.read(b, off, (int) Math.min(len, left));
            if (n > 0) left -= n;
            return n;
        }
    }
}
