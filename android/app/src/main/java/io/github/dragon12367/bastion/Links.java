package io.github.dragon12367.bastion;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.Reader;
import java.net.URI;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Judges a link before it is opened. Pure Java, so it is tested on a PC. Same rules as the Windows app. */
public final class Links {
    public static final int SAFE = 0, CAUTION = 1, DANGER = 2;

    public static final class Result {
        public int level;
        public String headline, host;
        public final List<String> reasons = new ArrayList<>();
    }

    /** Looks a site name up in the phishing lists; returns which list, or null. */
    public interface Lists { String badSite(String host); }

    static final Map<String, String[]> BRANDS = new LinkedHashMap<>();
    static {
        BRANDS.put("paypal", new String[]{"paypal.com", "paypal.me"});
        BRANDS.put("microsoft", new String[]{"microsoft.com", "live.com", "office.com", "microsoftonline.com", "msn.com", "outlook.com", "xbox.com", "bing.com", "sharepoint.com", "skype.com", "windows.com", "azure.com", "office365.com", "microsoft365.com"});
        BRANDS.put("outlook", new String[]{"outlook.com", "live.com", "office.com", "microsoft.com"});
        BRANDS.put("apple", new String[]{"apple.com", "icloud.com"});
        BRANDS.put("icloud", new String[]{"icloud.com", "apple.com"});
        BRANDS.put("google", new String[]{"google.com", "google.ca", "google.co.uk", "youtube.com", "gmail.com", "googleusercontent.com", "gstatic.com", "goo.gl", "googleapis.com"});
        BRANDS.put("gmail", new String[]{"gmail.com", "google.com"});
        BRANDS.put("amazon", new String[]{"amazon.com", "amazon.ca", "amazon.co.uk", "amazon.de", "amazonaws.com", "amazon.in"});
        BRANDS.put("netflix", new String[]{"netflix.com"});
        BRANDS.put("facebook", new String[]{"facebook.com", "fb.com", "meta.com", "messenger.com"});
        BRANDS.put("instagram", new String[]{"instagram.com"});
        BRANDS.put("whatsapp", new String[]{"whatsapp.com", "whatsapp.net"});
        BRANDS.put("roblox", new String[]{"roblox.com", "rbxcdn.com"});
        BRANDS.put("steam", new String[]{"steampowered.com", "steamcommunity.com", "steamstatic.com"});
        BRANDS.put("discord", new String[]{"discord.com", "discord.gg", "discordapp.com"});
        BRANDS.put("coinbase", new String[]{"coinbase.com"});
        BRANDS.put("metamask", new String[]{"metamask.io"});
        BRANDS.put("binance", new String[]{"binance.com"});
        BRANDS.put("interac", new String[]{"interac.ca"});
        BRANDS.put("canadapost", new String[]{"canadapost-postescanada.ca", "canadapost.ca"});
        BRANDS.put("usps", new String[]{"usps.com"});
        BRANDS.put("fedex", new String[]{"fedex.com"});
        BRANDS.put("dhl", new String[]{"dhl.com", "dhl.de"});
        BRANDS.put("docusign", new String[]{"docusign.com", "docusign.net"});
    }
    static final Set<String> SHORTENERS = new HashSet<>(Arrays.asList("bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy", "shorturl.at", "ow.ly", "tiny.cc", "rebrand.ly", "s.id", "t.ly"));
    static final Pattern LINK = Pattern.compile("(?i)\\b((?:https?|hxxps?)://\\S+|(?:www\\.)?[a-z0-9-]+(?:\\.[a-z0-9-]+)+(?:[/:?#]\\S*)?)");

    private Links() {}

    /** The site name in some shared or pasted text, or null. */
    public static String hostOf(String text) {
        if (text == null) return null;
        Matcher m = LINK.matcher(text.trim());
        if (!m.find()) return null;
        String link = m.group(1).replaceFirst("(?i)^hxxp", "http");
        if (!link.matches("(?i)^[a-z]+://.*")) link = "http://" + link;
        try {
            String h = new URI(link.replaceAll("[\\s\"'<>]", "")).getHost();
            if (h == null || !h.contains(".")) return null;
            h = h.toLowerCase(Locale.ROOT);
            return h.endsWith(".") ? h.substring(0, h.length() - 1) : h;
        } catch (Exception e) {
            return null;
        }
    }

    static boolean belongs(String host, String[] own) {
        for (String d : own) if (host.equals(d) || host.endsWith("." + d)) return true;
        return false;
    }

    static String registered(String host) {
        String[] p = host.split("\\.");
        int n = p.length;
        if (n >= 3 && p[n - 1].length() == 2 && Arrays.asList("co", "com", "org", "net", "gov", "ac", "gc").contains(p[n - 2]))
            return p[n - 3] + "." + p[n - 2] + "." + p[n - 1];
        return n >= 2 ? p[n - 2] + "." + p[n - 1] : host;
    }

    public static Result check(String text, Lists lists) {
        Result r = new Result();
        String host = hostOf(text);
        r.host = host;
        if (host == null) {
            r.level = CAUTION;
            r.headline = "That doesn't look like a web link";
            return r;
        }
        for (String h : host.startsWith("www.") ? new String[]{host, host.substring(4)} : new String[]{host}) {
            String why = lists == null ? null : lists.badSite(h);
            if (why != null) {
                r.level = DANGER;
                r.headline = "Dangerous: a known phishing or scam site";
                r.reasons.add(host + " is on the " + why);
                r.reasons.add("Don't open it, and never type a password or card number there.");
                return r;
            }
        }
        if (host.matches("\\d+\\.\\d+\\.\\d+\\.\\d+") || host.startsWith("[")) {
            r.reasons.add("It goes to a bare number address instead of a site name, which real companies don't do");
        }
        if (host.contains("xn--")) r.reasons.add("It uses look-alike letters from another alphabet to imitate a real name");
        Set<String> words = new HashSet<>(Arrays.asList(host.split("[.\\-_]")));
        for (Map.Entry<String, String[]> b : BRANDS.entrySet()) {
            if (words.contains(b.getKey()) && !belongs(host, b.getValue())) {
                r.reasons.add("It mentions " + b.getKey() + " but is not " + b.getKey() + "'s real site (" + registered(host) + ")");
                break;
            }
        }
        if (SHORTENERS.contains(host) || SHORTENERS.contains(registered(host))) r.reasons.add("It is a shortened link that hides where it really goes");
        if (host.split("\\.").length >= 5 && host.matches(".*(login|signin|verify|secure|account|update|wallet).*"))
            r.reasons.add("A very long name full of words like 'login' or 'verify' is a common phishing trick");
        if (r.reasons.isEmpty()) {
            r.level = SAFE;
            r.headline = "No warning signs found";
            r.reasons.add(host + " is not on the phishing lists Bastion uses.");
            r.reasons.add("That doesn't prove it's safe: new scam sites appear every hour.");
        } else {
            r.level = CAUTION;
            r.headline = "Be careful with this link";
        }
        return r;
    }

    // ------------------------------------------------------------------ compact site list: sorted 64-bit fingerprints, 8 bytes a site
    public static long fingerprint(String host) {
        long h = 0xcbf29ce484222325L;                  // FNV-1a
        for (int i = 0; i < host.length(); i++) {
            h ^= host.charAt(i);
            h *= 0x100000001b3L;
        }
        return h;
    }

    /** Fingerprints of every site name in a one-per-line list, sorted and without repeats. */
    public static long[] buildList(Reader in) throws IOException {
        BufferedReader br = new BufferedReader(in, 1 << 16);
        long[] a = new long[1 << 16];
        int n = 0;
        String line;
        while ((line = br.readLine()) != null) {
            String s = line.trim().toLowerCase(Locale.ROOT);
            if (s.isEmpty() || s.startsWith("#") || s.indexOf('.') < 0 || !s.matches("[a-z0-9_.-]+")) continue;
            if (n == a.length) a = Arrays.copyOf(a, n * 2);
            a[n++] = fingerprint(s);
            if (n > 3_000_000) break;
        }
        a = Arrays.copyOf(a, n);
        Arrays.sort(a);
        int k = 0;
        for (int i = 0; i < n; i++) if (k == 0 || a[i] != a[k - 1]) a[k++] = a[i];
        return Arrays.copyOf(a, k);
    }

    public static boolean contains(long[] sorted, String host) {
        return sorted != null && Arrays.binarySearch(sorted, fingerprint(host)) >= 0;
    }
}
