package io.github.dragon12367.bastion;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Reads GitHub's "latest release" answer and says whether it holds a newer Bastion for Android. Pure Java, tested on a PC.
 *  Android itself only installs the download as an update if it is signed with the same key as the installed app. */
public final class Updates {
    public static final String API = "https://api.github.com/repos/DRAGON12367/Bastion/releases/latest";
    public static final String DOWNLOADS = "https://github.com/DRAGON12367/Bastion/releases/download/";
    static final Pattern TAG = Pattern.compile("\"tag_name\"\\s*:\\s*\"v?(\\d{1,4})\\.(\\d{1,4})\\.(\\d{1,4})\"");
    static final Pattern PAGE = Pattern.compile("\"html_url\"\\s*:\\s*\"(https://github\\.com/DRAGON12367/Bastion/releases/tag/[^\"]+)\"");
    static final Pattern APK = Pattern.compile("\"browser_download_url\"\\s*:\\s*\"(https://github\\.com/DRAGON12367/Bastion/releases/download/[^\"/]+/Bastion-Android-(\\d{1,4})\\.(\\d{1,4})\\.(\\d{1,4})\\.apk)\"");
    static final Pattern FLAG = Pattern.compile("\"(prerelease|draft)\"\\s*:\\s*true");

    private Updates() {}

    /** {version, apkUrl, releasePage} when the release is newer than `current` and has an Android app; otherwise null. */
    public static String[] newer(String json, String current) {
        if (json == null || FLAG.matcher(json).find()) return null;
        int[] now = parse(current);
        if (now == null) return null;
        Matcher m = APK.matcher(json);
        while (m.find()) {
            int[] v = {Integer.parseInt(m.group(2)), Integer.parseInt(m.group(3)), Integer.parseInt(m.group(4))};
            if (compare(v, now) > 0) {
                Matcher p = PAGE.matcher(json);
                return new String[]{v[0] + "." + v[1] + "." + v[2], m.group(1), p.find() ? p.group(1) : "https://github.com/DRAGON12367/Bastion/releases"};
            }
        }
        return null;
    }

    static int[] parse(String s) {
        if (s == null) return null;
        Matcher m = Pattern.compile("v?(\\d{1,4})\\.(\\d{1,4})\\.(\\d{1,4})").matcher(s.trim());
        return m.matches() ? new int[]{Integer.parseInt(m.group(1)), Integer.parseInt(m.group(2)), Integer.parseInt(m.group(3))} : null;
    }

    static int compare(int[] a, int[] b) {
        for (int i = 0; i < 3; i++) if (a[i] != b[i]) return Integer.compare(a[i], b[i]);
        return 0;
    }
}
