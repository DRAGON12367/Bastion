package io.github.dragon12367.bastion;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/** Turns what is known about one installed app into a plain-language verdict. Pure Java, so it is tested on a PC.
 *  It never says "malware" from behaviour alone: only a match on the public stalkerware list does that. */
public final class Judge {
    public static final int NONE = 0, INFO = 1, CHECK = 2, KNOWN = 3;

    /** Everything the scanner found out about one app. */
    public static final class Facts {
        public String pkg = "", label = "", installer = "", certSha1 = "";
        public boolean system, fromStore, hasLauncherIcon = true;
        public boolean accessibilityOn, deviceAdminOn, notificationListenerOn, overlayAllowed, canInstallApps;
        public boolean sms, callLog, microphone, camera, fineLocation, backgroundLocation, contacts;
    }

    public static final class Verdict {
        public int level = NONE, score;
        public String headline = "";
        public final List<String> reasons = new ArrayList<>();
    }

    private Judge() {}

    public static Verdict judge(Facts f, Set<String> badPackages, Set<String> badCerts, Set<String> trusted) {
        Verdict v = new Verdict();
        boolean listed = badPackages.contains(f.pkg) || (!f.certSha1.isEmpty() && badCerts.contains(f.certSha1.toUpperCase(Locale.ROOT)));
        if (listed) {
            v.level = KNOWN;
            v.score = 100;
            v.headline = "Known stalkerware";
            v.reasons.add("On the public stalkerware list kept by the Echap association");
            return v;                       // a known match is reported even if the app was trusted
        }
        if (f.system || trusted.contains(f.pkg)) return v;

        add(v, f.accessibilityOn, 35, "Can see and control everything on the screen (accessibility is on)");
        add(v, f.deviceAdminOn, 30, "Is a device administrator, which makes it harder to remove");
        add(v, f.notificationListenerOn, 15, "Reads all your notifications, including messages");
        add(v, f.overlayAllowed, 10, "Can draw over other apps");
        add(v, f.canInstallApps, 10, "Is allowed to install other apps");
        add(v, !f.fromStore, 15, "Was installed from outside an app store");
        add(v, !f.hasLauncherIcon, 20, "Has no icon on the home screen, so it is easy to miss");
        add(v, f.sms, 15, "Can read your text messages");
        add(v, f.callLog, 10, "Can read your call history");
        add(v, f.microphone, 10, "Can use the microphone");
        add(v, f.backgroundLocation, 10, "Can track your location in the background");
        add(v, f.fineLocation && !f.backgroundLocation, 5, "Can see your exact location");
        add(v, f.camera, 5, "Can use the camera");
        add(v, f.contacts, 5, "Can read your contacts");

        boolean outsideOrHidden = !f.fromStore || !f.hasLauncherIcon;
        if (v.score >= 70 && outsideOrHidden) {
            v.level = CHECK;
            v.headline = "Check this app";
        } else if (v.score >= 45) {
            v.level = INFO;
            v.headline = "Has powerful access: make sure you trust it";
        }
        return v;
    }

    private static void add(Verdict v, boolean when, int points, String why) {
        if (when) {
            v.score += points;
            v.reasons.add(why);
        }
    }

    /** Package names and certificate fingerprints from the Echap ioc.yaml (one entry per line under "packages:" and "certificates:"). */
    public static void parseList(String yaml, Set<String> packages, Set<String> certs) {
        String section = "";
        for (String raw : yaml.split("\n")) {
            String line = raw.replace("\r", "");
            String t = line.trim();
            if (!line.startsWith(" ") && !line.startsWith("-") && t.endsWith(":")) { section = t; continue; }
            if (t.endsWith(":") && !t.startsWith("-")) { section = t; continue; }
            if (!t.startsWith("- ")) continue;
            String value = t.substring(2).trim();
            if (section.equals("packages:") && value.matches("[A-Za-z0-9_]+(\\.[A-Za-z0-9_]+)+")) packages.add(value);
            else if (section.equals("certificates:") && value.matches("[0-9A-Fa-f]{40}")) certs.add(value.toUpperCase(Locale.ROOT));
        }
    }

    /** Days since the security patch date (YYYY-MM-DD), or -1 if it cannot be read. */
    public static long patchAgeDays(String patch, long nowMillis) {
        try {
            String[] p = patch.split("-");
            java.util.Calendar c = java.util.Calendar.getInstance(java.util.TimeZone.getTimeZone("UTC"));
            c.clear();
            c.set(Integer.parseInt(p[0]), Integer.parseInt(p[1]) - 1, Integer.parseInt(p[2]));
            return Math.max(0, (nowMillis - c.getTimeInMillis()) / 86_400_000L);
        } catch (RuntimeException e) {
            return -1;
        }
    }
}
