import io.github.dragon12367.bastion.Judge;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.Set;

/** Run:  javac -d out ../app/src/main/java/io/github/dragon12367/bastion/Judge.java JudgeTest.java && java -cp out JudgeTest [ioc.yaml] */
public class JudgeTest {
    static int failed = 0;

    static void check(boolean ok, String what) {
        System.out.println((ok ? "ok    " : "FAIL  ") + what);
        if (!ok) failed++;
    }

    static Judge.Facts app(String pkg) {
        Judge.Facts f = new Judge.Facts();
        f.pkg = pkg;
        f.label = pkg;
        f.fromStore = true;
        return f;
    }

    public static void main(String[] a) throws Exception {
        Set<String> none = new HashSet<>(), pk = new HashSet<>(), certs = new HashSet<>(), trusted = new HashSet<>();

        // ordinary apps are not shown
        Judge.Facts maps = app("com.google.android.apps.maps");
        maps.fineLocation = true; maps.backgroundLocation = true;
        check(Judge.judge(maps, none, none, trusted).level == Judge.NONE, "a maps app with location is not flagged");

        Judge.Facts chat = app("org.telegram.messenger");
        chat.microphone = true; chat.camera = true; chat.contacts = true; chat.notificationListenerOn = false;
        check(Judge.judge(chat, none, none, trusted).level == Judge.NONE, "a chat app with mic, camera and contacts is not flagged");

        // a password manager from the Play Store with accessibility: informational, never "check this app"
        Judge.Facts pw = app("com.x8bit.bitwarden");
        pw.accessibilityOn = true; pw.overlayAllowed = true;
        Judge.Verdict v = Judge.judge(pw, none, none, trusted);
        check(v.level <= Judge.INFO, "a store-installed password manager using accessibility is at most informational");

        // classic stalkerware shape: sideloaded, hidden, accessibility + SMS + mic + location
        Judge.Facts spy = app("com.system.service.update");
        spy.fromStore = false; spy.hasLauncherIcon = false; spy.accessibilityOn = true; spy.sms = true; spy.microphone = true;
        spy.backgroundLocation = true; spy.notificationListenerOn = true;
        v = Judge.judge(spy, none, none, trusted);
        check(v.level == Judge.CHECK && v.score >= 70, "a hidden sideloaded app with accessibility, SMS, mic and location must be checked");
        check(!v.headline.toLowerCase().contains("malware"), "behaviour alone is never called malware");

        // the same app from the Play Store with an icon is only informational
        spy.fromStore = true; spy.hasLauncherIcon = true;
        check(Judge.judge(spy, none, none, trusted).level == Judge.INFO, "the same permissions from a store app with an icon are only informational");

        // system apps and trusted apps are skipped
        spy.system = true;
        check(Judge.judge(spy, none, none, trusted).level == Judge.NONE, "system apps are not judged on behaviour");
        spy.system = false;
        trusted.add(spy.pkg);
        check(Judge.judge(spy, none, none, trusted).level == Judge.NONE, "apps the user trusted are not shown");

        // a list match beats trust, and matches by certificate too (any case)
        pk.add("com.thetruth");
        certs.add("31A6ECECD97CF39BC4126B8745CD94A7C30BF81C");
        trusted.add("com.thetruth");
        check(Judge.judge(app("com.thetruth"), pk, certs, trusted).level == Judge.KNOWN, "a listed package is reported even if trusted");
        Judge.Facts renamed = app("com.renamed.spy");
        renamed.certSha1 = "31a6ececd97cf39bc4126b8745cd94a7c30bf81c";
        check(Judge.judge(renamed, pk, certs, new HashSet<>()).level == Judge.KNOWN, "a renamed app is caught by its signing certificate");

        // list parsing, including the real file when given
        String sample = "- name: X\n  names:\n  - SpyZee\n  type: stalkerware\n  packages:\n  - com.spyzee\n  - not a package\n  certificates:\n  - 31A6ECECD97CF39BC4126B8745CD94A7C30BF81C\n  - XYZ\n  websites:\n  - spyzee.com\n";
        Set<String> p2 = new HashSet<>(), c2 = new HashSet<>();
        Judge.parseList(sample, p2, c2);
        check(p2.size() == 1 && p2.contains("com.spyzee"), "parser takes package names only from the packages section");
        check(c2.size() == 1, "parser takes only 40-hex certificate fingerprints");
        check(!p2.contains("spyzee.com"), "websites are not mistaken for package names");
        if (a.length > 0) {
            Set<String> rp = new HashSet<>(), rc = new HashSet<>();
            Judge.parseList(new String(Files.readAllBytes(Path.of(a[0])), StandardCharsets.UTF_8), rp, rc);
            System.out.println("      real list: " + rp.size() + " packages, " + rc.size() + " certificates");
            check(rp.size() > 100 && rc.size() > 100, "the real Echap list parses into many entries");
            check(rp.contains("com.thetruth"), "the real list contains a known stalkerware package");
        }

        check(Judge.patchAgeDays("2026-11-01", Judge.patchAgeDays("2026-11-01", 0) >= 0 ? 1_795_000_000_000L : 0) >= 0, "patch date parses");
        check(Judge.patchAgeDays("not a date", 0) == -1, "a bad patch date is reported as unknown");

        System.out.println(failed == 0 ? "\nALL PASSED" : "\n" + failed + " FAILED");
        System.exit(failed == 0 ? 0 : 1);
    }
}
