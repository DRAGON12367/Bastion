import io.github.dragon12367.bastion.Links;

import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

/** Run:  javac -d out ../app/src/main/java/io/github/dragon12367/bastion/Links.java LinksTest.java && java -cp out LinksTest [phishing-domains.txt] */
public class LinksTest {
    static int failed = 0;

    static void check(boolean ok, String what) {
        System.out.println((ok ? "ok    " : "FAIL  ") + what);
        if (!ok) failed++;
    }

    public static void main(String[] a) throws Exception {
        String[] honest = {"https://www.google.com/search?q=x", "https://accounts.google.com", "https://login.microsoftonline.com/common", "https://www.paypal.com/signin",
                "https://appleid.apple.com", "https://www.roblox.com/games/1", "https://store.steampowered.com", "https://pineapple.com", "https://www.purchase.com",
                "https://groups.google.com/g/x", "https://steamboat.com", "https://discord.com/app", "https://www.amazon.ca/dp/1", "en.wikipedia.org/wiki/Phishing",
                "Look at this https://www.canadapost-postescanada.ca/track?id=1 thanks"};
        for (String u : honest) check(Links.check(u, null).level == Links.SAFE, "no false alarm: " + u);
        String[] tricks = {"https://paypal.com.secure-login.xyz/signin", "https://apple-id-verify.help", "http://192.0.2.7/login", "https://xn--pple-43d.com",
                "bit.ly/3abc", "https://steam-community.gift/trade", "https://microsoft-account-verify.online", "hxxps://roblox.free-robux.click"};
        for (String u : tricks) check(Links.check(u, null).level == Links.CAUTION, "caught trick: " + u);
        check(Links.check("hello there", null).level == Links.CAUTION, "plain words are not a link");
        Links.Lists one = h -> h.equals("evil.example.com") ? "test list" : null;
        check(Links.check("Your parcel: https://www.evil.example.com/p", one).level == Links.DANGER, "a listed site is dangerous, also with www. and text around it");

        long[] list = Links.buildList(new StringReader("# comment\nbad-login.example\nbad-login.example\nwww.paypa1-verify.example\nnot a site\n"));
        check(list.length == 2, "list keeps site names once and skips junk");
        check(Links.contains(list, "bad-login.example") && !Links.contains(list, "google.com") && !Links.contains(list, "paypa1-verify.example"), "exact site names only");

        if (a.length > 0) {
            long t = System.currentTimeMillis();
            long[] real = Links.buildList(new StringReader(new String(Files.readAllBytes(Path.of(a[0])), StandardCharsets.UTF_8)));
            System.out.println("      real list: " + real.length + " sites, " + (real.length * 8 / 1024) + " KB, built in " + (System.currentTimeMillis() - t) + " ms");
            check(real.length > 100_000, "the real phishing list loads");
            for (String h : new String[]{"google.com", "www.google.com", "microsoft.com", "github.com", "youtube.com", "roblox.com", "paypal.com", "reddit.com", "amazon.ca"})
                check(!Links.contains(real, h), "popular site not on the list: " + h);
        }
        System.out.println(failed == 0 ? "\nALL PASSED" : "\n" + failed + " FAILED");
        System.exit(failed == 0 ? 0 : 1);
    }
}
