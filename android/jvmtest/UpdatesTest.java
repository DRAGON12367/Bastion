import io.github.dragon12367.bastion.Updates;

/** Run:  javac -d out ../app/src/main/java/io/github/dragon12367/bastion/Updates.java UpdatesTest.java && java -cp out UpdatesTest [latest.json] */
public class UpdatesTest {
    static int failed = 0;

    static void check(boolean ok, String what) {
        System.out.println((ok ? "ok    " : "FAIL  ") + what);
        if (!ok) failed++;
    }

    static String rel(String tag, String apkUrl, String extra) {
        return "{\"tag_name\":\"" + tag + "\",\"html_url\":\"https://github.com/DRAGON12367/Bastion/releases/tag/" + tag + "\"," + extra
                + "\"assets\":[{\"name\":\"x\",\"browser_download_url\":\"" + apkUrl + "\"}]}";
    }

    public static void main(String[] a) throws Exception {
        String good = Updates.DOWNLOADS + "v1.3.0/Bastion-Android-1.3.0.apk";
        String[] u = Updates.newer(rel("v1.3.0", good, ""), "1.2.0");
        check(u != null && u[0].equals("1.3.0") && u[1].equals(good), "a newer Android release is offered");
        check(Updates.newer(rel("v1.3.0", good, ""), "1.3.0") == null, "the same version is not offered");
        check(Updates.newer(rel("v1.3.0", good, ""), "1.10.0") == null, "versions compare as numbers, not text");
        check(Updates.newer(rel("v1.3.0", "https://evil.example/Bastion-Android-1.3.0.apk", ""), "1.2.0") == null, "a download from another site is refused");
        check(Updates.newer(rel("v1.3.0", "https://github.com/someone-else/Bastion/releases/download/v1.3.0/Bastion-Android-1.3.0.apk", ""), "1.2.0") == null, "another GitHub account is refused");
        check(Updates.newer(rel("v1.3.0", good, "\"prerelease\": true,"), "1.2.0") == null, "pre-releases are not offered");
        check(Updates.newer(rel("v1.3.0", Updates.DOWNLOADS + "v1.3.0/Bastion-Setup-1.3.0.exe", ""), "1.2.0") == null, "a Windows-only release is not offered to phones");
        check(Updates.newer("not json at all", "1.2.0") == null && Updates.newer(null, "1.2.0") == null, "junk answers are ignored");
        if (a.length > 0) {
            String real = new String(java.nio.file.Files.readAllBytes(java.nio.file.Path.of(a[0])), java.nio.charset.StandardCharsets.UTF_8);
            String[] r = Updates.newer(real, "1.0.0");
            check(r != null && r[1].startsWith(Updates.DOWNLOADS), "the real latest release offers an update to a 1.0.0 phone: " + (r == null ? "none" : r[0]));
        }
        System.out.println(failed == 0 ? "\nALL PASSED" : "\n" + failed + " FAILED");
        System.exit(failed == 0 ? 0 : 1);
    }
}
