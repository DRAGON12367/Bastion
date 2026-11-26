package io.github.dragon12367.bastion;

import android.app.AppOpsManager;
import android.app.KeyguardManager;
import android.app.admin.DevicePolicyManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.content.pm.Signature;
import android.os.Build;
import android.provider.Settings;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/** Looks at this phone. Read-only: it never changes a setting or removes anything. */
public final class Scanner {
    static final String LIST_URL = "https://raw.githubusercontent.com/AssoEchap/stalkerware-indicators/master/ioc.yaml";
    static final long LIST_MAX_AGE = 3L * 86_400_000L;
    static final Set<String> STORES = new HashSet<>(Arrays.asList(
            "com.android.vending", "com.amazon.venezia", "com.sec.android.app.samsungapps", "com.huawei.appmarket",
            "org.fdroid.fdroid", "org.fdroid.basic", "com.aurora.store", "com.xiaomi.market", "com.xiaomi.mipicks",
            "com.heytap.market", "com.oppo.market", "com.bbk.appstore", "com.google.android.feedback"));

    public static final class Check {
        public final String title, detail;
        public final boolean ok;
        public final String settingsAction;
        Check(String title, String detail, boolean ok, String settingsAction) {
            this.title = title; this.detail = detail; this.ok = ok; this.settingsAction = settingsAction;
        }
    }

    public static final class AppResult {
        public final Judge.Facts facts;
        public final Judge.Verdict verdict;
        AppResult(Judge.Facts f, Judge.Verdict v) { facts = f; verdict = v; }
    }

    public static final class Report {
        public final List<Check> checks = new ArrayList<>();
        public final List<AppResult> apps = new ArrayList<>();
        public int appsLooked;
        public String listNote = "";
    }

    private final Context ctx;
    private final PackageManager pm;

    public Scanner(Context ctx) {
        this.ctx = ctx.getApplicationContext();
        this.pm = this.ctx.getPackageManager();
    }

    public Report run(Set<String> trusted) {
        Report r = new Report();
        health(r);
        Set<String> badPkgs = new HashSet<>(), badCerts = new HashSet<>();
        r.listNote = stalkerwareList(badPkgs, badCerts);
        apps(r, badPkgs, badCerts, trusted);
        return r;
    }

    // ------------------------------------------------------------------ phone health
    private void health(Report r) {
        KeyguardManager km = (KeyguardManager) ctx.getSystemService(Context.KEYGUARD_SERVICE);
        boolean locked = km != null && km.isDeviceSecure();
        r.checks.add(new Check("Screen lock", locked ? "A PIN, pattern, password or fingerprint protects this phone." : "Anyone who picks up this phone can open it. Set a PIN or password.",
                locked, Settings.ACTION_SECURITY_SETTINGS));

        DevicePolicyManager dpm = (DevicePolicyManager) ctx.getSystemService(Context.DEVICE_POLICY_SERVICE);
        int enc = dpm == null ? 0 : dpm.getStorageEncryptionStatus();
        boolean encrypted = enc == DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE || enc == DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE_PER_USER
                || enc == DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE_DEFAULT_KEY;
        r.checks.add(new Check("Storage encryption", encrypted ? "Your files are encrypted." : "Storage is not encrypted. Setting a screen lock usually turns it on.",
                encrypted, Settings.ACTION_SECURITY_SETTINGS));

        long age = Judge.patchAgeDays(Build.VERSION.SECURITY_PATCH, System.currentTimeMillis());
        boolean fresh = age >= 0 && age <= 120;
        r.checks.add(new Check("Security updates", age < 0 ? "The security patch date could not be read." :
                "Last security patch: " + Build.VERSION.SECURITY_PATCH + " (" + age + " days ago)." + (fresh ? "" : " Check for a system update; if none comes, this phone may no longer get security fixes."),
                fresh, Settings.ACTION_DEVICE_INFO_SETTINGS));

        boolean adb = Settings.Global.getInt(ctx.getContentResolver(), Settings.Global.ADB_ENABLED, 0) == 1;
        r.checks.add(new Check("USB debugging", adb ? "USB debugging is on. A computer you plug into could control this phone. Turn it off unless you need it." : "Off.",
                !adb, Settings.ACTION_APPLICATION_DEVELOPMENT_SETTINGS));

        boolean dev = Settings.Global.getInt(ctx.getContentResolver(), Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0) == 1;
        r.checks.add(new Check("Developer options", dev ? "Developer options are on. Fine if you use them; otherwise turn them off." : "Off.",
                !dev, Settings.ACTION_APPLICATION_DEVELOPMENT_SETTINGS));
    }

    // ------------------------------------------------------------------ public stalkerware list
    /** Fills the sets from the cached list, refreshing it when older than 3 days. Returns a note for the screen. */
    String stalkerwareList(Set<String> pkgs, Set<String> certs) {
        File f = new File(ctx.getFilesDir(), "stalkerware-ioc.yaml");
        String note;
        if (!f.exists() || System.currentTimeMillis() - f.lastModified() > LIST_MAX_AGE) {
            try {
                byte[] data = download(LIST_URL, 5_000_000);
                String text = new String(data, StandardCharsets.UTF_8);
                if (!text.contains("packages:")) throw new java.io.IOException("unexpected content");
                File tmp = new File(ctx.getFilesDir(), "stalkerware-ioc.tmp");
                try (FileOutputStream out = new FileOutputStream(tmp)) { out.write(data); }
                if (!tmp.renameTo(f)) { f.delete(); tmp.renameTo(f); }
                note = "Stalkerware list updated just now.";
            } catch (Exception e) {
                note = f.exists() ? "Using the saved stalkerware list (could not update it now)." : "The stalkerware list could not be downloaded, so only behaviour was checked.";
            }
        } else {
            note = "Stalkerware list checked within the last 3 days.";
        }
        if (f.exists()) {
            try (InputStream in = new FileInputStream(f)) {
                Judge.parseList(new String(readAll(in, 5_000_000), StandardCharsets.UTF_8), pkgs, certs);
            } catch (Exception ignored) { }
        }
        return note + " (" + pkgs.size() + " apps, " + certs.size() + " signing certificates)";
    }

    private static byte[] download(String url, int limit) throws Exception {
        HttpURLConnection c = (HttpURLConnection) new URL(url).openConnection();
        c.setConnectTimeout(15_000);
        c.setReadTimeout(30_000);
        c.setRequestProperty("User-Agent", "blocklist-client/1.0");
        try (InputStream in = c.getInputStream()) {
            if (c.getResponseCode() != 200) throw new java.io.IOException("HTTP " + c.getResponseCode());
            return readAll(in, limit);
        } finally {
            c.disconnect();
        }
    }

    private static byte[] readAll(InputStream in, int limit) throws java.io.IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] b = new byte[16384];
        int n;
        while ((n = in.read(b)) > 0) {
            out.write(b, 0, n);
            if (out.size() > limit) throw new java.io.IOException("too large");
        }
        return out.toByteArray();
    }

    // ------------------------------------------------------------------ installed apps
    private void apps(Report r, Set<String> badPkgs, Set<String> badCerts, Set<String> trusted) {
        String acc = Settings.Secure.getString(ctx.getContentResolver(), Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES);
        String notif = Settings.Secure.getString(ctx.getContentResolver(), "enabled_notification_listeners");
        Set<String> admins = new HashSet<>();
        DevicePolicyManager dpm = (DevicePolicyManager) ctx.getSystemService(Context.DEVICE_POLICY_SERVICE);
        List<ComponentName> active = dpm == null ? null : dpm.getActiveAdmins();
        if (active != null) for (ComponentName c : active) admins.add(c.getPackageName());
        Set<String> launchable = new HashSet<>();
        for (ResolveInfo ri : pm.queryIntentActivities(new Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER), 0))
            launchable.add(ri.activityInfo.packageName);

        int flags = PackageManager.GET_PERMISSIONS | (Build.VERSION.SDK_INT >= 28 ? PackageManager.GET_SIGNING_CERTIFICATES : PackageManager.GET_SIGNATURES);
        AppOpsManager ops = (AppOpsManager) ctx.getSystemService(Context.APP_OPS_SERVICE);
        for (PackageInfo pi : pm.getInstalledPackages(flags)) {
            if (pi.applicationInfo == null || pi.packageName.equals(ctx.getPackageName())) continue;
            r.appsLooked++;
            Judge.Facts f = new Judge.Facts();
            f.pkg = pi.packageName;
            f.label = String.valueOf(pi.applicationInfo.loadLabel(pm));
            f.system = (pi.applicationInfo.flags & (ApplicationInfo.FLAG_SYSTEM | ApplicationInfo.FLAG_UPDATED_SYSTEM_APP)) != 0;
            f.installer = installer(pi.packageName);
            f.fromStore = STORES.contains(f.installer);
            f.hasLauncherIcon = launchable.contains(f.pkg);
            f.accessibilityOn = acc != null && (":" + acc + ":").contains(":" + f.pkg + "/");
            f.notificationListenerOn = notif != null && (":" + notif + ":").contains(":" + f.pkg + "/");
            f.deviceAdminOn = admins.contains(f.pkg);
            f.certSha1 = certSha1(pi);
            String[] perms = pi.requestedPermissions;
            int[] states = pi.requestedPermissionsFlags;
            if (perms != null && states != null) {
                for (int i = 0; i < perms.length && i < states.length; i++) {
                    boolean granted = (states[i] & PackageInfo.REQUESTED_PERMISSION_GRANTED) != 0;
                    if (!granted) continue;
                    switch (perms[i]) {
                        case "android.permission.READ_SMS": case "android.permission.RECEIVE_SMS": f.sms = true; break;
                        case "android.permission.READ_CALL_LOG": f.callLog = true; break;
                        case "android.permission.RECORD_AUDIO": f.microphone = true; break;
                        case "android.permission.CAMERA": f.camera = true; break;
                        case "android.permission.ACCESS_FINE_LOCATION": f.fineLocation = true; break;
                        case "android.permission.ACCESS_BACKGROUND_LOCATION": f.backgroundLocation = true; break;
                        case "android.permission.READ_CONTACTS": f.contacts = true; break;
                        default: break;
                    }
                }
                List<String> asked = Arrays.asList(perms);
                int uid = pi.applicationInfo.uid;
                if (asked.contains("android.permission.SYSTEM_ALERT_WINDOW")) f.overlayAllowed = allowed(ops, "android:system_alert_window", uid, f.pkg);
                if (asked.contains("android.permission.REQUEST_INSTALL_PACKAGES")) f.canInstallApps = allowed(ops, "android:request_install_packages", uid, f.pkg);
            }
            Judge.Verdict v = Judge.judge(f, badPkgs, badCerts, trusted);
            if (v.level > Judge.NONE) r.apps.add(new AppResult(f, v));
        }
        r.apps.sort((a, b) -> b.verdict.level != a.verdict.level ? b.verdict.level - a.verdict.level : b.verdict.score - a.verdict.score);
    }

    private String installer(String pkg) {
        try {
            String s = Build.VERSION.SDK_INT >= 30 ? pm.getInstallSourceInfo(pkg).getInstallingPackageName() : pm.getInstallerPackageName(pkg);
            return s == null ? "" : s;
        } catch (Exception e) {
            return "";
        }
    }

    private static boolean allowed(AppOpsManager ops, String op, int uid, String pkg) {
        if (ops == null) return false;
        try {
            int mode = Build.VERSION.SDK_INT >= 29 ? ops.unsafeCheckOpNoThrow(op, uid, pkg) : ops.checkOpNoThrow(op, uid, pkg);
            return mode == AppOpsManager.MODE_ALLOWED;
        } catch (Exception e) {
            return false;
        }
    }

    @SuppressWarnings("deprecation")
    private static String certSha1(PackageInfo pi) {
        try {
            Signature[] sigs;
            if (Build.VERSION.SDK_INT >= 28 && pi.signingInfo != null)
                sigs = pi.signingInfo.hasMultipleSigners() ? pi.signingInfo.getApkContentsSigners() : pi.signingInfo.getSigningCertificateHistory();
            else
                sigs = pi.signatures;
            if (sigs == null || sigs.length == 0) return "";
            byte[] d = MessageDigest.getInstance("SHA-1").digest(sigs[0].toByteArray());
            StringBuilder sb = new StringBuilder();
            for (byte x : d) sb.append(String.format(Locale.ROOT, "%02X", x));
            return sb.toString();
        } catch (Exception e) {
            return "";
        }
    }
}
