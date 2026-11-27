package io.github.dragon12367.bastion;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.job.JobInfo;
import android.app.job.JobParameters;
import android.app.job.JobScheduler;
import android.app.job.JobService;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Build;

import java.util.HashSet;
import java.util.Set;

/** Bastion's 24/7 part on the phone: Android wakes it about every 30 minutes (and after a restart) to re-check the apps,
 *  and it notifies when a new app looks like spyware or an app has just been given control of the screen. */
public class GuardJob extends JobService {
    static final int ID = 1;
    static final String CHANNEL = "alerts";

    public static void schedule(Context c) {
        JobScheduler js = (JobScheduler) c.getSystemService(Context.JOB_SCHEDULER_SERVICE);
        if (js == null) return;
        for (JobInfo j : js.getAllPendingJobs()) if (j.getId() == ID) return;
        js.schedule(new JobInfo.Builder(ID, new ComponentName(c, GuardJob.class))
                .setPeriodic(30 * 60 * 1000L)
                .setPersisted(true)
                .build());
    }

    @Override
    public boolean onStartJob(JobParameters params) {
        new Thread(() -> {
            try {
                check(this);
            } catch (Exception ignored) {
            } finally {
                jobFinished(params, false);
            }
        }, "bastion-guard").start();
        return true;
    }

    @Override
    public boolean onStopJob(JobParameters params) { return true; }

    static void check(Context c) {
        SharedPreferences p = c.getSharedPreferences("bastion", MODE_PRIVATE);
        Set<String> trusted = new HashSet<>(p.getStringSet("trusted", new HashSet<>()));
        Scanner.Report r = new Scanner(c).run(trusted);
        Set<String> before = new HashSet<>(p.getStringSet("flagged", new HashSet<>()));
        Set<String> powerBefore = new HashSet<>(p.getStringSet("powerful", new HashSet<>()));
        Set<String> flagged = new HashSet<>(), powerful = new HashSet<>();
        boolean firstRun = !p.contains("flagged");
        for (Scanner.AppResult a : r.apps) {
            if (a.verdict.level >= Judge.CHECK) {
                flagged.add(a.facts.pkg);
                if (!firstRun && !before.contains(a.facts.pkg))
                    notify(c, a.facts.pkg.hashCode(), a.verdict.level == Judge.KNOWN ? "Known stalkerware found: " + a.facts.label : "Check this app: " + a.facts.label,
                            a.verdict.reasons.isEmpty() ? "Open Bastion to see why." : a.verdict.reasons.get(0));
            }
            if (a.facts.accessibilityOn || a.facts.deviceAdminOn) {
                powerful.add(a.facts.pkg);
                if (!firstRun && !powerBefore.contains(a.facts.pkg) && a.verdict.level < Judge.CHECK)
                    notify(c, a.facts.pkg.hashCode() + 1, a.facts.label + " now has powerful access",
                            a.facts.accessibilityOn ? "It can now see and control your screen. If you didn't just allow this, check it in Bastion." :
                                    "It is now a device administrator. If you didn't just allow this, check it in Bastion.");
            }
        }
        p.edit().putStringSet("flagged", flagged).putStringSet("powerful", powerful).putLong("lastCheck", System.currentTimeMillis()).apply();
        new PhishLists(c).refresh(false);
        String[] u = updateDue(c);
        if (u != null && !u[0].equals(p.getString("toldUpdate", ""))) {
            p.edit().putString("toldUpdate", u[0]).apply();
            notifyLink(c, 777, "Bastion " + u[0] + " is available", "Tap to download it. Android installs it as an update to the Bastion you have.", u[1]);
        }
    }

    /** Asks GitHub at most once a day for a newer Bastion. {version, apkUrl, page} or null. Never raises. */
    static String[] updateDue(Context c) {
        SharedPreferences p = c.getSharedPreferences("bastion", MODE_PRIVATE);
        if (System.currentTimeMillis() - p.getLong("updateChecked", 0) < 86_400_000L) {
            String v = p.getString("updateVersion", "");
            return v.isEmpty() ? null : new String[]{v, p.getString("updateUrl", ""), p.getString("updatePage", "")};
        }
        try {
            java.net.HttpURLConnection h = (java.net.HttpURLConnection) new java.net.URL(Updates.API).openConnection();
            h.setConnectTimeout(15_000);
            h.setReadTimeout(20_000);
            h.setRequestProperty("Accept", "application/vnd.github+json");
            h.setRequestProperty("User-Agent", "Bastion-update-check");
            String json;
            try (java.io.InputStream in = new PhishLists.LimitedStream(h.getInputStream(), 2_000_000)) {
                java.io.ByteArrayOutputStream buf = new java.io.ByteArrayOutputStream();
                byte[] b = new byte[16384];
                int n;
                while ((n = in.read(b)) > 0) buf.write(b, 0, n);       // readAllBytes() needs Android 13
                json = new String(buf.toByteArray(), java.nio.charset.StandardCharsets.UTF_8);
            } finally {
                h.disconnect();
            }
            String current = c.getPackageManager().getPackageInfo(c.getPackageName(), 0).versionName;
            String[] u = Updates.newer(json, current);
            p.edit().putLong("updateChecked", System.currentTimeMillis())
                    .putString("updateVersion", u == null ? "" : u[0]).putString("updateUrl", u == null ? "" : u[1]).putString("updatePage", u == null ? "" : u[2]).apply();
            return u;
        } catch (Exception e) {
            return null;            // offline: try again later
        }
    }

    static void notifyLink(Context c, int id, String title, String text, String url) {
        NotificationManager nm = (NotificationManager) c.getSystemService(Context.NOTIFICATION_SERVICE);
        if (nm == null) return;
        if (Build.VERSION.SDK_INT >= 26)
            nm.createNotificationChannel(new NotificationChannel("updates", "Updates", NotificationManager.IMPORTANCE_DEFAULT));
        PendingIntent open = PendingIntent.getActivity(c, id, new Intent(Intent.ACTION_VIEW, android.net.Uri.parse(url)).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
                PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
        Notification n = builder(c, "updates")
                .setSmallIcon(R.drawable.ic_launcher_foreground)
                .setContentTitle(title)
                .setContentText(text)
                .setStyle(new Notification.BigTextStyle().bigText(text))
                .setContentIntent(open)
                .setAutoCancel(true)
                .build();
        try { nm.notify(id, n); } catch (SecurityException ignored) { }
    }

    static void notify(Context c, int id, String title, String text) {
        NotificationManager nm = (NotificationManager) c.getSystemService(Context.NOTIFICATION_SERVICE);
        if (nm == null) return;
        if (Build.VERSION.SDK_INT >= 26)
            nm.createNotificationChannel(new NotificationChannel(CHANNEL, "Security alerts", NotificationManager.IMPORTANCE_HIGH));
        PendingIntent open = PendingIntent.getActivity(c, 0, new Intent(c, MainActivity.class).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
                PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
        Notification n = builder(c, CHANNEL)
                .setSmallIcon(R.drawable.ic_launcher_foreground)
                .setContentTitle(title)
                .setContentText(text)
                .setStyle(new Notification.BigTextStyle().bigText(text))
                .setContentIntent(open)
                .setAutoCancel(true)
                .build();
        try {
            nm.notify(id, n);
        } catch (SecurityException ignored) {        // notifications not allowed by the user
        }
    }

    /** Android 8+ needs a channel; Android 6 and 7 do not have channels. */
    @SuppressWarnings("deprecation")
    static Notification.Builder builder(Context c, String channel) {
        return Build.VERSION.SDK_INT >= 26 ? new Notification.Builder(c, channel) : new Notification.Builder(c);
    }
}
