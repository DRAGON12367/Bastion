package io.github.dragon12367.bastion;

import android.app.Activity;
import android.content.Intent;
import android.content.SharedPreferences;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.provider.Settings;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.EditText;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.os.Build;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import java.util.HashSet;
import java.util.Set;

/** One screen: a summary, the phone's health checks, and the apps worth a look. Nothing is ever changed without the user tapping. */
public class MainActivity extends Activity {
    static final int BG = 0xFF04080D, CARD = 0xC80A1E2C, LINE = 0xFF16506A, TEXT = 0xFFD8F3FF, DIM = 0xFF7F9BB0;
    static final int GOOD = 0xFF3FD8FF, WARN = 0xFFFFB547, BAD = 0xFFFF4D5E, ACCENT = 0xFF0D4A63;

    private LinearLayout list;
    private TextView headline, subline;
    private Button scanButton;
    private SharedPreferences prefs;
    private final Handler ui = new Handler(Looper.getMainLooper());
    private boolean scanning;
    private LinearLayout linkResult;
    private EditText linkBox;
    private PhishLists phish;
    private Reactor reactor;
    private TextView feed;

    @Override
    protected void onCreate(Bundle saved) {
        super.onCreate(saved);
        prefs = getSharedPreferences("bastion", MODE_PRIVATE);
        getWindow().setStatusBarColor(BG);
        getWindow().setNavigationBarColor(BG);

        ScrollView scroll = new ScrollView(this);
        scroll.setBackground(new GradientDrawable(GradientDrawable.Orientation.TOP_BOTTOM, new int[]{0xFF0B1C2A, BG, BG}));
        scroll.setFillViewport(true);
        LinearLayout root = column();
        // Tablets, Chromebooks and TVs: keep a readable column in the middle instead of stretching across the screen.
        int widthDp = getResources().getConfiguration().screenWidthDp, side = Math.max(18, (widthDp - 680) / 2);
        root.setPadding(dp(side), dp(28), dp(side), dp(28));
        scroll.addView(root);

        LinearLayout top = card();
        TextView title = text("Bastion", 26, TEXT, true);
        headline = text("Ready to check this phone", 20, TEXT, true);
        subline = text("Looks at installed apps and phone settings. Nothing about you is sent anywhere.", 14, DIM, false);
        scanButton = button("Check this phone", true, v -> scan());
        reactor = new Reactor(this);
        top.addView(reactor, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(200)));
        title.setLetterSpacing(0.12f);
        title.setGravity(Gravity.CENTER);
        top.addView(title);
        top.addView(space(6));
        top.addView(headline);
        top.addView(space(4));
        top.addView(subline);
        top.addView(space(14));
        top.addView(scanButton);
        feed = text("", 12, 0xFFC9E7F2, false);
        feed.setTypeface(Typeface.MONOSPACE);
        feed.setPadding(dp(10), dp(8), dp(10), dp(8));
        GradientDrawable fb = new GradientDrawable();
        fb.setColor(0xE6040C14);
        fb.setCornerRadius(dp(6));
        fb.setStroke(dp(1), 0xFF1C5A77);
        feed.setBackground(fb);
        top.addView(space(12));
        top.addView(text("LIVE FEED", 11, 0xFF5F8AA0, true));
        top.addView(feed);
        root.addView(top);
        say("Bastion online. Checks run on this phone only.");

        LinearLayout link = card();
        link.addView(text("Check a link", 17, TEXT, true));
        link.addView(text("Paste a link, or share one to Bastion from your browser or messages, before you open it.", 13, DIM, false));
        linkBox = new EditText(this);
        linkBox.setHint("https://…");
        linkBox.setTextColor(TEXT);
        linkBox.setHintTextColor(DIM);
        linkBox.setSingleLine(true);
        link.addView(linkBox);
        link.addView(button("Check link", false, v -> showLink(String.valueOf(linkBox.getText()))));
        linkResult = column();
        link.addView(linkResult);
        root.addView(link);

        list = column();
        root.addView(list);

        TextView foot = text("No app can see everything on Android: Bastion can't read other apps' data or remove anything by itself. Keep Google Play Protect on and your phone updated.", 12, DIM, false);
        foot.setPadding(dp(4), dp(18), dp(4), 0);
        root.addView(foot);
        setContentView(scroll);
        GuardJob.schedule(this);
        if (Build.VERSION.SDK_INT >= 33 && checkSelfPermission("android.permission.POST_NOTIFICATIONS") != android.content.pm.PackageManager.PERMISSION_GRANTED)
            requestPermissions(new String[]{"android.permission.POST_NOTIFICATIONS"}, 1);
        new Thread(() -> {
            String[] u = GuardJob.updateDue(this);
            if (u != null) ui.post(() -> showUpdate(u));
            PhishLists p = new PhishLists(this);
            p.refresh(false);
            ui.post(() -> { phish = p; say("Phishing lists ready: " + p.size() + " sites."); handleShare(getIntent()); });
        }, "lists").start();
        scan();
    }

    @Override
    protected void onNewIntent(Intent i) {
        super.onNewIntent(i);
        handleShare(i);
    }

    private void showUpdate(String[] u) {
        LinearLayout c = card();
        c.addView(text("Bastion " + u[0] + " is available", 17, GOOD, true));
        c.addView(text("Download it, then open it: Android installs it as an update to the Bastion you have. Android only accepts it if it really comes from the same developer.", 14, TEXT, false));
        c.addView(button("Download update", true, v -> open(new Intent(Intent.ACTION_VIEW, Uri.parse(u[1])))));
        c.addView(button("What's new", false, v -> open(new Intent(Intent.ACTION_VIEW, Uri.parse(u[2])))));
        ((LinearLayout) list.getParent()).addView(c, 1);
    }

    private void handleShare(Intent i) {
        if (i != null && Intent.ACTION_SEND.equals(i.getAction())) {
            String shared = i.getStringExtra(Intent.EXTRA_TEXT);
            if (shared != null) {
                linkBox.setText(shared);
                showLink(shared);
            }
        }
    }

    private void showLink(String text) {
        Links.Result r = Links.check(text, phish);
        say("Link checked: " + r.headline);
        linkResult.removeAllViews();
        int colour = r.level == Links.DANGER ? BAD : r.level == Links.CAUTION ? WARN : GOOD;
        linkResult.addView(space(8));
        linkResult.addView(text(r.headline, 15, colour, true));
        for (String why : r.reasons) linkResult.addView(text("• " + why, 14, TEXT, false));
        if (phish == null || phish.size() == 0) linkResult.addView(text("The phishing lists are still downloading, so only warning signs were checked.", 12, DIM, false));
    }

    private void scan() {
        if (scanning) return;
        scanning = true;
        scanButton.setEnabled(false);
        scanButton.setText("Checking…");
        headline.setText("Checking this phone");
        subline.setText("Looking at installed apps and settings.");
        reactor.setState(GOOD, "SCANNING", true);
        say("Scanning installed apps and phone settings.");
        Set<String> trusted = new HashSet<>(prefs.getStringSet("trusted", new HashSet<>()));
        new Thread(() -> {
            Scanner.Report r;
            try {
                r = new Scanner(this).run(trusted);
            } catch (Exception e) {
                r = null;
            }
            Scanner.Report done = r;
            ui.post(() -> show(done));
        }, "scan").start();
    }

    private void show(Scanner.Report r) {
        scanning = false;
        scanButton.setEnabled(true);
        scanButton.setText("Check again");
        list.removeAllViews();
        if (r == null) {
            headline.setText("The check could not finish");
            reactor.setState(WARN, "STANDBY", false);
            say("Check failed. Tap to try again.");
            subline.setText("Please try again.");
            return;
        }
        int known = 0, check = 0, weak = 0;
        for (Scanner.AppResult a : r.apps) {
            if (a.verdict.level == Judge.KNOWN) known++;
            else if (a.verdict.level == Judge.CHECK) check++;
        }
        for (Scanner.Check c : r.checks) if (!c.ok) weak++;
        reactor.setState(known > 0 ? BAD : check > 0 || weak > 0 ? WARN : GOOD, known > 0 ? "ALERT" : check > 0 ? "CAUTION" : "SECURE", false);
        say(r.appsLooked + " apps checked: " + known + " known bad, " + check + " to look at, " + weak + " weak setting" + (weak == 1 ? "." : "s."));
        if (known > 0) {
            headline.setText("Known stalkerware found");
            headline.setTextColor(BAD);
        } else if (check > 0) {
            headline.setText(check + (check == 1 ? " app" : " apps") + " to look at");
            headline.setTextColor(WARN);
        } else {
            headline.setText("Nothing known-bad found");
            headline.setTextColor(GOOD);
        }
        subline.setText("24/7 checks are on: Bastion re-checks your apps about every 30 minutes and notifies you. " + r.appsLooked + " apps checked. " + (weak == 0 ? "Phone settings look good." : weak + " setting" + (weak == 1 ? "" : "s") + " could be safer.")
                + "\n" + r.listNote);

        if (known > 0) list.addView(advice());

        list.addView(section("Apps"));
        if (r.apps.isEmpty()) list.addView(note("No installed app has the mix of powerful access that spyware needs."));
        for (Scanner.AppResult a : r.apps) list.addView(appCard(a));

        list.addView(section("Phone settings"));
        for (Scanner.Check c : r.checks) list.addView(checkCard(c));
    }

    private View advice() {
        LinearLayout c = card();
        c.addView(text("Before you remove it", 16, BAD, true));
        c.addView(space(6));
        c.addView(text("Stalkerware is usually installed by someone you know. Removing it can alert them. If you might be in danger, talk to a support service first, for example a domestic abuse helpline, and consider using a different phone to ask for help.", 14, TEXT, false));
        c.addView(space(10));
        c.addView(button("Learn more (Coalition Against Stalkerware)", false, v -> open(new Intent(Intent.ACTION_VIEW, Uri.parse("https://stopstalkerware.org/")))));
        return c;
    }

    private View appCard(Scanner.AppResult a) {
        LinearLayout c = card();
        int colour = a.verdict.level == Judge.KNOWN ? BAD : a.verdict.level == Judge.CHECK ? WARN : DIM;
        c.addView(text(a.facts.label, 17, TEXT, true));
        c.addView(text(a.facts.pkg, 12, DIM, false));
        c.addView(space(6));
        c.addView(text(a.verdict.headline, 14, colour, true));
        for (String why : a.verdict.reasons) c.addView(text("• " + why, 14, TEXT, false));
        c.addView(space(10));
        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.VERTICAL);
        row.addView(button("Open app info", false, v -> open(new Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:" + a.facts.pkg)))));
        if (a.facts.accessibilityOn) row.addView(button("Accessibility settings", false, v -> open(new Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS))));
        if (a.facts.deviceAdminOn) row.addView(button("Device admin settings", false, v -> open(new Intent(Settings.ACTION_SECURITY_SETTINGS))));
        if (a.verdict.level != Judge.KNOWN) row.addView(button("I know this app, stop showing it", false, v -> trust(a.facts.pkg)));
        c.addView(row);
        return c;
    }

    private View checkCard(Scanner.Check k) {
        LinearLayout c = card();
        c.addView(text((k.ok ? "✓  " : "!  ") + k.title, 16, k.ok ? GOOD : WARN, true));
        c.addView(space(4));
        c.addView(text(k.detail, 14, TEXT, false));
        if (!k.ok) {
            c.addView(space(8));
            if (k.title.equals("Dangerous-site blocking"))
                c.addView(button("Copy dns.quad9.net", false, v -> {
                    ClipboardManager cb = (ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
                    if (cb != null) cb.setPrimaryClip(ClipData.newPlainText("Private DNS", "dns.quad9.net"));
                    android.widget.Toast.makeText(this, "Copied. Paste it into Private DNS provider hostname.", android.widget.Toast.LENGTH_LONG).show();
                }));
            c.addView(button("Open settings", false, v -> open(new Intent(k.settingsAction))));
        }
        return c;
    }

    private void trust(String pkg) {
        Set<String> t = new HashSet<>(prefs.getStringSet("trusted", new HashSet<>()));
        t.add(pkg);
        prefs.edit().putStringSet("trusted", t).apply();
        scan();
    }

    private void open(Intent i) {
        try {
            startActivity(i);
        } catch (Exception e) {
            try { startActivity(new Intent(Settings.ACTION_SETTINGS)); } catch (Exception ignored) { }
        }
    }

    // ------------------------------------------------------------------ small view helpers
    private int dp(int v) {
        return Math.round(TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, v, getResources().getDisplayMetrics()));
    }

    private LinearLayout column() {
        LinearLayout l = new LinearLayout(this);
        l.setOrientation(LinearLayout.VERTICAL);
        return l;
    }

    /** A line in the live feed; keeps the last eight. Only real events are written here. */
    private void say(String line) {
        String stamp = new java.text.SimpleDateFormat("HH:mm:ss", java.util.Locale.US).format(new java.util.Date());
        String[] old = String.valueOf(feed.getText()).split("\n");
        StringBuilder b = new StringBuilder();
        for (int i = Math.max(0, old.length - 7); i < old.length; i++) if (!old[i].isEmpty()) b.append(old[i]).append('\n');
        feed.setText(b.append('[').append(stamp).append("] ").append(line));
    }

    private LinearLayout card() {
        LinearLayout l = column();
        GradientDrawable g = new GradientDrawable();
        g.setColor(CARD);
        g.setCornerRadius(dp(6));
        g.setStroke(dp(1), LINE);
        l.setBackground(g);
        l.setPadding(dp(16), dp(14), dp(16), dp(14));
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.topMargin = dp(10);
        l.setLayoutParams(lp);
        return l;
    }

    private TextView text(String s, int sp, int colour, boolean bold) {
        TextView t = new TextView(this);
        t.setText(s);
        t.setTextSize(TypedValue.COMPLEX_UNIT_SP, sp);
        t.setTextColor(colour);
        t.setLineSpacing(0, 1.15f);
        if (bold) t.setTypeface(Typeface.create("sans-serif-medium", Typeface.NORMAL));
        return t;
    }

    private TextView section(String s) {
        TextView t = text(s, 13, DIM, true);
        t.setAllCaps(true);
        t.setLetterSpacing(0.08f);
        t.setPadding(dp(4), dp(22), 0, dp(2));
        return t;
    }

    private TextView note(String s) {
        TextView t = text(s, 14, DIM, false);
        t.setPadding(dp(4), dp(8), dp(4), 0);
        return t;
    }

    private View space(int h) {
        View v = new View(this);
        v.setLayoutParams(new LinearLayout.LayoutParams(1, dp(h)));
        return v;
    }

    private Button button(String s, boolean main, View.OnClickListener click) {
        Button b = new Button(this);
        b.setText(s);
        b.setAllCaps(false);
        b.setTextColor(main ? Color.WHITE : TEXT);
        b.setTextSize(TypedValue.COMPLEX_UNIT_SP, 15);
        b.setGravity(Gravity.CENTER);
        GradientDrawable g = new GradientDrawable();
        g.setColor(main ? ACCENT : 0xFF0B2231);
        g.setCornerRadius(dp(4));
        g.setStroke(dp(1), main ? GOOD : 0xFF1C5A77);
        b.setBackground(g);
        b.setOnClickListener(click);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(46));
        lp.topMargin = dp(6);
        b.setLayoutParams(lp);
        return b;
    }
}
