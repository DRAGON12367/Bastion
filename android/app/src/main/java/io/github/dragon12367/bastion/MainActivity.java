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
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import java.util.HashSet;
import java.util.Set;

/** One screen: a summary, the phone's health checks, and the apps worth a look. Nothing is ever changed without the user tapping. */
public class MainActivity extends Activity {
    static final int BG = 0xFF10151C, CARD = 0xFF171E28, LINE = 0xFF222C39, TEXT = 0xFFE2E8F0, DIM = 0xFF8B96A5;
    static final int GOOD = 0xFF4CC38A, WARN = 0xFFE0A73C, BAD = 0xFFE5534B, ACCENT = 0xFF1F7A55;

    private LinearLayout list;
    private TextView headline, subline;
    private Button scanButton;
    private SharedPreferences prefs;
    private final Handler ui = new Handler(Looper.getMainLooper());
    private boolean scanning;

    @Override
    protected void onCreate(Bundle saved) {
        super.onCreate(saved);
        prefs = getSharedPreferences("bastion", MODE_PRIVATE);
        getWindow().setStatusBarColor(BG);
        getWindow().setNavigationBarColor(BG);

        ScrollView scroll = new ScrollView(this);
        scroll.setBackgroundColor(BG);
        scroll.setFillViewport(true);
        LinearLayout root = column();
        root.setPadding(dp(18), dp(28), dp(18), dp(28));
        scroll.addView(root);

        LinearLayout top = card();
        TextView title = text("Bastion", 26, TEXT, true);
        headline = text("Ready to check this phone", 20, TEXT, true);
        subline = text("Looks at installed apps and phone settings. Nothing about you is sent anywhere.", 14, DIM, false);
        scanButton = button("Check this phone", true, v -> scan());
        top.addView(title);
        top.addView(space(6));
        top.addView(headline);
        top.addView(space(4));
        top.addView(subline);
        top.addView(space(14));
        top.addView(scanButton);
        root.addView(top);

        list = column();
        root.addView(list);

        TextView foot = text("No app can see everything on Android: Bastion can't read other apps' data or remove anything by itself. Keep Google Play Protect on and your phone updated.", 12, DIM, false);
        foot.setPadding(dp(4), dp(18), dp(4), 0);
        root.addView(foot);
        setContentView(scroll);
        scan();
    }

    private void scan() {
        if (scanning) return;
        scanning = true;
        scanButton.setEnabled(false);
        scanButton.setText("Checking…");
        headline.setText("Checking this phone");
        subline.setText("Looking at installed apps and settings.");
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
            subline.setText("Please try again.");
            return;
        }
        int known = 0, check = 0, weak = 0;
        for (Scanner.AppResult a : r.apps) {
            if (a.verdict.level == Judge.KNOWN) known++;
            else if (a.verdict.level == Judge.CHECK) check++;
        }
        for (Scanner.Check c : r.checks) if (!c.ok) weak++;
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
        subline.setText(r.appsLooked + " apps checked. " + (weak == 0 ? "Phone settings look good." : weak + " setting" + (weak == 1 ? "" : "s") + " could be safer.")
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

    private LinearLayout card() {
        LinearLayout l = column();
        GradientDrawable g = new GradientDrawable();
        g.setColor(CARD);
        g.setCornerRadius(dp(12));
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
        g.setColor(main ? ACCENT : 0xFF22303F);
        g.setCornerRadius(dp(8));
        b.setBackground(g);
        b.setOnClickListener(click);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(46));
        lp.topMargin = dp(6);
        b.setLayoutParams(lp);
        return b;
    }
}
