package io.github.dragon12367.bastion;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.RadialGradient;
import android.graphics.RectF;
import android.graphics.Shader;
import android.graphics.SweepGradient;
import android.graphics.Matrix;
import android.os.SystemClock;
import android.view.View;

/** The animated core on the main screen. Its colour and word show the real result of the last check; it only animates while on screen. */
public class Reactor extends View {
    private final Paint paint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final RectF box = new RectF();
    private final Matrix spin = new Matrix();
    private final long t0 = SystemClock.uptimeMillis();
    private int colour = 0xFF3FD8FF;
    private String word = "ONLINE";
    private boolean busy;

    public Reactor(Context c) {
        super(c);
    }

    public void setState(int colour, String word, boolean busy) {
        this.colour = colour;
        this.word = word;
        this.busy = busy;
        invalidate();
    }

    private int tint(int alpha) {
        return Color.argb(alpha, Color.red(colour), Color.green(colour), Color.blue(colour));
    }

    private void arcs(Canvas c, float cx, float cy, float r, float width, int segments, float gap, float angle, int alpha) {
        paint.setShader(null);
        paint.setStyle(Paint.Style.STROKE);
        paint.setStrokeWidth(width);
        paint.setColor(tint(alpha));
        box.set(cx - r, cy - r, cx + r, cy + r);
        float span = 360f / segments;
        for (int i = 0; i < segments; i++) c.drawArc(box, angle + i * span, span - gap, false, paint);
    }

    @Override
    protected void onDraw(Canvas c) {
        float t = (SystemClock.uptimeMillis() - t0) / 1000f, speed = busy ? 2.4f : 1f;
        float w = getWidth(), h = getHeight(), cx = w / 2, cy = h / 2, r = Math.min(w, h) / 2 - 4;
        float d = getResources().getDisplayMetrics().density;

        paint.setStyle(Paint.Style.FILL);
        paint.setShader(new RadialGradient(cx, cy, r, new int[]{tint(70), tint(18), tint(0)}, new float[]{0, 0.55f, 1}, Shader.TileMode.CLAMP));
        c.drawCircle(cx, cy, r, paint);

        paint.setShader(null);
        paint.setStyle(Paint.Style.STROKE);
        c.save();
        c.rotate(t * 8 * speed, cx, cy);
        for (int i = 0; i < 72; i++) {
            boolean major = i % 6 == 0;
            paint.setStrokeWidth(major ? 2 * d : d);
            paint.setColor(tint(major ? 210 : 90));
            c.drawLine(cx, cy - r, cx, cy - r + (major ? 9 : 5) * d, paint);
            c.rotate(5, cx, cy);
        }
        c.restore();

        arcs(c, cx, cy, r - 16 * d, 3 * d, 3, 28, -t * 30 * speed, 200);
        arcs(c, cx, cy, r - 26 * d, 6 * d, 12, 9, t * 18 * speed, 120);
        arcs(c, cx, cy, r - 38 * d, 1.5f * d, 1, 0, 0, 90);

        SweepGradient sweep = new SweepGradient(cx, cy, new int[]{tint(0), tint(0), tint(120)}, new float[]{0, 0.82f, 1});
        spin.setRotate(t * 90 * speed, cx, cy);
        sweep.setLocalMatrix(spin);
        paint.setStyle(Paint.Style.FILL);
        paint.setShader(sweep);
        c.drawCircle(cx, cy, r - 40 * d, paint);

        float pulse = 0.5f + 0.5f * (float) Math.sin(t * (busy ? 5 : 2.2));
        float core = r * (0.30f + 0.03f * pulse);
        paint.setShader(new RadialGradient(cx, cy, core, new int[]{0xEBFFFFFF, tint(230), tint(25)}, new float[]{0, 0.35f, 1}, Shader.TileMode.CLAMP));
        c.drawCircle(cx, cy, core, paint);
        paint.setShader(null);
        paint.setStyle(Paint.Style.STROKE);
        paint.setStrokeWidth(2 * d);
        paint.setColor(tint(160 + (int) (80 * pulse)));
        c.drawCircle(cx, cy, core + 6 * d, paint);

        paint.setStyle(Paint.Style.FILL);
        paint.setColor(0xFFE9FBFF);
        paint.setTextAlign(Paint.Align.CENTER);
        paint.setTextSize(Math.max(9 * d, w / 20));
        paint.setFakeBoldText(true);
        paint.setLetterSpacing(0.15f);
        c.drawText(word, cx, cy + core + 22 * d, paint);

        if (isShown()) postInvalidateOnAnimation();
    }
}
