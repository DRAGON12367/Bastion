package io.github.dragon12367.bastion;

import android.graphics.Canvas;
import android.graphics.ColorFilter;
import android.graphics.LinearGradient;
import android.graphics.Paint;
import android.graphics.Path;
import android.graphics.PixelFormat;
import android.graphics.RadialGradient;
import android.graphics.Rect;
import android.graphics.Shader;
import android.graphics.drawable.Drawable;

/** The HUD look shared by phones, tablets and TVs: a hex-grid backdrop and chamfered glass panels with glowing corner brackets. */
final class Hud {
    private Hud() {
    }

    /** Deep gradient, faint hex grid and frame brackets behind the whole screen. */
    static final class Backdrop extends Drawable {
        private final Paint paint = new Paint(Paint.ANTI_ALIAS_FLAG);
        private final Path hex = new Path();
        private final float d;

        Backdrop(float density) {
            d = density;
        }

        @Override
        public void draw(Canvas c) {
            Rect b = getBounds();
            float w = b.width(), h = b.height();
            paint.setStyle(Paint.Style.FILL);
            paint.setShader(new RadialGradient(w * 0.5f, h * 0.18f, Math.max(w, h), new int[]{0xFF0C2233, 0xFF050C14, 0xFF020407}, new float[]{0, 0.6f, 1}, Shader.TileMode.CLAMP));
            c.drawRect(b, paint);
            paint.setShader(null);
            paint.setStyle(Paint.Style.STROKE);
            paint.setStrokeWidth(d);
            paint.setColor(0x123FD8FF);
            float s = 18 * d, dx = (float) (s * Math.sqrt(3)), dy = s * 1.5f;
            for (int r = 0; r * dy < h + s; r++) {
                for (int col = 0; col * dx < w + dx; col++) {
                    float cx = col * dx + (r % 2 == 1 ? dx / 2 : 0), cy = r * dy;
                    hex.reset();
                    for (int k = 0; k < 6; k++) {
                        double a = Math.toRadians(60 * k + 30);
                        float x = cx + (float) (s * Math.cos(a)), y = cy + (float) (s * Math.sin(a));
                        if (k == 0) hex.moveTo(x, y);
                        else hex.lineTo(x, y);
                    }
                    hex.close();
                    c.drawPath(hex, paint);
                }
            }
        }

        @Override public void setAlpha(int a) { }
        @Override public void setColorFilter(ColorFilter f) { }
        @Override public int getOpacity() { return PixelFormat.OPAQUE; }
    }

    /** A chamfered glass panel. The accent colour (cyan, amber or red) shows the state of what is inside. */
    static final class Panel extends Drawable {
        private final Paint paint = new Paint(Paint.ANTI_ALIAS_FLAG);
        private final Path path = new Path();
        private final float d;
        private int accent;

        Panel(float density, int accent) {
            d = density;
            this.accent = accent;
        }

        void setAccent(int colour) {
            accent = colour;
            invalidateSelf();
        }

        @Override
        public void draw(Canvas c) {
            Rect b = getBounds();
            float l = b.left + d, t = b.top + d, r = b.right - d, bt = b.bottom - d, k = 12 * d, L = 16 * d;
            path.reset();
            path.moveTo(l + k, t);
            path.lineTo(r, t);
            path.lineTo(r, bt - k);
            path.lineTo(r - k, bt);
            path.lineTo(l, bt);
            path.lineTo(l, t + k);
            path.close();
            paint.setStyle(Paint.Style.FILL);
            paint.setShader(new LinearGradient(0, t, 0, bt, 0xD80A2232, 0xD8061622, Shader.TileMode.CLAMP));
            c.drawPath(path, paint);
            paint.setShader(null);
            paint.setStyle(Paint.Style.STROKE);
            paint.setStrokeWidth(d);
            paint.setColor(0xFF16506A);
            c.drawPath(path, paint);
            paint.setStrokeWidth(2 * d);
            paint.setColor(accent);
            c.drawLine(l + k, t, l + k + 2 * L, t, paint);
            c.drawLine(r - L, t, r, t, paint);
            c.drawLine(r, t, r, t + L, paint);
            c.drawLine(l, bt, l + L, bt, paint);
            c.drawLine(l, bt, l, bt - L, paint);
            c.drawLine(r - k, bt, r - k - 2 * L, bt, paint);
        }

        @Override public void setAlpha(int a) { }
        @Override public void setColorFilter(ColorFilter f) { }
        @Override public int getOpacity() { return PixelFormat.TRANSLUCENT; }
    }

    /** A live line graph of the last minute of one real reading. */
    static final class Graph extends android.view.View {
        private final Paint paint = new Paint(Paint.ANTI_ALIAS_FLAG);
        private final Path line = new Path(), area = new Path();
        private final float[] values = new float[60];
        private final String name;
        private final int colour;
        private final float d;
        private String text = "--";

        Graph(android.content.Context c, String name, int colour) {
            super(c);
            this.name = name;
            this.colour = colour;
            d = c.getResources().getDisplayMetrics().density;
        }

        void push(float fraction, String text) {
            System.arraycopy(values, 1, values, 0, values.length - 1);
            values[values.length - 1] = Math.max(0, Math.min(1, fraction));
            this.text = text;
            invalidate();
        }

        @Override
        protected void onDraw(Canvas c) {
            float w = getWidth(), h = getHeight(), top = 18 * d;
            paint.setShader(null);
            paint.setStyle(Paint.Style.STROKE);
            paint.setStrokeWidth(d);
            paint.setColor(0x5516506A);
            for (int i = 1; i < 4; i++) {
                float y = top + (h - top) * i / 4;
                c.drawLine(0, y, w, y, paint);
            }
            line.reset();
            for (int i = 0; i < values.length; i++) {
                float x = w * i / (values.length - 1), y = h - 2 * d - (h - top - 2 * d) * values[i];
                if (i == 0) line.moveTo(x, y);
                else line.lineTo(x, y);
            }
            area.set(line);
            area.lineTo(w, h);
            area.lineTo(0, h);
            area.close();
            paint.setStyle(Paint.Style.FILL);
            paint.setShader(new LinearGradient(0, top, 0, h, (colour & 0x00FFFFFF) | 0x6E000000, colour & 0x00FFFFFF, Shader.TileMode.CLAMP));
            c.drawPath(area, paint);
            paint.setShader(null);
            paint.setStyle(Paint.Style.STROKE);
            paint.setStrokeWidth(1.6f * d);
            paint.setColor(colour);
            c.drawPath(line, paint);
            paint.setStyle(Paint.Style.FILL);
            paint.setTextSize(9 * d);
            paint.setLetterSpacing(0.15f);
            paint.setColor(0xFF5F8AA0);
            paint.setTypeface(android.graphics.Typeface.DEFAULT_BOLD);
            paint.setTextAlign(Paint.Align.LEFT);
            c.drawText(name, 0, 11 * d, paint);
            paint.setLetterSpacing(0);
            paint.setTypeface(android.graphics.Typeface.MONOSPACE);
            paint.setTextSize(11 * d);
            paint.setColor(0xFFE9FBFF);
            paint.setTextAlign(Paint.Align.RIGHT);
            c.drawText(text, w, 11 * d, paint);
        }
    }

    /** Threat radar: each blip is an app the last check flagged. Known spyware sits near the centre in red; apps to look at further out in amber. */
    static final class Radar extends android.view.View {
        private final Paint paint = new Paint(Paint.ANTI_ALIAS_FLAG);
        private final android.graphics.Matrix spin = new android.graphics.Matrix();
        private final long t0 = android.os.SystemClock.uptimeMillis();
        private final float d;
        private float[][] blips = new float[0][];

        Radar(android.content.Context c) {
            super(c);
            d = c.getResources().getDisplayMetrics().density;
        }

        /** Each blip: {angle in degrees, distance 0..1, colour}. */
        void setBlips(float[][] b) {
            blips = b;
            invalidate();
        }

        @Override
        protected void onDraw(Canvas c) {
            float w = getWidth(), h = getHeight(), cx = w / 2, cy = (h - 14 * d) / 2, r = Math.min(w, h - 14 * d) / 2 - 4 * d;
            float ang = ((android.os.SystemClock.uptimeMillis() - t0) / 1000f * 80) % 360;
            paint.setShader(null);
            paint.setStyle(Paint.Style.FILL);
            paint.setColor(0xC8040E16);
            c.drawCircle(cx, cy, r, paint);
            paint.setStyle(Paint.Style.STROKE);
            paint.setStrokeWidth(1.5f * d);
            paint.setColor(0x963FD8FF);
            c.drawCircle(cx, cy, r, paint);
            paint.setStrokeWidth(d);
            paint.setColor(0x2D3FD8FF);
            for (float k : new float[]{0.25f, 0.5f, 0.75f}) c.drawCircle(cx, cy, r * k, paint);
            c.drawLine(cx - r, cy, cx + r, cy, paint);
            c.drawLine(cx, cy - r, cx, cy + r, paint);
            android.graphics.SweepGradient sweep = new android.graphics.SweepGradient(cx, cy, new int[]{0x003FD8FF, 0x003FD8FF, 0x783FD8FF}, new float[]{0, 0.88f, 1});
            spin.setRotate(ang, cx, cy);
            sweep.setLocalMatrix(spin);
            paint.setStyle(Paint.Style.FILL);
            paint.setShader(sweep);
            c.drawCircle(cx, cy, r, paint);
            paint.setShader(null);
            for (float[] b : blips) {
                float behind = ((ang - b[0]) % 360 + 360) % 360;
                int glow = Math.max(70, 255 - (int) (behind * 0.7f)), col = (int) b[2];
                double a = Math.toRadians(b[0]);
                float x = cx + (float) Math.cos(a) * r * b[1], y = cy + (float) Math.sin(a) * r * b[1];
                paint.setColor((col & 0x00FFFFFF) | ((glow / 3) << 24));
                c.drawCircle(x, y, 7 * d, paint);
                paint.setColor((col & 0x00FFFFFF) | (glow << 24));
                c.drawCircle(x, y, 3 * d, paint);
            }
            paint.setColor(0xAA3FD8FF);
            paint.setTextAlign(Paint.Align.CENTER);
            paint.setTextSize(9 * d);
            paint.setLetterSpacing(0.15f);
            paint.setTypeface(android.graphics.Typeface.DEFAULT_BOLD);
            c.drawText("THREATS : " + blips.length, cx, h - 2 * d, paint);
            if (isShown()) postInvalidateOnAnimation();
        }
    }
}
