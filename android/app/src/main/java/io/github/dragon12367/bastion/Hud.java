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
}
