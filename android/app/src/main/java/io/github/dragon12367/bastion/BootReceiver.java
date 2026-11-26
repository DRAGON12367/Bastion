package io.github.dragon12367.bastion;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;

/** After a restart or an app update, makes sure the 24/7 check is still scheduled. */
public class BootReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context c, Intent i) {
        GuardJob.schedule(c);
    }
}
