package org.lsposed.lspromise;

import static org.lsposed.lspromise.Shellcode.TAG;

import android.os.IBinder;
import android.os.Parcel;
import android.util.Log;

public class DirtyFrag {

    // Step 1: patch vendor file as kernel module
    public static native int patchMod();

    // Step 2: patch libc for modprobe to load module
    public static native int patchLibc();

    // Step 3: patch libc++ for init to execute modprobe
    public static native int patchCxx();

    // Step 4: create orphaned process and kill it to trigger init shell code
    public static native int createOrphanProcess();

    private final IBinder reporterBinder;

    public DirtyFrag(IBinder b) {
        reporterBinder = b;
    }

    public native void runAll();

    public void report(String msg) {
        var p = Parcel.obtain();
        try {
            p.writeString(msg);
            reporterBinder.transact(1, p, null, IBinder.FLAG_ONEWAY);
        } catch (Throwable t) {
            Log.e(TAG, "report failed (" + msg + ")", t);
        } finally {
            p.recycle();
        }
    }
}
