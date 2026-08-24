## LSPromise
Complete exploit chain allowing privilege escalation from local untrusted app to root/kernel.

Tested on Pixel 10 running the initial Android 17 official release.

Usage: Install KernelSU app, open this app, click "Run userspace exploit" then "Run kernel exploit and load KernelSU". After a successful exploitation, KernelSU will be activated and you can use it to grant root access to other apps.

Screen recording: https://t.me/LSPosed/322

## Writeup
The chain is made from two distinct vulnerabilities: one is a 0-day in the Telecom service, the other is a kernel 1-day disclosed 3 months ago, but Android remains vulnerable to it at the time of writing.

### Getting into system_server
The first vulnerability of the chain is a simple logic bug introduced in Android 17. It originates from [a crazy change](https://cs.android.com/android/_/android/platform/packages/services/Telecomm/+/478761578b3ccb380410a4f5e82e1d0e388d59cf), which adds [the following code](https://cs.android.com/android/platform/superproject/+/android-17.0.0_r1:packages/services/Telecomm/src/com/android/server/telecom/InCallController.java;l=2644-2663) to the InCallController.java:
```java
        PackageManager packageManager = mContext.getPackageManager();
        Context userContext = mContext.createContextAsUser(userHandle,
                0 /* flags */);
        PackageManager userPackageManager = userContext != null ?
                userContext.getPackageManager() : packageManager;

        List<ResolveInfo> entries;
        entries = userPackageManager.queryIntentServices(
                serviceIntent,
                PackageManager.GET_META_DATA | PackageManager.MATCH_DISABLED_COMPONENTS);
        for (ResolveInfo entry : entries) {
            ServiceInfo serviceInfo = entry.serviceInfo;

            if (serviceInfo != null) {
                boolean isMetaFlag = serviceInfo.metaData != null &&
                        serviceInfo.metaData.getBoolean(
                                "android.telecom.CLASS_EXISTENCE_CHECK", false);
                if (isMetaFlag && !serviceClassExists(serviceInfo, userHandle)) {
                    continue;
                }
            }
        }
```
Where the [`serviceClassExists()` method is defined as follows](https://cs.android.com/android/platform/superproject/+/android-17.0.0_r1:packages/services/Telecomm/src/com/android/server/telecom/InCallController.java;l=2603-2627):
```java
    /**
     * Verifies that the class for a given ServiceInfo exists within its package.
     * This prevents a system crash if a service is declared in the manifest but its
     * class was not included in the compiled code.
     * @param serviceInfo The ServiceInfo of the service to check.
     * @param userHandle The user under which to check for the service.
     * @return {@code true} if the class exists, {@code false} otherwise.
     */
    private boolean serviceClassExists(ServiceInfo serviceInfo, UserHandle userHandle) {
        Log.i(this, "serviceClassExists check");
        try {
            Context packageContext = mContext.createPackageContextAsUser(
                    serviceInfo.packageName,
                    Context.CONTEXT_INCLUDE_CODE | Context.CONTEXT_IGNORE_SECURITY, userHandle);
            ClassLoader classLoader = packageContext.getClassLoader();
            Class.forName(serviceInfo.name, false, classLoader);
            return true;
        } catch (NameNotFoundException | ClassNotFoundException e) {
            Log.w(this, "Skipping InCallService: class not found for " + serviceInfo.name);
            return false;
        } catch (Exception e) {
            Log.e(this, e, "Error checking for existence of " + serviceInfo.name);
            return false;
        }
    }
```
This is the most unbelievable vulnerability I've ever seen. The code uses `Context.CONTEXT_INCLUDE_CODE | Context.CONTEXT_IGNORE_SECURITY` to load code from an arbitrary app; while there seems to be some effect to protect it from arbitrary code execution, such as passing `false` to `Class.forName()` so it won't trigger class initialization, the app can still declare a custom [AppComponentFactory](https://developer.android.com/reference/android/app/AppComponentFactory) and it will be invoked when `getClassLoader()` is called.

On the other hand, the bug exists in InCallController.java, which is a part of the `com.android.server.telecom` package rather than `com.android.phone`. It should be noticed that the package [declares `android:sharedUserId="android.uid.system"` and `android:process="system"` in AndroidManifest.xml](https://cs.android.com/android/platform/superproject/+/android-17.0.0_r1:packages/services/Telecomm/AndroidManifest.xml;l=93), so it runs in the `system_server` process, one of the most privileged userspace process in Android. Therefore, we now have the ability to execute arbitrary Java code inside `system_server`.

It's a surprise that even a Google engineer can make such a big mistake in the AI era. We found and reported it to the Android Security Team on July 23, 2026. They told us it was a duplicate. Google has switched the monthly security bulletin to quarterly release, which may explain why the vulnerability was not fixed three months after the release of Android 17.

### Getting into network stack
The first bug allows us to escalate privileges to system, but is still far away from root. A complete root requires at least UID 0 and not being restricted by SELinux.

Now it's time to introduce the kernel 1-day: the [DirtyFrag](https://github.com/V4bel/dirtyfrag/blob/master/assets/write-up.md#cve-2026-43284-xfrm-esp-page-cache-write) vulnerabilities. There are 2 variants: CVE-2026-43500 requires `RxRPC` which is disabled for Android Generic Kernels; CVE-2026-43284 requires `xfrm-ESP` and is exploitable on Android. However, [SELinux forbids untrusted apps from using that feature](https://cs.android.com/android/platform/superproject/+/android-17.0.0_r1:system/sepolicy/private/app.te;l=619):
```sepolicy
# Privileged netlink socket interfaces.
neverallow { appdomain -network_stack }
    domain:{
        netlink_tcpdiag_socket
        netlink_nflog_socket
        netlink_xfrm_socket
        netlink_audit_socket
        netlink_dnrt_socket
    } *;
```
The only allowed domains are [`system_server`](https://cs.android.com/android/platform/superproject/+/android-17.0.0_r1:system/sepolicy/private/system_server.te;l=190-195), [`network_stack`](https://cs.android.com/android/platform/superproject/+/android-17.0.0_r1:system/sepolicy/private/network_stack.te;l=93-98) and [`netd`](https://cs.android.com/android/platform/superproject/+/android-17.0.0_r1:system/sepolicy/private/netd.te;l=143-148). In order to exploit DirtyFrag, attackers must first compromise one of the allowlisted privileged process.

Combine two bugs together. While the userspace bug allows us to execute Java code inside `system_server`, SELinux also forbids `system_server` from either [loading native libraries from `/data`](https://cs.android.com/android/platform/superproject/+/android-17.0.0_r1:system/sepolicy/private/system_server.te;l=1559-1562) or [mapping anonymous executable memory](https://cs.android.com/android/platform/superproject/+/android-17.0.0_r1:system/sepolicy/private/system_server.te;l=1572-1580). This makes us impossible to use native languages, increasing the difficulty of exploitation. It would be better if we could inject code into `com.android.networkstack`, which could load native code from our APK and had enough privileges to exploit DirtyFrag.

Luckily, `system_server` is the process where `ActivityManager` runs. `ActivityManager` stores [`IApplicationThread`](https://cs.android.com/android/platform/superproject/+/android-17.0.0_r1:frameworks/base/core/java/android/app/IApplicationThread.aidl)s of every app processes into [a Java map](https://cs.android.com/android/platform/superproject/+/android-17.0.0_r1:frameworks/base/services/core/java/com/android/server/am/ProcessList.java;l=771) and since we run as the same process of `ActivityManager` we can retrieve them using Java reflection. With this, we can send arbitrary commands to `com.android.networkstack` to force it to load our code. 

### Getting into kernel
DirtyFrag allows to overwrite read-only files. This is a powerful primitive in Linux world, because we can overwrite the `su` binary which has the `SUID` bit. However, we don't have `su` in Android world. We refer to [polygraphene's exploit for DirtyPipe](https://github.com/polygraphene/DirtyPipe-Android/blob/master/TECHNICAL-DETAILS.md) to turn DirtyFrag into kernel code execution on Android:
1. We patch `libc.so`, `libc++.so` and `/vendor/lib64/libstagefright_aidl_bufferpool2.so` through DirtyFrag. `libstagefright_aidl_bufferpool2.so` has `vendor_file` domain so it can't be accessed from network stack process. The solution is to patch `/apex/com.android.runtime/bin/crash_dump64` first, execute it, and once we transition to the `crash_dump` domain we can open `libstagefright_aidl_bufferpool2.so`.
2. Create and destroy an orphan process to trigger code execution in init process. Because `libc++.so` is patched, our code gets executed in UID 0 with the `init` domain. We then execute `/vendor/bin/modprobe` to transit to `vendor_modprobe` domain.
3. When `modprobe` is executed, because `libc.so` is also patched, our code is executed under `vendor_modprobe` domain. We can now load kernel modules but only for files that have specified labels. We load `libstagefright_aidl_bufferpool2.so` which has `vendor_file` label.
4. Since we patched `libstagefright_aidl_bufferpool2.so`, the real content of that file got replaced by our own kernel module. Kernel module gets loaded, and now we can do anything, including adjusting SELinux policy or setting SELinux to permissive.
5. We set SELinux to permissive. Now we have UID 0 with SELinux permissive, we launch KernelSU for you.
