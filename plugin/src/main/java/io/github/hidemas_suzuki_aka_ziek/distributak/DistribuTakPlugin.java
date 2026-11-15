// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import android.app.AlertDialog;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.util.Log;
import android.widget.Button;
import com.atak.plugins.impl.AbstractPlugin;
import com.atak.plugins.impl.AbstractPluginTool;
import com.atak.plugins.impl.PluginContextProvider;
import com.atakmap.android.ipc.AtakBroadcast.DocumentedIntentFilter;
import com.atakmap.android.maps.AbstractMapComponent;
import com.atakmap.android.maps.MapView;
import gov.tak.api.plugin.IServiceController;
import gov.tak.api.ui.IHostUIService;
import gov.tak.api.ui.Pane;
import gov.tak.api.ui.PaneBuilder;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.Crypto;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.Blake2sDigest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.modes.AEADCipher;
import org.bouncycastle.crypto.modes.ChaCha20Poly1305;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.math.ec.rfc7748.X25519;
import org.bouncycastle.math.ec.rfc8032.Ed25519;
import org.bouncycastle.util.encoders.Hex;

/** ツール一覧から、Wi-Fi LANの試験画面を開く。 */
public final class DistribuTakPlugin extends AbstractPlugin {
    private static final String TAG = "DistribuTAK";
    private static final String OPEN = "io.github.hidemas_suzuki_aka_ziek.distributak.OPEN";

    public DistribuTakPlugin(IServiceController services) {
        this(services, services.getService(PluginContextProvider.class).getPluginContext());
    }
    private DistribuTakPlugin(IServiceController services, Context context) {
        super(services, new Tool(context), new Component(services.getService(IHostUIService.class)));
    }
    private static final class Tool extends AbstractPluginTool {
        Tool(Context context) {
            super(context, "DistribuTAK", "Wi-Fi LAN の試験", context.getDrawable(R.drawable.distributak_icon), OPEN);
        }
    }
    private static final class Component extends AbstractMapComponent {
        private final IHostUIService hostUI;
        private Pane pane;
        private AlertDialog dialog;
        private LanScreen screen;
        private LanController controller;

        Component(IHostUIService hostUI) { this.hostUI = hostUI; }
        @Override public void onCreate(Context context, Intent intent, MapView map) {
            screen = new LanScreen(map.getContext());
            controller = AndroidLanRuntime.create(map.getContext(), screen, DistribuTakPlugin::checkBouncyCastleLoader,map);
            screen.attach(controller);
            registerReceiver(context, new BroadcastReceiver() {
                @Override public void onReceive(Context host, Intent event) {
                    if (OPEN.equals(event.getAction())) open(map.getContext());
                }
            }, new DocumentedIntentFilter(OPEN));
        }
        private void open(Context context) {
            screen.setVisible(true);
            if (pane != null) { hostUI.showPane(pane, null); return; }
            if (dialog != null) { dialog.show(); return; }
            android.widget.ScrollView scroll = new android.widget.ScrollView(context);
            scroll.addView(screen.root);
            Button close = new Button(context); close.setText("閉じる"); screen.root.addView(close);
            if (hostUI != null) {
                pane = new PaneBuilder(scroll)
                        .setMetaValue(Pane.RELATIVE_LOCATION, Pane.Location.Right)
                        .setMetaValue(Pane.PREFERRED_WIDTH_RATIO, 0.5)
                        .setMetaValue(Pane.PREFERRED_HEIGHT_RATIO, 1.0)
                        .setMetaValue(Pane.PANE_NAME, "DistribuTAK")
                        .setMetaValue(Pane.RETAIN, true).build();
                close.setOnClickListener(view -> { screen.setVisible(false); hostUI.closePane(pane); });
                hostUI.showPane(pane, null);
            } else {
                dialog = new AlertDialog.Builder(context).setTitle("DistribuTAK").setView(scroll).create();
                dialog.setOnDismissListener(ignored -> screen.setVisible(false));
                close.setOnClickListener(view -> dialog.dismiss()); dialog.show();
            }
        }
        @Override protected void onDestroyImpl(Context context, MapView map) {
            if (screen != null) screen.close();
            if (controller != null) controller.close();
            if (pane != null) hostUI.closePane(pane);
            if (dialog != null) dialog.dismiss();
            pane = null; dialog = null; screen = null; controller = null;
        }
    }

    private static void checkBouncyCastleLoader() {
        ClassLoader pluginLoader = DistribuTakPlugin.class.getClassLoader();
        if (Crypto.class.getClassLoader() != pluginLoader) throw new IllegalStateException("core class loader");
        Class<?>[] classes = {Blake2sDigest.class, SHA256Digest.class, HMac.class, ChaCha20Poly1305.class,
                AESEngine.class, GCMBlockCipher.class, HKDFBytesGenerator.class, AEADParameters.class,
                X25519.class, Ed25519.class, Hex.class, KeyParameter.class, HKDFParameters.class,
                AEADCipher.class, InvalidCipherTextException.class, Digest.class,
                org.bouncycastle.util.Arrays.class};
        boolean matched = true;
        for (Class<?> type : classes) {
            ClassLoader loader = type.getClassLoader();
            boolean same = loader == pluginLoader;
            Log.i(TAG, "Bouncy Castle loader: " + type.getName() + " pluginOwned=" + same + " loader=" + loader);
            matched &= same;
        }
        if (!matched) throw new IllegalStateException("Bouncy Castle class loader conflict");
        Log.i(TAG, "Bouncy Castle loader PASS: checked classes belong to plugin class loader");
    }
}
