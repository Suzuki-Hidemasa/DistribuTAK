// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import android.Manifest;
import android.app.*;
import android.content.*;
import android.content.pm.PackageManager;
import android.graphics.Bitmap;
import android.graphics.drawable.BitmapDrawable;
import android.os.*;
import android.text.InputType;
import android.view.*;
import android.widget.*;
import java.util.Arrays;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.*;

/** 秘密のDialogと公開状態のPaneの内容。 */
final class LanScreen implements LanController.Ui,AutoCloseable {
    final LinearLayout root;
    private final Context context;
    private final Activity activity;
    private final Handler main=new Handler(Looper.getMainLooper());
    private final TextView state;
    private final Button create,scan,invite,reinvite,connect,send,stop,portButton,erase,dhtRescan,removeUnknown;
    private final Button fenceTest,fenceOnlyTest,fenceBroadcastTest,fenceServersTest,fenceAnyTest,fenceTakServerTest;
    private final EditText port;
    private LanController controller;
    private Dialog sensitive,managementConfirmation;
    private ImageView qrView;
    private Bitmap bitmap;
    private QrCamera camera;
    private SensitivePanel panel;
    private final View.OnLayoutChangeListener windowLayout=(view,l,t,r,b,ol,ot,or,ob)->runMain(()->{if(panel!=null)panel.fit();});
    private boolean closed,permissionPending,visible=true;
    private volatile long sensitiveGeneration;
    private boolean resumed;
    private LanController.Ticket permissionTicket;
    private LanController.Status last;
    private final Application.ActivityLifecycleCallbacks lifecycle=new Application.ActivityLifecycleCallbacks(){
        public void onActivityCreated(Activity a,Bundle b){}
        public void onActivityStarted(Activity a){}
        public void onActivityResumed(Activity a){runMain(()->{if(a==activity){resumed=true;if(permissionPending)checkPermission();}});}
        public void onActivityPaused(Activity a){runMain(()->{if(a==activity){
            // 権限のDialogによる一時停止でも画像は消す。復帰後に許否だけを調べる。
            resumed=false;boolean requested=permissionPending;var ticket=permissionTicket;
            hideSensitive();permissionPending=requested;permissionTicket=ticket;
        }});}
        public void onActivityStopped(Activity a){runMain(()->{if(a==activity)hideSensitive();});}
        public void onActivitySaveInstanceState(Activity a,Bundle b){}
        public void onActivityDestroyed(Activity a){runMain(()->{if(a==activity)close();});}
    };
    LanScreen(Context context) {
        this.context=context;activity=activity(context);resumed=activity!=null&&!activity.isFinishing();root=new LinearLayout(context){
            @Override protected void onVisibilityChanged(View changed,int visibility){super.onVisibilityChanged(changed,visibility);if(visibility!=View.VISIBLE)hideSensitive();}
            @Override protected void onWindowVisibilityChanged(int visibility){super.onWindowVisibilityChanged(visibility);if(visibility!=View.VISIBLE)hideSensitive();}
            @Override protected void onDetachedFromWindow(){hideSensitive();super.onDetachedFromWindow();}
        };root.setOrientation(LinearLayout.VERTICAL);
        int padding=(int)(12*context.getResources().getDisplayMetrics().density);root.setPadding(padding,padding,padding,padding);
        state=new TextView(context);root.addView(state);
        create=button("グループを作る",()->controller.create());scan=button("招待を読む",this::requestScan);
        invite=button("招待QRを出す",()->{hideSensitive();controller.showInvitation(controller.ticket(),Math.min(1024,mediaEdge()));});connect=button("接続する",()->controller.connect());
        reinvite=button("相手を入り直させる",()->{hideSensitive();controller.showRejoinInvitation(controller.ticket(),Math.min(1024,mediaEdge()));});
        send=button("試験DATAを1回送る",()->controller.sendTest());stop=button("通信を止める",()->controller.disconnect());
        dhtRescan=button("DHTを探し直す",()->controller.rescanDht());
        removeUnknown=button("対応のない管理者をすべて外す",()->controller.removeUnknown(controller.ticket()));
        fenceTest=CotFixtureControl.button(BuildConfig.DEBUG,()->button("架空のCoTで柵を確かめる",()->controller.debugFence()));
        fenceOnlyTest=CotFixtureControl.button(BuildConfig.DEBUG,()->button("架空のCoTで柵だけを確かめる",()->controller.debugFenceOnly()));
        fenceBroadcastTest=CotFixtureControl.button(BuildConfig.DEBUG,()->button("架空のCoTを broadcast で送らせる",()->controller.debugFenceSend(CotPort.Send.BROADCAST)));
        fenceServersTest=CotFixtureControl.button(BuildConfig.DEBUG,()->button("架空のCoTを servers で送らせる",()->controller.debugFenceSend(CotPort.Send.SERVERS)));
        fenceAnyTest=CotFixtureControl.button(BuildConfig.DEBUG,()->button("架空のCoTを ANY で送らせる",()->controller.debugFenceSend(CotPort.Send.ANY)));
        fenceTakServerTest=CotFixtureControl.button(BuildConfig.DEBUG,()->button("架空のCoTを TAK_SERVER で送らせる",()->controller.debugFenceSend(CotPort.Send.TAK_SERVER)));
        port=new EditText(context);port.setInputType(InputType.TYPE_CLASS_NUMBER);port.setHint("UDPポート 49152〜65535");root.addView(port);
        portButton=button("ポートを保存",()->{
            try{int value=Integer.parseInt(port.getText().toString());LanSupport.port(value,new java.util.Random());controller.setPort(value);}
            catch(RuntimeException e){Toast.makeText(context,"49152〜65535の番号を入れてください",Toast.LENGTH_SHORT).show();}
        });
        erase=button("消去",()->new AlertDialog.Builder(context).setTitle("鍵と所属を消去します")
                .setMessage("通信を止め、鍵とグループの記録を消します。消去後は別のグループを作るか、新しい招待を読んでください。")
                .setNegativeButton("戻る",null).setPositiveButton("消去",(dialog,which)->runMain(()->{hideSensitive();controller.erase();})).show());
        if(activity!=null){activity.getApplication().registerActivityLifecycleCallbacks(lifecycle);activity.getWindow().getDecorView().addOnLayoutChangeListener(windowLayout);}
    }
    void attach(LanController controller){this.controller=controller;}
    private void runMain(Runnable action){if(controller!=null)controller.runMain(action);else action.run();}
    private void postMain(Runnable action){main.post(()->runMain(action));}
    private void laterMain(Runnable action,long delay){main.postDelayed(()->runMain(action),delay);}
    private Button button(String title,Runnable action){Button button=new Button(context);button.setText(title);button.setEnabled(false);root.addView(button);button.setOnClickListener(view->{if(controller!=null)runMain(action);});return button;}
    private static Activity activity(Context context) {
        for(int n=0;n<16&&context!=null;n++) {
            if(context instanceof Activity)return (Activity)context;
            if(!(context instanceof ContextWrapper))return null;
            Context next=((ContextWrapper)context).getBaseContext();if(next==context)return null;context=next;
        }return null;
    }
    @Override public void render(LanController.Status status) {
        if(closed)return;last=status;state.setText(status.text);boolean usable=status.ready&&status.operationsReady&&!status.busy;
        create.setEnabled(usable&&status.wifi&&StoreRecovery.canCreate(status.member,status.erasing));scan.setEnabled(usable&&status.wifi&&(StoreRecovery.canJoin(status.member)||status.rejoin));
        reinvite.setEnabled(usable&&status.wifi&&status.reinvite);
        invite.setEnabled(usable&&status.wifi&&status.admin);connect.setEnabled(usable&&status.wifi&&status.member);
        send.setEnabled(usable&&status.wifi&&status.member&&status.running);stop.setEnabled(usable&&status.running);
        dhtRescan.setEnabled(usable&&status.wifi&&status.running&&status.dht);
        removeUnknown.setVisibility(status.unknown>0?View.VISIBLE:View.GONE);
        removeUnknown.setEnabled(usable&&status.wifi&&status.running&&status.unknown>0);
        if(fenceTest!=null)fenceTest.setEnabled(usable&&status.running);
        if(fenceOnlyTest!=null)fenceOnlyTest.setEnabled(usable&&status.running);
        if(fenceBroadcastTest!=null)fenceBroadcastTest.setEnabled(usable&&status.running);
        if(fenceServersTest!=null)fenceServersTest.setEnabled(usable&&status.running);
        if(fenceAnyTest!=null)fenceAnyTest.setEnabled(usable&&status.running);
        if(fenceTakServerTest!=null)fenceTakServerTest.setEnabled(usable&&status.running);
        portButton.setEnabled(usable&&!status.running);port.setEnabled(usable&&!status.running);
        if(!port.hasFocus()&&status.port!=0)port.setText(Integer.toString(status.port));erase.setEnabled(!status.busy);
        if(!status.wifi)hideSensitive();
    }
    @Override public void confirmUnknown(Object token,int count){
        if(!foreground()) {controller.cancelManagement();return;}
        hideManagementConfirmation();
        var next=new AlertDialog.Builder(context).setTitle("対応のない管理者をすべて外しますか")
                .setMessage("対象: "+count+" 件。切り替えを確かめてから全員を外します。")
                .setNegativeButton("戻る",(dialog,which)->controller.cancelManagement())
                .setPositiveButton("すべて外す",(dialog,which)->{hideManagementConfirmation();controller.confirmUnknown(token);}).create();
        managementConfirmation=next;
        next.setOnCancelListener(dialog->controller.cancelManagement());
        next.getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);next.show();
    }
    @Override public void hideManagementConfirmation(){
        Dialog previous=managementConfirmation;managementConfirmation=null;
        if(previous!=null){previous.setOnCancelListener(null);previous.dismiss();}
    }
    private Dialog dialog(LinearLayout content) {
        Dialog dialog=new Dialog(context);dialog.requestWindowFeature(Window.FEATURE_NO_TITLE);dialog.setContentView(content);
        Window window=dialog.getWindow();if(window==null)throw new IllegalStateException("画面を開けません");
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE);dialog.setOnDismissListener(ignored->runMain(this::hideSensitive));return dialog;
    }
    private int[] windowSize(){
        var metrics=context.getResources().getDisplayMetrics();
        View decor=activity==null?root.getRootView():activity.getWindow().getDecorView();
        return new int[]{decor.getWidth()>0?decor.getWidth():metrics.widthPixels,decor.getHeight()>0?decor.getHeight():metrics.heightPixels};
    }
    private int mediaEdge(){var size=windowSize();return CameraGeometry.mediaEdge(size[0],size[1],context.getResources().getDisplayMetrics().density);}
    private final class SensitivePanel {
        final LinearLayout root=new LinearLayout(context),controls=new LinearLayout(context);
        final FrameLayout media=new FrameLayout(context);
        SensitivePanel(String title){
            int padding=Math.round(8*context.getResources().getDisplayMetrics().density);root.setPadding(padding,padding,padding,padding);
            controls.setOrientation(LinearLayout.VERTICAL);TextView text=new TextView(context);text.setText("DistribuTAK\n"+title);controls.addView(text);
            Button close=new Button(context);close.setText("閉じる");close.setOnClickListener(view->runMain(LanScreen.this::hideSensitive));controls.addView(close);
            root.addView(media,new LinearLayout.LayoutParams(1,1));root.addView(controls,new LinearLayout.LayoutParams(-1,-2));fit();
        }
        void fit(){
            var size=windowSize();boolean horizontal=size[0]>size[1];int edge=mediaEdge();
            root.setOrientation(horizontal?LinearLayout.HORIZONTAL:LinearLayout.VERTICAL);
            var layout=media.getLayoutParams();if(layout.width!=edge||layout.height!=edge){layout.width=edge;layout.height=edge;media.setLayoutParams(layout);}
            var control=(LinearLayout.LayoutParams)controls.getLayoutParams();int width=horizontal?0:LinearLayout.LayoutParams.MATCH_PARENT;float weight=horizontal?1:0;
            if(control.width!=width||control.weight!=weight){control.width=width;control.weight=weight;controls.setLayoutParams(control);}
        }
    }
    private void showPanel(){
        sensitive=dialog(panel.root);sensitive.show();sensitive.getWindow().setLayout(WindowManager.LayoutParams.MATCH_PARENT,WindowManager.LayoutParams.WRAP_CONTENT);panel.fit();
    }
    @Override public long screenEpoch(){return sensitiveGeneration;}
    @Override public boolean foreground(){return !closed&&visible&&resumed&&activity!=null&&!activity.isFinishing()
            &&root.isAttachedToWindow()&&root.isShown()&&root.getWindowVisibility()==View.VISIBLE;}
    @Override public void qr(byte[] pixels) {
        try {
            clearSensitive();if(!foreground())return;
            panel=new SensitivePanel("招待QR。対面の相手だけに見せてください。60秒で消えます。");
            int side=(int)Math.sqrt(pixels.length);if(side*side!=pixels.length)throw new IllegalArgumentException("QRの画素数が違います");
            int[] colors=new int[pixels.length];
            try {
                for(int i=0;i<colors.length;i++)colors[i]=(pixels[i]&255)==0?0xff000000:0xffffffff;
                bitmap=Bitmap.createBitmap(side,side,Bitmap.Config.ARGB_8888);bitmap.setDensity(Bitmap.DENSITY_NONE);
                bitmap.setPixels(colors,0,side,0,0,side,side);
            }finally{Arrays.fill(colors,0);}
            qrView=new ImageView(context);var drawable=new BitmapDrawable(context.getResources(),bitmap);drawable.setFilterBitmap(false);drawable.setAntiAlias(false);drawable.setDither(false);
            qrView.setScaleType(ImageView.ScaleType.FIT_CENTER);qrView.setImageDrawable(drawable);
            panel.media.addView(qrView,new FrameLayout.LayoutParams(-1,-1));showPanel();long epoch=sensitiveGeneration;
            laterMain(()->{if(epoch==sensitiveGeneration)hideSensitive();},60_000);
        }finally{Crypto.wipe(pixels);}
    }
    private void requestScan() {
        hideSensitive();
        if(activity==null){Toast.makeText(context,"ATAKの画面を取得できません",Toast.LENGTH_SHORT).show();return;}
        LanController.Ticket ticket=controller.ticket();if(!controller.accepts(ticket))return;
        if(context.checkSelfPermission(Manifest.permission.CAMERA)==PackageManager.PERMISSION_GRANTED){startCamera(ticket);return;}
        try {
            var info=context.getPackageManager().getPackageInfo(context.getPackageName(),PackageManager.GET_PERMISSIONS);
            if(info.requestedPermissions==null||!Arrays.asList(info.requestedPermissions).contains(Manifest.permission.CAMERA)) {
                Toast.makeText(context,"ATAKのカメラ権限が不足しています",Toast.LENGTH_LONG).show();return;
            }
            permissionTicket=ticket;permissionPending=true;activity.requestPermissions(new String[]{Manifest.permission.CAMERA},0x4454);
            long epoch=sensitiveGeneration;
            laterMain(()->{if(permissionPending&&epoch==sensitiveGeneration)checkPermission();},1000);
        }catch(Exception e){permissionPending=false;Toast.makeText(context,"カメラの許可が必要です",Toast.LENGTH_LONG).show();}
    }
    private void checkPermission() {
        if(closed||!permissionPending)return;permissionPending=false;
        var ticket=permissionTicket;permissionTicket=null;
        if(context.checkSelfPermission(Manifest.permission.CAMERA)==PackageManager.PERMISSION_GRANTED)startCamera(ticket);
        else Toast.makeText(context,"カメラの許可が必要です。許可してから招待を読むを押してください",Toast.LENGTH_LONG).show();
    }
    private void startCamera(LanController.Ticket ticket) {
        if(!controller.accepts(ticket)||last==null||!last.wifi)return;clearSensitive();
        panel=new SensitivePanel("招待QRをカメラで読み取ります。画像は保存しません。");
        TextView note=new TextView(context);panel.controls.addView(note);
        TextureView preview=new TextureView(context);panel.media.addView(preview,new FrameLayout.LayoutParams(-1,-1));
        showPanel();long epoch=sensitiveGeneration;
        camera=new QrCamera(context,preview,invitation->postMain(()->{
            try{
                if(epoch!=sensitiveGeneration||!controller.accepts(ticket)){invitation.close();return;}
                clearSensitive();controller.join(invitation,ticket);
            }
            catch(RuntimeException e){invitation.close();throw e;}
        }),text->postMain(()->{if(!closed&&epoch==sensitiveGeneration)note.setText(text);}));
        laterMain(()->{if(epoch==sensitiveGeneration)hideSensitive();},60_000);
    }
    void setVisible(boolean visible){this.visible=visible;if(!visible)hideSensitive();}
    @Override public void hideSensitive() {
        if(managementConfirmation!=null){hideManagementConfirmation();if(controller!=null)controller.cancelManagement();}
        sensitiveGeneration++;permissionPending=false;permissionTicket=null;clearSensitive();
    }
    private void clearSensitive(){
        if(camera!=null){QrCamera previousCamera=camera;camera=null;SensitiveImage.attempt(previousCamera::close);}
        panel=null;Dialog previous=sensitive;sensitive=null;if(previous!=null){SensitiveImage.attempt(()->previous.setOnDismissListener(null));SensitiveImage.attempt(previous::dismiss);}
        ImageView view=qrView;qrView=null;Bitmap image=bitmap;bitmap=null;
        SensitiveImage.clear(()->{if(view!=null)view.setImageDrawable(null);},
                ()->{if(image!=null&&!image.isRecycled())image.eraseColor(0);},
                ()->{if(image!=null)image.recycle();});
    }
    @Override public void close(){if(closed)return;closed=true;hideSensitive();if(activity!=null){activity.getApplication().unregisterActivityLifecycleCallbacks(lifecycle);activity.getWindow().getDecorView().removeOnLayoutChangeListener(windowLayout);}}
}
