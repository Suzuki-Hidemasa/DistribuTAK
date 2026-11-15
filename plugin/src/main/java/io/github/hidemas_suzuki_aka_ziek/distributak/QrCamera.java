// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import android.annotation.SuppressLint;
import android.content.Context;
import android.graphics.*;
import android.hardware.camera2.*;
import android.hardware.display.DisplayManager;
import android.media.ImageReader;
import android.os.*;
import android.util.Size;
import android.view.*;
import java.nio.ByteBuffer;
import java.util.*;
import java.util.function.Consumer;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.*;

/** 画像を保存せず、Y平面だけをQRの解析へ渡す。 */
final class QrCamera implements AutoCloseable {
    private final Context context;
    private final TextureView preview;
    private final Consumer<Invitation> found;
    private final Consumer<String> status;
    private final HandlerThread thread=new HandlerThread("distributak-camera");
    private final Handler handler;
    private final Handler main=new Handler(Looper.getMainLooper());
    private final DisplayManager displays;
    private boolean displayRegistered;
    private volatile CameraGeometry.Resolution resolution;
    private volatile int sensorOrientation;
    private int focusMode=-1;
    private final DisplayManager.DisplayListener displayListener=new DisplayManager.DisplayListener(){
        public void onDisplayAdded(int id){}
        public void onDisplayRemoved(int id){}
        public void onDisplayChanged(int id){var display=preview.getDisplay();if(display!=null&&display.getDisplayId()==id)transform();}
    };
    private volatile boolean closed;
    // 以下の資源はcameraのhandlerだけで読み書きする。
    private CameraDevice device;
    private CameraCaptureSession session;
    private ImageReader reader;
    private Surface surface;
    private SurfaceTexture texture;
    private boolean opening;
    QrCamera(Context context,TextureView preview,Consumer<Invitation> found,Consumer<String> status) {
        this.context=context;this.preview=preview;this.found=found;this.status=status;
        displays=(DisplayManager)context.getSystemService(Context.DISPLAY_SERVICE);
        thread.start();handler=new Handler(thread.getLooper());
        try {
        if(displays!=null)try{displays.registerDisplayListener(displayListener,main);displayRegistered=true;}catch(RuntimeException unavailable){fail();}
        preview.setSurfaceTextureListener(new TextureView.SurfaceTextureListener(){
            public void onSurfaceTextureAvailable(SurfaceTexture texture,int width,int height){handler.post(()->open(texture));}
            public void onSurfaceTextureSizeChanged(SurfaceTexture texture,int width,int height){transform();}
            public boolean onSurfaceTextureDestroyed(SurfaceTexture texture){close();return true;}
            public void onSurfaceTextureUpdated(SurfaceTexture texture){}
        });
        if(preview.isAvailable())handler.post(()->open(preview.getSurfaceTexture()));
        }catch(RuntimeException e){close();throw e;}
    }
    @SuppressLint("MissingPermission") // ホストActivityの許可をLanScreenで確認してからだけ作る。
    private void open(SurfaceTexture texture) {
        if(closed||texture==null||reader!=null)return;
        try {
            CameraManager manager=(CameraManager)context.getSystemService(Context.CAMERA_SERVICE);
            if(manager==null)throw new IllegalStateException();String selected=null;
            for(String id:manager.getCameraIdList()) {
                Integer facing=manager.getCameraCharacteristics(id).get(CameraCharacteristics.LENS_FACING);
                if(facing!=null&&facing==CameraCharacteristics.LENS_FACING_BACK){selected=id;break;}
            }
            if(selected==null)throw new IllegalStateException();
            var characteristics=manager.getCameraCharacteristics(selected);
            Integer sensor=characteristics.get(CameraCharacteristics.SENSOR_ORIENTATION);if(sensor==null)throw new IllegalStateException();
            sensorOrientation=sensor;
            int[] af=characteristics.get(CameraCharacteristics.CONTROL_AF_AVAILABLE_MODES);
            if(af!=null){
                for(int mode:af)if(mode==CaptureRequest.CONTROL_AF_MODE_CONTINUOUS_PICTURE)focusMode=mode;
                for(int mode:af)if(mode==CaptureRequest.CONTROL_AF_MODE_CONTINUOUS_VIDEO)focusMode=mode;
            }
            var config=characteristics.get(CameraCharacteristics.SCALER_STREAM_CONFIGURATION_MAP);
            if(config==null)throw new IllegalStateException();
            Size[] yuv=config.getOutputSizes(ImageFormat.YUV_420_888),textures=config.getOutputSizes(SurfaceTexture.class);
            if(yuv==null||textures==null)throw new IllegalStateException();
            List<CameraGeometry.Resolution> yuvSizes=new ArrayList<>(),textureSizes=new ArrayList<>();
            for(Size size:yuv)yuvSizes.add(new CameraGeometry.Resolution(size.getWidth(),size.getHeight()));
            for(Size size:textures)textureSizes.add(new CameraGeometry.Resolution(size.getWidth(),size.getHeight()));
            var size=CameraGeometry.choose(yuvSizes,textureSizes);resolution=size;
            this.texture=texture;texture.setDefaultBufferSize(size.width(),size.height());surface=new Surface(texture);
            main.post(this::transform);
            reader=ImageReader.newInstance(size.width(),size.height(),ImageFormat.YUV_420_888,2);
            reader.setOnImageAvailableListener(images->read(images),handler);
            opening=true;
            manager.openCamera(selected,new CameraDevice.StateCallback(){
                public void onOpened(CameraDevice camera){opening=false;if(closed){camera.close();cleanup();return;}device=camera;capture();}
                public void onDisconnected(CameraDevice camera){opening=false;camera.close();if(closed)cleanup();else fail();}
                public void onError(CameraDevice camera,int error){opening=false;camera.close();if(closed)cleanup();else fail();}
            },handler);
        }catch(Exception e){opening=false;fail();}
    }
    @SuppressWarnings("deprecation") // API23の公開Camera2 API。
    private void capture() {
        try {
            device.createCaptureSession(Arrays.asList(surface,reader.getSurface()),new CameraCaptureSession.StateCallback(){
                public void onConfigured(CameraCaptureSession configured) {
                    if(closed){configured.close();return;}session=configured;
                    try {
                        var request=device.createCaptureRequest(CameraDevice.TEMPLATE_PREVIEW);
                        request.addTarget(surface);request.addTarget(reader.getSurface());
                        if(focusMode>=0)request.set(CaptureRequest.CONTROL_AF_MODE,focusMode);
                        configured.setRepeatingRequest(request.build(),null,handler);
                    }catch(Exception e){fail();}
                }
                public void onConfigureFailed(CameraCaptureSession configured){configured.close();fail();}
            },handler);
        }catch(Exception e){fail();}
    }
    private void read(ImageReader images) {
        byte[] luminance=null;
        try(android.media.Image image=images.acquireLatestImage()) {
            if(image==null||closed)return;
            int width=image.getWidth(),height=image.getHeight();var plane=image.getPlanes()[0];
            luminance=CameraGeometry.luminance(plane.getBuffer(),width,height,plane.getRowStride(),plane.getPixelStride());
            try {
                Invitation invitation=InvitationQr.decode(luminance,width,height);
                if(closed){invitation.close();return;}
                close();found.accept(invitation);
            }catch(Exception invalid){status.accept("招待を読み取れません。QRを画面の中央に合わせてください");}
        }catch(RuntimeException invalid){if(!closed)fail();}
        finally{Crypto.wipe(luminance);}
    }
    /** TextureViewの操作はmainで行う。映像と解析は同じバッファの大きさを使う。 */
    private void transform(){
        if(closed||resolution==null||preview.getWidth()==0||preview.getHeight()==0)return;
        var display=preview.getDisplay();if(display==null)return;
        var size=resolution;
        try {
            var calculated=CameraGeometry.preview(size.width(),size.height(),preview.getWidth(),preview.getHeight(),sensorOrientation,display.getRotation()*90);
            Matrix matrix=new Matrix();matrix.setValues(calculated.texture());preview.setTransform(matrix);
        }catch(RuntimeException invalid){fail();}
    }
    private void fail(){if(!closed){status.accept("カメラを開けません。ほかのカメラ画面を閉じてやり直してください");close();}}
    @Override public void close() {
        if(closed)return;closed=true;
        main.post(()->{if(displayRegistered){displayRegistered=false;SensitiveImage.attempt(()->displays.unregisterDisplayListener(displayListener));}});
        handler.post(this::cleanup);
    }
    private void cleanup(){
            if(session!=null){session.close();session=null;}
            if(device!=null){device.close();device=null;}
            if(reader!=null){reader.close();reader=null;}
            if(surface!=null){surface.release();surface=null;}
            texture=null;
            // openCameraの返事が来るまではcallbackを受けられるようにする。
            if(!opening)thread.quitSafely();
    }
}
