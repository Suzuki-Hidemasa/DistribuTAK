// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import com.google.zxing.*;
import com.google.zxing.common.*;
import com.google.zxing.qrcode.*;
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel;
import java.net.*;
import java.util.*;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.*;

final class InvitationQr {
    private InvitationQr(){}
    static byte[] encode(Invitation invitation,int size)throws WriterException {
        BitMatrix bits=new QRCodeWriter().encode(InvitationUrl.encode(invitation),BarcodeFormat.QR_CODE,size,size,
                Map.of(EncodeHintType.ERROR_CORRECTION,ErrorCorrectionLevel.M,EncodeHintType.MARGIN,4));
        size=bits.getWidth();
        byte[] image=new byte[size*size];
        try {for(int y=0;y<size;y++)for(int x=0;x<size;x++)image[y*size+x]=(byte)(bits.get(x,y)?0:255);return image;}
        finally {bits.clear();}
    }
    static Invitation decode(byte[] luminance,int width,int height)throws Exception {
        if(width<=0 || height<=0 || (long)width*height!=luminance.length || luminance.length>4096*4096)
            throw new IllegalArgumentException("画像の長さが違います");
        byte[] view=luminance;int viewWidth=width,viewHeight=height;
        QRCodeReader reader=new QRCodeReader();ReaderException last=NotFoundException.getNotFoundInstance();
        try {
            // 通常の検出に失敗したときだけ走査の向きを変える。PURE_BARCODEは使わない。
            for(int turn=0;turn<4;turn++) {
                var source=new PlanarYUVLuminanceSource(view,viewWidth,viewHeight,0,0,viewWidth,viewHeight,false);
                try{return parse(reader.decode(new BinaryBitmap(new HybridBinarizer(source)),
                        Collections.singletonMap(DecodeHintType.TRY_HARDER,Boolean.TRUE)).getText());}
                catch(ReaderException invalid){last=invalid;}
                finally{reader.reset();}
                if(turn<3){
                    byte[] rotated=new byte[view.length];
                    for(int y=0;y<viewHeight;y++)for(int x=0;x<viewWidth;x++)rotated[x*viewHeight+viewHeight-1-y]=view[y*viewWidth+x];
                    if(view!=luminance)Crypto.wipe(view);view=rotated;
                    int previous=viewWidth;viewWidth=viewHeight;viewHeight=previous;
                }
            }
            throw last;
        }finally{if(view!=luminance)Crypto.wipe(view);}
    }
    static Invitation parse(String text)throws Exception {
        if(text==null || text.length()>1024)throw new IllegalArgumentException("招待の長さが違います");
        Invitation invitation=InvitationUrl.decode(text);
        try {
            InetAddress address=InetAddress.getByAddress(invitation.adminAddress());
            if(LanSupport.selectIpv4(Collections.singletonList(address))==null)
                throw new SecurityException("招待はWi-FiのIPv4だけです");
            return invitation;
        } catch(Exception e) {invitation.close();throw e;}
    }
}
