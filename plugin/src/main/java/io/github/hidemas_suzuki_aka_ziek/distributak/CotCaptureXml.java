// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.*;
import java.nio.charset.StandardCharsets;
import java.io.StringReader;
import java.time.Instant;
import java.util.*;
import javax.xml.parsers.SAXParserFactory;
import org.xml.sax.*;
import org.xml.sax.helpers.DefaultHandler;

/** XMLの値や名前を診断へ渡さない。比較用の要約だけをメモリに持つ。 */
final class CotCaptureXml {
    static final Set<String> EXCLUDED=Set.of(); // 実測で確かめるまでは何も除かない。
    static final Set<String> CLOCK_FIELDS=Set.of("time","start","stale");
    static byte[] fingerprint(byte[] xml,Set<String> excluded){
        CotXml.inspect(xml);if(excluded.isEmpty())return Crypto.blake2s(xml);
        byte[][] parts=parts(xml,excluded);byte[] joined=new byte[128];for(int i=0;i<4;i++)System.arraycopy(parts[i],0,joined,32*i,32);
        try{return Crypto.blake2s(joined);}finally{Crypto.wipe(joined);}
    }
    /** 根の時刻属性3つと、それ以外の意味内容を別々に要約する。 */
    static byte[][] parts(byte[] xml,Set<String> excluded){
        CotXml.inspect(xml);
        final class Handler extends DefaultHandler {
            final org.bouncycastle.crypto.digests.Blake2sDigest[] hashes=new org.bouncycastle.crypto.digests.Blake2sDigest[4];int depth;
            Handler(){for(int i=0;i<4;i++)hashes[i]=new org.bouncycastle.crypto.digests.Blake2sDigest(256);}
            void token(int n,String value){byte[] b=value.getBytes(StandardCharsets.UTF_8);var d=hashes[n];d.update((byte)(b.length>>>24));d.update((byte)(b.length>>>16));d.update((byte)(b.length>>>8));d.update((byte)b.length);d.update(b,0,b.length);Crypto.wipe(b);}
            @Override public void startElement(String uri,String local,String name,Attributes attrs){
                depth++;token(3,"<"+name);var names=new ArrayList<String>();for(int i=0;i<attrs.getLength();i++)names.add(attrs.getQName(i));Collections.sort(names);
                for(String a:names){
                    int n=depth==1?"time".equals(a)?0:"start".equals(a)?1:"stale".equals(a)?2:3:3;
                    if(depth==1&&excluded.contains(a))continue;
                    token(n,a);token(n,attrs.getValue(a));
                }
            }
            @Override public void endElement(String uri,String local,String name){token(3,"/"+name);depth--;}
            @Override public void characters(char[] c,int start,int length){token(3,new String(c,start,length));}
            @Override public InputSource resolveEntity(String p,String s)throws SAXException{throw new SAXException("CoT external entity");}
            @Override public void error(SAXParseException e)throws SAXException{throw new SAXException("CoT XML");}
            @Override public void fatalError(SAXParseException e)throws SAXException{throw new SAXException("CoT XML");}
        }
        var h=new Handler();
        try{
            var f=SAXParserFactory.newInstance();f.setNamespaceAware(false);f.setValidating(false);var r=f.newSAXParser().getXMLReader();
            r.setFeature("http://xml.org/sax/features/external-general-entities",false);r.setFeature("http://xml.org/sax/features/external-parameter-entities",false);
            r.setContentHandler(h);r.setEntityResolver(h);r.setErrorHandler(h);r.parse(new InputSource(new StringReader(new String(xml,StandardCharsets.UTF_8))));
            byte[][] out=new byte[4][32];for(int i=0;i<4;i++)h.hashes[i].doFinal(out[i],0);return out;
        }catch(Exception failure){throw new IllegalArgumentException("CoTを比較できません");}
    }
    /** 検査済みの根のstaleだけを置換し、測位の期限を延ばさない。 */
    static byte[] stale(byte[] xml,long stale){
        CotXml.inspect(xml);String s=new String(xml,StandardCharsets.UTF_8);
        // コメントや宣言はルートの前にあり得る。属性の名前・引用符を順に読む。
        int at=0;
        while(at<s.length()){
            if(Character.isWhitespace(s.charAt(at))||s.charAt(at)=='\ufeff'){at++;continue;}
            if(s.startsWith("<?",at)){at=s.indexOf("?>",at)+2;continue;}
            if(s.startsWith("<!--",at)){at=s.indexOf("-->",at)+3;continue;}break;
        }
        at+=6;
        while(at<s.length()){
            while(Character.isWhitespace(s.charAt(at)))at++;
            if(s.charAt(at)=='>'||s.charAt(at)=='/')break;
            int begin=at;while(!Character.isWhitespace(s.charAt(at))&&s.charAt(at)!='=')at++;
            String name=s.substring(begin,at);while(Character.isWhitespace(s.charAt(at)))at++;at++;
            while(Character.isWhitespace(s.charAt(at)))at++;char quote=s.charAt(at++);int value=at;at=s.indexOf(quote,at);
            if(name.equals("stale")){byte[] out=(s.substring(0,value)+Instant.ofEpochMilli(stale)+s.substring(at)).getBytes(StandardCharsets.UTF_8);CotXml.inspect(out);return out;}at++;
        }
        throw new IllegalArgumentException("CoTの期限がありません");
    }
}
