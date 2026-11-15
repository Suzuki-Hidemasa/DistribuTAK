// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.*;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.function.Supplier;

/** 本番のXML構築を文字数とUTF-8の両方で64KiBに収める。 */
final class CotCaptureExport {
    interface Writer<E>{void write(E event,Appendable out)throws IOException;}
    static <E> byte[] position(Object item,Object self,Supplier<E> factory,Writer<E> writer){
        return item!=null&&item==self?read(factory,writer):null;
    }
    static <E> byte[] read(Supplier<E> factory,Writer<E> writer){
        E event=factory.get();if(event==null)return null;
        final class Limited implements Appendable {
            final StringBuilder text=new StringBuilder();boolean limit;
            private IOException limit(){limit=true;return new IOException("CoTの上限です");}
            public Appendable append(char value)throws IOException{if(text.length()>=CotXml.MAX_BYTES)throw limit();text.append(value);return this;}
            public Appendable append(CharSequence value)throws IOException{return append(value,0,value==null?4:value.length());}
            public Appendable append(CharSequence value,int start,int end)throws IOException{
                CharSequence actual=value==null?"null":value;if(end-start>CotXml.MAX_BYTES-text.length())throw limit();text.append(actual,start,end);return this;
            }
        }
        var limited=new Limited();
        try{
            writer.write(event,limited);byte[] xml=limited.text.toString().getBytes(StandardCharsets.UTF_8);
            if(xml.length<=CotXml.MAX_BYTES)return xml;Crypto.wipe(xml);limited.limit=true;
        }catch(IOException failure){return null;}
        return null;
    }
}
