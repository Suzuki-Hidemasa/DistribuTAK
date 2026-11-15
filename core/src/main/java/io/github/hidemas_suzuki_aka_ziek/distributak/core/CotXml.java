// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.io.StringReader;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import javax.xml.parsers.SAXParserFactory;
import org.xml.sax.Attributes;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;
import org.xml.sax.helpers.DefaultHandler;

/** XMLは検査だけを行い、中継するバイト列を直列化し直さない。 */
public final class CotXml {
    public static final int MAX_BYTES=65536;
    public static final long MAX_STALE_MILLIS=30L*24*60*60*1000;
    public static final long MAX_FUTURE_MILLIS=300000;
    private CotXml() {}
    public record Fields(String uid,long stale) {
        @Override public String toString() { return "CoT fields"; }
    }
    static byte[] utf8(String text) {
        if(text==null)throw invalid();
        try {
            ByteBuffer bytes=StandardCharsets.UTF_8.newEncoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT).encode(java.nio.CharBuffer.wrap(text));
            byte[] out=new byte[bytes.remaining()];bytes.get(out);return out;
        } catch(CharacterCodingException e) { throw invalid(); }
    }
    private static String text(byte[] xml) {
        if(xml==null||xml.length==0||xml.length>MAX_BYTES)throw invalid();
        try {
            return StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(xml)).toString();
        } catch(CharacterCodingException e) { throw invalid(); }
    }
    private static IllegalArgumentException invalid() { return new IllegalArgumentException("CoT の形式が違います"); }
    public static Fields inspect(byte[] xml) {
        String input=text(xml);
        // StringReaderでUTF-8を確定し、宣言をパーサーへ渡す前にも断る。
        if(input.contains("<!DOCTYPE")||input.contains("<!ENTITY"))throw invalid();
        final class Handler extends DefaultHandler {
            int depth,elements;String uid;long stale;
            @Override public void startElement(String uri,String local,String name,Attributes attrs) throws SAXException {
                if(++depth>32||++elements>4096)throw new SAXException("CoT limit");
                if(depth==1) {
                    if(!name.equals("event"))throw new SAXException("CoT root");
                    uid=attrs.getValue("uid");String value=attrs.getValue("stale");
                    try { stale=Instant.parse(value).toEpochMilli(); }
                    catch(RuntimeException e) { throw new SAXException("CoT time"); }
                    if(uid==null||uid.isEmpty()||stale<0)throw new SAXException("CoT fields");
                }
            }
            @Override public void endElement(String uri,String local,String name) { depth--; }
            @Override public InputSource resolveEntity(String publicId,String systemId) throws SAXException { throw new SAXException("CoT external entity"); }
            @Override public void error(SAXParseException e) throws SAXException { throw new SAXException("CoT XML"); }
            @Override public void fatalError(SAXParseException e) throws SAXException { throw new SAXException("CoT XML"); }
        }
        var handler=new Handler();
        try {
            var factory=SAXParserFactory.newInstance();factory.setNamespaceAware(false);factory.setValidating(false);
            var reader=factory.newSAXParser().getXMLReader();
            reader.setFeature("http://xml.org/sax/features/external-general-entities",false);
            reader.setFeature("http://xml.org/sax/features/external-parameter-entities",false);
            reader.setContentHandler(handler);reader.setEntityResolver(handler);reader.setErrorHandler(handler);
            reader.parse(new InputSource(new StringReader(input)));
            if(handler.elements==0||handler.depth!=0)throw invalid();
            return new Fields(handler.uid,handler.stale);
        } catch(Exception e) { throw invalid(); }
    }
    /** 自分の送信前だけに使う。元のXMLと、stale以外のバイト列は変えない。 */
    public static byte[] shortenStale(byte[] xml,long now) {
        Fields fields=inspect(xml);if(now<0||now>Long.MAX_VALUE-MAX_STALE_MILLIS)throw invalid();
        if(fields.stale<=now+MAX_STALE_MILLIS)return xml.clone();
        String input=text(xml);int at=0;
        // 検査済みのXMLからルートの開始タグを探す。コメント内のeventを選ばない。
        while(at<input.length()) {
            if(Character.isWhitespace(input.charAt(at))||input.charAt(at)=='\ufeff') { at++;continue; }
            if(input.startsWith("<?",at)) { at=input.indexOf("?>",at)+2;continue; }
            if(input.startsWith("<!--",at)) { at=input.indexOf("-->",at)+3;continue; }
            break;
        }
        if(!input.startsWith("<event",at))throw invalid();at+=6;
        while(at<input.length()) {
            while(Character.isWhitespace(input.charAt(at)))at++;
            if(input.charAt(at)=='>'||input.charAt(at)=='/')break;
            int nameAt=at;while(at<input.length()&&!Character.isWhitespace(input.charAt(at))&&input.charAt(at)!='=')at++;
            String name=input.substring(nameAt,at);
            while(Character.isWhitespace(input.charAt(at)))at++;
            if(input.charAt(at++)!='=')throw invalid();
            while(Character.isWhitespace(input.charAt(at)))at++;
            char quote=input.charAt(at++);int valueAt=at;at=input.indexOf(quote,at);
            if(at<0)throw invalid();
            if(name.equals("stale")) {
                String value=Instant.ofEpochMilli(now+MAX_STALE_MILLIS-MAX_FUTURE_MILLIS).toString();
                byte[] out=utf8(input.substring(0,valueAt)+value+input.substring(at));
                if(out.length>MAX_BYTES)throw invalid();return out;
            }
            at++;
        }
        throw invalid();
    }
}
