// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * 端末内の呼び名を、値を例外へ含めずに検査する。
 * <p>
 * Validates local labels without including their values in exceptions.
 */
final class LocalLabels {
    private LocalLabels(){}
    static void validate(Map<String,String> labels){
        if(labels.size()>65_536)throw invalid();
        var names=new HashSet<String>();
        for(String label:labels.values()){
            validate(label);if(!names.add(label))throw invalid();
        }
    }
    static void validate(String label){
        if(label==null||label.isEmpty())throw invalid();
        int scalars=0;
        for(int i=0;i<label.length();){
            char ch=label.charAt(i);int point;
            if(Character.isHighSurrogate(ch)){
                if(i+1>=label.length()||!Character.isLowSurrogate(label.charAt(i+1)))throw invalid();
                point=Character.toCodePoint(ch,label.charAt(i+1));i+=2;
            }else{
                if(Character.isLowSurrogate(ch))throw invalid();point=ch;i++;
            }
            if(Character.isISOControl(point)||point==0x2028||point==0x2029||++scalars>32)throw invalid();
        }
        if(label.getBytes(StandardCharsets.UTF_8).length>128)throw invalid();
    }
    private static IllegalArgumentException invalid(){return new IllegalArgumentException("呼び名を確かめてください。32文字・128バイト以内で、空欄・制御文字・重複は使えません");}
}
