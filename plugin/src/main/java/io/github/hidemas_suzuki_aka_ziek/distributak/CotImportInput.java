// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import java.util.function.Predicate;
import java.util.function.Supplier;

/** 入力の不正だけを、予期しない取り込みの失敗から分ける。 */
final class CotImportInput {
    static final class Invalid extends IllegalArgumentException {
        Invalid(){super("入力が無効なため取り込みを見送りました");}
    }
    static <T> T parse(Supplier<T> parser,Predicate<T> valid){
        T event;
        try{event=parser.get();}catch(IllegalArgumentException e){throw new Invalid();}
        if(event==null||!valid.test(event))throw new Invalid();return event;
    }
}
