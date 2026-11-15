// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.*;

/** 保存済みの印と、mainで見てworkerが保存する途中の外来を合わせて見る。 */
final class CotImportGate {
    /** Android側とPC試験で同じ短絡判定を使う。柵の状態・登録そのものは変えない。 */
    static boolean fenced(boolean enabled,java.util.function.BooleanSupplier ready,java.util.function.BooleanSupplier savedUid){
        return enabled&&ready.getAsBoolean()&&savedUid.getAsBoolean();
    }
    static String status(boolean enabled){return enabled?"有効（柵・uidの門で判定）":"停止中";}
    private final java.util.function.Consumer<Runnable> main;
    private final java.util.function.BooleanSupplier active;
    private final java.util.function.Supplier<ExternalMarks> saved;
    private final CotSourceBuffer source;private final boolean enabled;
    private final java.util.function.Consumer<CotRecord> accept;
    private final Runnable externalMatch;
    private final Runnable invalidInput;
    CotImportGate(java.util.function.Consumer<Runnable> main,java.util.function.BooleanSupplier active,java.util.function.Supplier<ExternalMarks> saved,CotSourceBuffer source,boolean enabled,java.util.function.Consumer<CotRecord> accept){this(main,active,saved,source,enabled,accept,()->{});}
    CotImportGate(java.util.function.Consumer<Runnable> main,java.util.function.BooleanSupplier active,java.util.function.Supplier<ExternalMarks> saved,CotSourceBuffer source,boolean enabled,java.util.function.Consumer<CotRecord> accept,Runnable externalMatch){this(main,active,saved,source,enabled,accept,externalMatch,()->{});}
    CotImportGate(java.util.function.Consumer<Runnable> main,java.util.function.BooleanSupplier active,java.util.function.Supplier<ExternalMarks> saved,CotSourceBuffer source,boolean enabled,java.util.function.Consumer<CotRecord> accept,Runnable externalMatch,Runnable invalidInput){this.main=main;this.active=active;this.saved=saved;this.source=source;this.enabled=enabled;this.accept=accept;this.externalMatch=()->{if(enabled)externalMatch.run();};this.invalidInput=invalidInput;}
    void notice(CotRecord record){
        if(!active.getAsBoolean()||!allowed(record))return;
        main.accept(()->{if(active.getAsBoolean()&&allowed(record)&&enabled){try{accept.accept(record);}catch(CotImportInput.Invalid e){invalidInput.run();}}});
    }
    private boolean allowed(CotRecord record){return source.permitsImport(record.uid(),saved,externalMatch);}
    static boolean allowed(CotRecord record,ExternalMarks saved,CotSourceBuffer source){return allowed(record,()->saved,source);}
    static boolean allowed(CotRecord record,java.util.function.Supplier<ExternalMarks> saved,CotSourceBuffer source){return source.permitsImport(record.uid(),saved);}
}
