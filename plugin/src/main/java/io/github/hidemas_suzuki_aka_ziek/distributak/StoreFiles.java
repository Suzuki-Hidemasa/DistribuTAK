// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import java.io.File;
import java.io.IOException;

/** 消去と初回の立ち直りで、同じ記録とAtomicFileの一時ファイルを取り除く。 */
final class StoreFiles {
    private StoreFiles(){}
    interface Delete { void delete(File file)throws Exception; }
    static void deleteRecords(File directory,Delete atomicDelete)throws Exception {
        ColdFileStore.clearDirectory(new File(directory,"sync-cache"));
        for(String name:new String[]{"joining.bin","state.bin","settings.bin","sync.bin","external.bin"}) {
            File base=new File(directory,name);atomicDelete.delete(base);remove(base);
        }
    }
    static void remove(File base)throws IOException {
        for(File file:new File[]{base,new File(base+".bak"),new File(base+".new")})
            if(file.exists()&&!file.delete())throw new IOException("消去を完了できません");
    }
}
