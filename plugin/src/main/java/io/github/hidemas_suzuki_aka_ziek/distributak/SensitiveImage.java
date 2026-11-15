// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

/** UIから外して画素を消し、最後に解放する。後始末の例外をホストへ渡さない。 */
final class SensitiveImage {
    private SensitiveImage(){}
    static void clear(Runnable detach,Runnable erase,Runnable recycle){
        attempt(detach);attempt(erase);attempt(recycle);
    }
    static void attempt(Runnable action){try{action.run();}catch(RuntimeException ignored){}}
}
