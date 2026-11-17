// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import java.util.*;

/**
 * 案Bでは開始時の写しと切断の観測を使い、自動の再鍵だけでは候補にしない（04 §4.5）。
 * <p>
 * Scheme B uses the initial snapshot and observed disconnection, excluding automatic rekeys alone (04 §4.5).
 */
final class NamingCandidates {
    private final Map<String,byte[]> initial;
    private final Set<String> disconnected=new HashSet<>();
    NamingCandidates(Map<String,byte[]> initial){this.initial=new HashMap<>(initial);}
    Map<String,byte[]> observe(Map<String,byte[]> current){
        for(String identity:initial.keySet())if(!current.containsKey(identity))disconnected.add(identity);
        var result=new HashMap<>(current);
        result.entrySet().removeIf(e->initial.containsKey(e.getKey())&&(!disconnected.contains(e.getKey())||Arrays.equals(initial.get(e.getKey()),e.getValue())));
        return result;
    }
    @Override public String toString(){return "Naming candidates";}
}
