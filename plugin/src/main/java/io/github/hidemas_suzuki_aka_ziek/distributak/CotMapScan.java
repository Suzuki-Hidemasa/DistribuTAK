// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import java.nio.charset.StandardCharsets;
import java.util.*;
import static io.github.hidemas_suzuki_aka_ziek.distributak.CotCapturePolicy.*;

/** 第1段。MapItemやXMLを待ちへ渡さず、uidと型だけを残す。 */
final class CotMapScan {
    interface Access<G,I> {Iterable<G> groups(G group);Iterable<I> items(G group);String uid(I item);String type(I item);}
    static final class Snapshot {
        final Map<String,String> items=new LinkedHashMap<>();
        final IdentityHashMap<Object,Object> topology=new IdentityHashMap<>();
        final Map<String,Object> location=new HashMap<>();
        Result result=Result.SUCCESS;
        int visitedItems,groups,overlap;
        boolean sameTopology(Snapshot other){
            if(!topology.equals(other.topology))return false;
            for(var entry:location.entrySet())if(other.location.containsKey(entry.getKey())&&other.location.get(entry.getKey())!=entry.getValue())return false;
            return true;
        }
        boolean same(Snapshot other){return result==Result.SUCCESS&&other.result==Result.SUCCESS&&items.equals(other.items)&&sameTopology(other);}
    }
    private static final class Halt extends RuntimeException {final Result reason;Halt(Result reason){this.reason=reason;}}
    static <G,I> Snapshot read(G root,Access<G,I> access){
        var result=new Snapshot();
        try{if(root==null)throw new Halt(Result.INTERRUPTED);visit(root,null,access,0,result);}
        catch(Halt stop){result.result=stop.reason;}
        catch(RuntimeException failure){result.result=Result.INTERRUPTED;}
        return result;
    }
    private static <G,I> void visit(G group,G parent,Access<G,I> access,int depth,Snapshot out){
        if(group==null)throw new Halt(Result.INCONSISTENT);
        if(depth>MAX_DEPTH||++out.groups>MAX_GROUPS)throw new Halt(Result.LIMIT);
        if(out.topology.containsKey(group)){out.overlap++;throw new Halt(Result.INCONSISTENT);}out.topology.put(group,parent);
        for(I item:access.items(group)){
            if(++out.visitedItems>MAX_ITEMS)throw new Halt(Result.LIMIT);
            String uid=access.uid(item),type=access.type(item);
            if(uid==null||uid.isEmpty()||uid.length()>256||uid.getBytes(StandardCharsets.UTF_8).length>256||type!=null&&type.length()>256)throw new Halt(Result.INCONSISTENT);
            if(out.items.containsKey(uid)){out.overlap++;throw new Halt(Result.INCONSISTENT);}
            out.items.put(uid,type);
            out.location.put(uid,group);
        }
        for(G child:access.groups(group))visit(child,group,access,depth+1,out);
    }
}
