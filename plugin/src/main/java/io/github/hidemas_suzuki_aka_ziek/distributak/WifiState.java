// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import java.net.*;
import java.util.*;
import java.util.function.BiFunction;

/** 通知の引数をその場で反映し、途中で元に戻った変化もrevisionに残す。 */
final class WifiState<K> {
    private static final class Entry {boolean eligible=true;Inet4Address address;}
    private final Map<K,Entry> entries=new HashMap<>();
    private final BiFunction<K,Inet4Address,LanRuntime.Link> links;
    private K selected;private Inet4Address address;private int count;private long revision;
    WifiState(BiFunction<K,Inet4Address,LanRuntime.Link> links){this.links=links;}
    synchronized void available(K network){entries.computeIfAbsent(network,k->new Entry()).eligible=true;update();}
    synchronized void lost(K network){entries.remove(network);update();}
    synchronized void capabilities(K network,boolean eligible){entries.computeIfAbsent(network,k->new Entry()).eligible=eligible;update();}
    synchronized void addresses(K network,Collection<InetAddress> addresses){
        entries.computeIfAbsent(network,k->new Entry()).address=LanSupport.selectIpv4(addresses);update();
    }
    private void update(){
        int nextCount=0;K nextNetwork=null;Inet4Address nextAddress=null;
        for(var item:entries.entrySet())if(item.getValue().eligible){nextCount++;nextNetwork=item.getKey();nextAddress=item.getValue().address;}
        if(nextCount!=1){nextNetwork=null;nextAddress=null;}
        if(count!=nextCount||!Objects.equals(selected,nextNetwork)||!Objects.equals(address,nextAddress))revision++;
        count=nextCount;selected=nextNetwork;address=nextAddress;
    }
    synchronized LanRuntime.NetworkSnapshot snapshot(){
        return new LanRuntime.NetworkSnapshot(count==1&&address!=null?links.apply(selected,address):null,revision);
    }
}
