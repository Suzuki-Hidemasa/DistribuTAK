// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import android.Manifest;
import android.content.Context;
import android.content.pm.PackageManager;
import android.net.*;
import java.net.*;
import java.util.*;

/** Wi-FiのNetworkを観測し、そのIPv4以外へは結ばない。 */
final class WifiLan implements LanRuntime.Network {
    static final class Selection implements LanRuntime.Link {
        final Network network;final Inet4Address address;final int prefix;
        Selection(Network network,Inet4Address address){this(network,address,io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.LocalNetwork.UNKNOWN_PREFIX);}
        Selection(Network network,Inet4Address address,int prefix){this.network=network;this.address=address;this.prefix=prefix;}
        public int prefixLength(){return prefix;}
        public boolean same(LanRuntime.Link other){
            if(!(other instanceof Selection))return false;
            Selection o=(Selection)other;
            return sameLan(network,address,prefix,o.network,o.address,o.prefix);
        }
        /** 同じ Wi-Fi の同じ番地・同じ prefix か。Android の Network を作らずに試験できる純粋な比べ。 */
        static boolean sameLan(Object network,Inet4Address address,int prefix,Object otherNetwork,Inet4Address otherAddress,int otherPrefix){
            return network.equals(otherNetwork)&&address.equals(otherAddress)&&prefix==otherPrefix;
        }
        public Inet4Address address(){return address;}
        public io.github.hidemas_suzuki_aka_ziek.distributak.core.UdpEndpoint.DatagramIo open(int port)throws java.io.IOException {return new io.github.hidemas_suzuki_aka_ziek.distributak.core.UdpEndpoint.SocketIo(socket(port));}
        @Override public String toString(){return "WifiLan.Selection";}
        java.net.DatagramSocket socket(int port)throws java.io.IOException {
            var socket=new DatagramSocket(null);
            try{network.bindSocket(socket);socket.bind(new InetSocketAddress(address,port));return socket;}
            catch(java.io.IOException|RuntimeException e){socket.close();throw e;}
        }
    }
    private final ConnectivityManager manager;
    private final WifiState<Network> state=new WifiState<>((network,address)->new Selection(network,address,prefixOf(network,address)));
    private final ConnectivityManager.NetworkCallback callback;
    private boolean registered;
    WifiLan(Context host,Runnable changed) {
        for(String permission:new String[]{Manifest.permission.INTERNET,Manifest.permission.ACCESS_NETWORK_STATE})
            if(host.checkSelfPermission(permission)!=PackageManager.PERMISSION_GRANTED)throw new SecurityException("ATAKの通信権限が不足しています");
        manager=(ConnectivityManager)host.getSystemService(Context.CONNECTIVITY_SERVICE);
        if(manager==null)throw new IllegalStateException("回線を調べられません");
        callback=new ConnectivityManager.NetworkCallback(){
            @Override public void onAvailable(Network network){state.available(network);changed.run();}
            @Override public void onLost(Network network){state.lost(network);changed.run();}
            @Override public void onCapabilitiesChanged(Network network,NetworkCapabilities caps){state.capabilities(network,eligible(caps));changed.run();}
            @Override public void onLinkPropertiesChanged(Network network,LinkProperties links){state.addresses(network,addresses(links));changed.run();}
        };
        NetworkRequest request=new NetworkRequest.Builder().addTransportType(NetworkCapabilities.TRANSPORT_WIFI)
                .removeCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET).build();
        // 登録後の初期照会と通知の反映を直列にする。通知の引数は照会し直さず使う。
        synchronized(state){
            manager.registerNetworkCallback(request,callback);registered=true;
            try {
                for(Network network:manager.getAllNetworks()) {
                    var caps=manager.getNetworkCapabilities(network);if(!eligible(caps))continue;
                    state.available(network);state.addresses(network,addresses(manager.getLinkProperties(network)));
                }
            }catch(RuntimeException e){close();throw e;}
        }
    }
    /** manager は state より後に入るが、state が Selection を作るのは登録のあとなので、ここで読んでよい。 */
    private int prefixOf(Network network,Inet4Address address){
        try {
            var properties=manager==null?null:manager.getLinkProperties(network);
            if(properties!=null)for(LinkAddress link:properties.getLinkAddresses())
                if(address.equals(link.getAddress()))return link.getPrefixLength();
        }catch(RuntimeException ignored){}
        return io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.LocalNetwork.UNKNOWN_PREFIX;
    }
    private static boolean eligible(NetworkCapabilities caps){
        return caps!=null&&caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)
                &&!caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)&&!caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN);
    }
    private static List<InetAddress> addresses(LinkProperties properties){
        List<InetAddress> result=new ArrayList<>();
        if(properties!=null)for(LinkAddress link:properties.getLinkAddresses())result.add(link.getAddress());return result;
    }
    public Selection current(){return (Selection)state.snapshot().link;}
    @Override public LanRuntime.NetworkSnapshot snapshot(){return state.snapshot();}
    @Override public void close(){if(registered){registered=false;manager.unregisterNetworkCallback(callback);}}
}
