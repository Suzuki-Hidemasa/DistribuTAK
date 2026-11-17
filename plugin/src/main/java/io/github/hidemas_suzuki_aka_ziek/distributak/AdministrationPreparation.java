// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.*;
import java.util.*;

/**
 * 核の削除と招待の準備を、保存と配送へつなぐ。作業列からだけ使う。
 * <p>
 * Connects core removal and invitation preparation to storage and delivery. Used only on the worker queue.
 */
final class AdministrationPreparation implements AutoCloseable {
    interface Port {
        void own(AdminRecords.Record certificate);
        void issued(AdminRecords.Record certificate);
        void send(byte[] peer,RenewalMessage message);
        void commit(GroupAdministration.Preparation preparation,GroupAdministration.Candidate candidate);
    }
    final GroupAdministration administration;
    final GroupAdministration.Preparation preparation;
    private final Port port;
    private final SessionManager sessions;
    private final List<byte[]> peers=new ArrayList<>();
    private final boolean invitation;
    private boolean begun,closed;
    AdministrationPreparation(GroupAdministration administration,SessionManager sessions,List<byte[]> removed,boolean invitation,Port port){
        this.administration=administration;this.invitation=invitation;this.port=port;this.sessions=sessions;
        preparation=invitation?administration.prepareInvitation(sessions):administration.prepareRemoval(sessions,removed,true);
        for(var entry:administration.directory().validRecipients())if(sessions.verifiedSession(entry.memberId())!=null)peers.add(entry.memberId());
    }
    void begin(){if(closed||begun)throw new IllegalStateException("操作は取り消しました");preparation.reissue(port::own);begun=true;}
    boolean begun(){return begun;}
    boolean poll(){
        if(closed||!begun)return false;
        if(preparation.expired())throw new IllegalStateException("準備の期限が切れました");
        for(byte[] peer:peers){
            if(preparation.confirm(peer))continue;
            if(sessions.verifiedSession(peer)==null)continue;
            try{var message=preparation.next(peer,port::issued);if(message!=null)port.send(peer,message);}
            catch(SecurityException unavailable){
                if(preparation.phase()==GroupAdministration.Phase.CANCELLED||sessions.verifiedSession(peer)!=null)throw unavailable;
            }
            catch(IllegalArgumentException unavailable){if(sessions.verifiedSession(peer)!=null)throw unavailable;}
        }
        if(invitation){
            var result=preparation.result();
            if(result.timedOut())throw new IllegalStateException("準備の期限が切れました");
            return result.completed();
        }
        if(preparation.incomplete()!=0)return false;
        var candidate=preparation.commit();port.commit(preparation,candidate);return true;
    }
    void reply(byte[] peer,byte[] session,RenewalMessage message){
        if(closed||!begun)return;
        port.send(peer,preparation.reply(peer,session,message,port::issued));
    }
    public void close(){if(closed)return;closed=true;preparation.cancel();administration.close();}
    @Override public String toString(){return "Management preparation";}
}
