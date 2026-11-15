// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

/** debug版の架空CoTと柵の確認。固定の種類と件数だけを残す。 */
final class CotFixtureDiagnostics {
    private static final String[] METHODS={"TAK_SERVER","POINT_TO_POINT","ANY","その他"};
    private static final String[] FIXTURES={"従来","柵だけ"};
    private final long[] calls=new long[METHODS.length],consumed=new long[METHODS.length];
    private final long[] fixtureCalls=new long[METHODS.length],fixtureConsumed=new long[METHODS.length];
    private final long[][] fixtures=new long[FIXTURES.length][3];
    private final long[] apiCalls=new long[4],apiFailures=new long[4];
    private final boolean debug;
    private long sendPressed,sendDeclined;
    CotFixtureDiagnostics(boolean debug){this.debug=debug;}
    private void increment(long[] counts,int index){if(!debug)return;int selected=index>=0&&index<counts.length?index:counts.length-1;if(counts[selected]<Long.MAX_VALUE)counts[selected]++;}
    synchronized void processorCalled(int method){increment(calls,method);}
    synchronized void processorConsumed(int method){increment(consumed,method);}
    private synchronized void fixtureCalled(int method){increment(fixtureCalls,method);}
    private synchronized void fixtureConsumed(int method){increment(fixtureConsumed,method);}
    CotSendFilter.Result process(CotFence gate,CotSendFilter.Event event,long now,int method){
        if(!debug)return CotSendFilter.process(gate,event,now);
        processorCalled(method);
        boolean[] fixture={false};
        // 柵が読むUIDをその場で分類する。診断のための読み直しや、例外の握りつぶしはしない。
        CotSendFilter.Event observed=event==null?null:new CotSendFilter.Event(){
            public String uid(){
                String uid=event.uid();
                if(CotPort.FIXTURE_UID.equals(uid)){fixture[0]=true;fixtureCalled(method);}return uid;
            }
            public boolean deletion(){return event.deletion();}
            public int linkCount(){return event.linkCount();}
            public String linkUid(int index){return event.linkUid(index);}
        };
        CotSendFilter.Result result=CotSendFilter.process(gate,observed,now);
        if(result==CotSendFilter.Result.CONSUMED){processorConsumed(method);if(fixture[0])fixtureConsumed(method);}
        return result;
    }
    synchronized void fixture(int mode,int outcome){increment(fixtures[mode],outcome);}
    synchronized void sendPressed(){if(debug&&sendPressed<Long.MAX_VALUE)sendPressed++;}
    synchronized void sendDeclined(){if(debug&&sendDeclined<Long.MAX_VALUE)sendDeclined++;}
    synchronized void apiCalled(int api){increment(apiCalls,api);}
    synchronized void apiFailed(int api){increment(apiFailures,api);}
    private static void append(StringBuilder out,String[] labels,long[] counts){for(int n=0;n<labels.length;n++)out.append(labels[n]).append(": ").append(counts[n]).append(' ');}
    synchronized String text(){
        if(!debug)return "";
        var text=new StringBuilder("\n架空CoT・柵の確認（debug）");
        text.append("\n柵 呼び出し: ");append(text,METHODS,calls);text.append("\n柵 CONSUMED: ");append(text,METHODS,consumed);
        text.append("\n柵 呼び出し（架空）: ");append(text,METHODS,fixtureCalls);text.append("\n柵 CONSUMED（架空）: ");append(text,METHODS,fixtureConsumed);
        for(int mode=0;mode<FIXTURES.length;mode++)text.append("\n架空CoT ").append(FIXTURES[mode]).append(" 入れた: ").append(fixtures[mode][0])
                .append(" 入れなかった: ").append(fixtures[mode][1]).append(" 失敗: ").append(fixtures[mode][2]);
        text.append("\n架空CoT 送らせる 押した: ").append(sendPressed).append(" 断った: ").append(sendDeclined);
        text.append("\nbroadcast 呼び出し: ").append(apiCalls[0]).append(" 例外: ").append(apiFailures[0]);
        text.append("\nservers 呼び出し: ").append(apiCalls[1]).append(" 例外: ").append(apiFailures[1]);
        text.append("\nANY 呼び出し: ").append(apiCalls[2]).append(" 例外: ").append(apiFailures[2]);
        text.append("\nTAK_SERVER 呼び出し: ").append(apiCalls[3]).append(" 例外: ").append(apiFailures[3]);
        return text.toString();
    }
}
