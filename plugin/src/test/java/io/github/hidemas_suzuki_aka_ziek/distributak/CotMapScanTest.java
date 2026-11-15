// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import org.junit.Test;
import static org.junit.Assert.*;
import java.util.*;

public class CotMapScanTest {
    static class Group {List<Group> children=new ArrayList<>();List<String> items=new ArrayList<>();}
    static CotMapScan.Access<Group,String> access=new CotMapScan.Access<>(){
        public Iterable<Group> groups(Group g){return g.children;}
        public Iterable<String> items(Group g){return g.items;}
        public String uid(String i){if(i.equals("throw"))throw new IllegalStateException("private");return i;}
        public String type(String i){return "private-type";}
    };
    @Test public void completeScanCollectsOnlySmallValuesAndCountsGroupsAndItems(){
        var g=new Group();g.items.add("a");var c=new Group();c.items.add("b");g.children.add(c);
        var r=CotMapScan.read(g,access);assertEquals(CotCapturePolicy.Result.SUCCESS,r.result);assertEquals(Set.of("a","b"),r.items.keySet());assertEquals(2,r.visitedItems);assertEquals(2,r.groups);
    }
    @Test public void itemGroupDepthAndUidBoundsAbortWithoutPublishableResult(){
        var g=new Group();for(int i=0;i<8193;i++)g.items.add("a"+i);assertEquals(CotCapturePolicy.Result.LIMIT,CotMapScan.read(g,access).result);
        g=new Group();for(int i=0;i<1024;i++)g.children.add(new Group());assertEquals(CotCapturePolicy.Result.LIMIT,CotMapScan.read(g,access).result);
        g=new Group();var c=g;for(int i=0;i<65;i++){var n=new Group();c.children.add(n);c=n;}assertEquals(CotCapturePolicy.Result.LIMIT,CotMapScan.read(g,access).result);
    }
    @Test public void cyclesDuplicatesExceptionsAndMissingUidAreNotComplete(){
        var g=new Group();g.children.add(g);var r=CotMapScan.read(g,access);assertEquals(CotCapturePolicy.Result.INCONSISTENT,r.result);assertEquals(1,r.overlap);
        g=new Group();g.items.addAll(List.of("a","a"));assertEquals(CotCapturePolicy.Result.INCONSISTENT,CotMapScan.read(g,access).result);
        g=new Group();g.items.add("throw");assertEquals(CotCapturePolicy.Result.INTERRUPTED,CotMapScan.read(g,access).result);
        g=new Group();g.items.add("");assertEquals(CotCapturePolicy.Result.INCONSISTENT,CotMapScan.read(g,access).result);
    }
    @Test public void permittedBoundsSucceedAndMovementBetweenSameGroupsBreaksContinuity(){
        var g=new Group();for(int i=0;i<8192;i++)g.items.add("a"+i);assertEquals(CotCapturePolicy.Result.SUCCESS,CotMapScan.read(g,access).result);
        g=new Group();for(int i=0;i<1023;i++)g.children.add(new Group());assertEquals(CotCapturePolicy.Result.SUCCESS,CotMapScan.read(g,access).result);
        g=new Group();var deep=g;for(int i=0;i<64;i++){var n=new Group();deep.children.add(n);deep=n;}assertEquals(CotCapturePolicy.Result.SUCCESS,CotMapScan.read(g,access).result);
        g=new Group();var child=new Group();g.children.add(child);g.items.add("a");var before=CotMapScan.read(g,access);
        g.items.clear();child.items.add("a");var after=CotMapScan.read(g,access);assertFalse(before.same(after));assertFalse(before.sameTopology(after));
        child.items.clear();assertTrue(after.sameTopology(CotMapScan.read(g,access)));
    }
}
