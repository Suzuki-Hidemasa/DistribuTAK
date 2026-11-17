// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.nio.ByteBuffer;
import java.security.SecureRandom;

/**
 * 同じ通信寿命の通常送信と復旧要求へ、重ならない操作番号を発行する。
 * <p>
 * Issues distinct operation identifiers for normal sends and recovery requests within one transport lifetime.
 */
public final class ManagementOperations {
    private final byte[] prefix=new byte[8];
    private long counter;
    private boolean exhausted;
    public ManagementOperations(SecureRandom random){random.nextBytes(prefix);}
    public synchronized byte[] next(){
        if(exhausted)throw new IllegalStateException("Management operation identifiers exhausted");
        byte[] operation=ByteBuffer.allocate(16).put(prefix).putLong(counter).array();
        if(counter==Long.MAX_VALUE)exhausted=true;else counter++;
        return operation;
    }
}
