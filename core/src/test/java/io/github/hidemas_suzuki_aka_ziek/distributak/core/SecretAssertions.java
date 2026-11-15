// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.lang.reflect.Field;
import static org.junit.jupiter.api.Assertions.*;

/** 消去前に持った参照も調べ、フィールドを差し替えるだけの消去を見逃さない。 */
final class SecretAssertions {
    private SecretAssertions() {}
    static Object field(Object target, String name) throws Exception {
        Field field=target.getClass().getDeclaredField(name);
        field.setAccessible(true);return field.get(target);
    }
    static byte[] bytes(Object target, String name) throws Exception { return (byte[])field(target,name); }
    static void zero(byte[] value) {
        assertNotNull(value);assertArrayEquals(new byte[value.length],value);
    }
}
