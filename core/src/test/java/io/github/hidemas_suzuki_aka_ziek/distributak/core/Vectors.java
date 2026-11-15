// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Properties;

final class Vectors {
    final Properties values = new Properties();
    Vectors(String name) throws Exception {
        try (var in = Files.newInputStream(Path.of(System.getProperty("distributak.vectors"), name + ".properties"))) { values.load(in); }
    }
    byte[] bytes(String key) { return CryptoTest.hex(values.getProperty(key)); }
    int count(String key) { return Integer.parseInt(values.getProperty(key+".count")); }
}
