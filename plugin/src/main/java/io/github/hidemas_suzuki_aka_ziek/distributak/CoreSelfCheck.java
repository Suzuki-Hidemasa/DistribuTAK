// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.Crypto;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.NoiseHandshake;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.NoiseTransport;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.Totp;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.TotpVerifier;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.function.LongSupplier;

/** 保存・通信をせず、毎回新しく作った鍵で核を呼ぶ。 */
final class CoreSelfCheck {
    private CoreSelfCheck() {}

    static void run(Clock wallClock, LongSupplier monotonicNanos) {
        byte[] initiatorSecret = new byte[32], responderSecret = new byte[32];
        byte[] psk = new byte[32], totpSecret = new byte[32];
        SecureRandom random = new SecureRandom();
        try {
            random.nextBytes(initiatorSecret); random.nextBytes(responderSecret);
            random.nextBytes(psk); random.nextBytes(totpSecret);
            byte[] responderPublic = Crypto.x25519Public(responderSecret);
            byte[] initiatorPublic = Crypto.x25519Public(initiatorSecret);
            byte[] prologue = "DistribuTAK self-check".getBytes(StandardCharsets.US_ASCII);
            byte[] firstPayload = {1}, secondPayload = {2};
            try (NoiseHandshake initiator = new NoiseHandshake(true, initiatorSecret, responderPublic, psk, prologue);
                 NoiseHandshake responder = new NoiseHandshake(false, responderSecret, null, psk, prologue)) {
                if (!Crypto.equal(firstPayload, responder.readMessage(initiator.writeMessage(firstPayload)))
                        || !Crypto.equal(secondPayload, initiator.readMessage(responder.writeMessage(secondPayload)))) {
                    throw new IllegalStateException("握手の自己確認に失敗");
                }
                try (NoiseTransport sending = initiator.transport(monotonicNanos);
                     NoiseTransport receiving = responder.transport(monotonicNanos)) {
                    byte[] plaintext = "DistribuTAK".getBytes(StandardCharsets.US_ASCII);
                    byte[] decrypted = receiving.receive(sending.send(plaintext));
                    try {
                        if (!Crypto.equal(plaintext, decrypted)) throw new IllegalStateException("転送の自己確認に失敗");
                    } finally { Crypto.wipe(plaintext); Crypto.wipe(decrypted); }
                }
            }
            // 30秒の境界で実時計が進んでも、自己確認の入力を同じ時点にそろえる。
            Instant now = wallClock.instant();
            try (TotpVerifier verifier = new TotpVerifier(totpSecret,
                    Clock.fixed(now, ZoneOffset.UTC), monotonicNanos)) {
                String code = Totp.generate(totpSecret, now);
                if (verifier.verify(initiatorPublic, code) != TotpVerifier.Result.VALID
                        || !verifier.consume(initiatorPublic, code)
                        || verifier.verify(initiatorPublic, code) != TotpVerifier.Result.RETRANSMISSION) {
                    throw new IllegalStateException("TOTP の自己確認に失敗");
                }
            }
        } finally {
            Crypto.wipe(initiatorSecret); Crypto.wipe(responderSecret);
            Crypto.wipe(psk); Crypto.wipe(totpSecret);
        }
    }
}
