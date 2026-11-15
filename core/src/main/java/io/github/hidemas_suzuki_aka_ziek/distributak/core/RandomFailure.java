// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

/** 乱数の失敗を時計の失敗と区別する。元の例外の値は引き継がない。 */
final class RandomFailure extends RuntimeException {
    RandomFailure() { super("乱数を作れません"); }
}
