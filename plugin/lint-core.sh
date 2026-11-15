#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
set -euo pipefail
plugin_root="$(cd -- "$(dirname -- "$0")" && pwd)"
project_root="$(cd -- "$plugin_root/../../../.." && pwd)"
audit_root="$project_root/out/distributak/core-api-lint"
export ANDROID_HOME="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-$HOME/Android/Sdk}}"
if [[ ! -f "$ANDROID_HOME/platforms/android-36/android.jar" ]]; then
    echo 'Android SDK platform 36 を用意し、ANDROID_HOME を指定してください。' >&2
    exit 1
fi

# clean の直後にも生成ソースを解析できるよう、先に生成する。
"$plugin_root/../core/build.sh" generateProto
mkdir -p "$audit_root"
cat > "$audit_root/settings.gradle" <<'GRADLE'
// SPDX-License-Identifier: GPL-3.0-only
pluginManagement { repositories { google(); mavenCentral() } }
rootProject.name = 'distributak-core-api-lint'
GRADLE
cat > "$audit_root/build.gradle" <<'GRADLE'
// SPDX-License-Identifier: GPL-3.0-only
plugins { id 'com.android.library' version '8.13.0' }
repositories { google(); mavenCentral() }
def repositoryRoot = file(providers.gradleProperty('distributak.repositoryRoot').get())
android {
    namespace 'io.github.hidemas_suzuki_aka_ziek.distributak.apiaudit'
    compileSdk 36
    defaultConfig { minSdk 23 }
    compileOptions {
        sourceCompatibility JavaVersion.VERSION_17
        targetCompatibility JavaVersion.VERSION_17
        coreLibraryDesugaringEnabled true
    }
    sourceSets.main.java.srcDirs = [
        new File(repositoryRoot, 'software/eud/distributak/core/src/main/java'),
        new File(repositoryRoot, 'out/distributak/build/generated/source/proto/main/java')
    ]
    lint {
        checkOnly 'NewApi'
        abortOnError true
        error 'NewApi'
        xmlReport true
        textReport true
    }
}
dependencies {
    implementation 'org.bouncycastle:bcprov-jdk18on:1.83'
    implementation 'com.google.protobuf:protobuf-javalite:3.25.5'
    coreLibraryDesugaring 'com.android.tools:desugar_jdk_libs:2.1.5'
}
GRADLE
"$plugin_root/build.sh" -p "$audit_root" "-Pdistributak.repositoryRoot=$project_root" lintDebug
# 終了コードに加えて、レポートの NewApi の件数も確認する。
python3 - "$audit_root/build/reports/lint-results-debug.xml" <<'PY'
import sys
import xml.etree.ElementTree as ET
issues = ET.parse(sys.argv[1]).getroot().findall('issue')
new_api = [issue for issue in issues if issue.get('id') == 'NewApi']
print(f'Core Android API lint: minSdk=23, NewApi={len(new_api)}')
sys.exit(1 if new_api else 0)
PY
