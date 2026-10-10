"""Exercise the native guard with mocked filesystem metadata, without root."""
from __future__ import annotations

import ctypes
import re
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
BOOTSTRAP = "/Library/Application Support/ParatiaBootstrap"
BUNDLE = BOOTSTRAP + "/Paratia.app"
SCRIPT = BUNDLE + "/Contents/Resources/python/registro_installa.py"

PREPARATION_COMMAND = '''sudo /bin/sh -c 'set -eu
[ ! -L "/Library/Application Support/ParatiaBootstrap" ]
[ -d "/Applications/Paratia.app" ]
[ ! -L "/Applications/Paratia.app" ]
/usr/bin/install -d -m 755 -o root -g wheel "/Library/Application Support/ParatiaBootstrap"
/bin/chmod -N "/Library/Application Support/ParatiaBootstrap"
paratia_bootstrap_stage=$(/usr/bin/mktemp -d "/Library/Application Support/ParatiaBootstrap/.prepara.XXXXXX")
/usr/bin/ditto --noacl "/Applications/Paratia.app" "$paratia_bootstrap_stage/Paratia.app"
/usr/bin/find "$paratia_bootstrap_stage/Paratia.app" ! -type d ! -type f -print > "$paratia_bootstrap_stage/percorsi-non-ordinari"
[ ! -s "$paratia_bootstrap_stage/percorsi-non-ordinari" ]
/usr/sbin/chown -R root:wheel "$paratia_bootstrap_stage/Paratia.app"
/bin/chmod -R go-w "$paratia_bootstrap_stage/Paratia.app"
/usr/bin/codesign --verify --deep --strict "$paratia_bootstrap_stage/Paratia.app"
[ ! -L "/Library/Application Support/ParatiaBootstrap/Paratia.app" ]
if [ -e "/Library/Application Support/ParatiaBootstrap/Paratia.app" ]; then
    /bin/mv "/Library/Application Support/ParatiaBootstrap/Paratia.app" "$paratia_bootstrap_stage/precedente.app"
fi
/bin/mv "$paratia_bootstrap_stage/Paratia.app" "/Library/Application Support/ParatiaBootstrap/Paratia.app"
/usr/bin/codesign --verify --deep --strict "/Library/Application Support/ParatiaBootstrap/Paratia.app"\''''


def swift_preparation_command():
    swift = (ROOT / "macos" / "NativeInstall.swift").read_text()
    match = re.search(r'static let preparationCommand = """\n(.*?)\n\s*"""', swift, re.S)
    assert match, "The manual command must be a selectable, fixed Swift string."
    return textwrap.dedent(match.group(1))


@pytest.fixture(scope="module")
def native_guard(tmp_path_factory):
    if sys.platform != "darwin":
        pytest.skip("macOS C ACL guard")
    directory = tmp_path_factory.mktemp("native-bootstrap-guard")
    source = directory / "fixture.c"
    # Include the real implementation. Only filesystem/ACL syscalls are faked;
    # the security decisions and ancestor traversal execute their actual C code.
    source.write_text(r'''
#include <Security/Authorization.h>
#include <Security/AuthorizationTags.h>
#include <sys/acl.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <stdio.h>
static char bad_path[PATH_MAX];
static int bad_kind;
void TestConfigure(const char *path, int kind) {
    snprintf(bad_path, sizeof(bad_path), "%s", path ? path : "");
    bad_kind = kind;
}
static int fake_lstat(const char *path, struct stat *result) {
    memset(result, 0, sizeof(*result));
    result->st_uid = 0;
    result->st_mode = S_IFDIR | 0755;
    if (strcmp(path, bad_path) == 0) {
        if (bad_kind == 1) result->st_uid = 501;
        if (bad_kind == 2) result->st_mode |= 0022;
        if (bad_kind == 3) result->st_mode = S_IFLNK | 0777;
        if (bad_kind == 8) result->st_mode = S_IFIFO | 0600;
        if (bad_kind == 9) { errno = ENOENT; return -1; }
    }
    return 0;
}
static acl_t fake_acl_get_file(const char *path, acl_type_t type) {
    if (strcmp(path, bad_path) == 0) {
        if (bad_kind == 5) { errno = EPERM; return NULL; }
        if (bad_kind == 4 || bad_kind == 6 || bad_kind == 7 || bad_kind == 11) return (acl_t)1;
    }
    errno = ENOENT;
    return NULL;
}
static int fake_acl_get_entry(acl_t acl, int position, acl_entry_t *entry) {
    if (position != ACL_FIRST_ENTRY) return -1;
    *entry = (acl_entry_t)2;
    return 0;
}
static int fake_acl_get_tag_type(acl_entry_t entry, acl_tag_t *tag) {
    *tag = bad_kind == 11 ? ACL_EXTENDED_DENY : ACL_EXTENDED_ALLOW;
    return 0;
}
static int fake_acl_get_permset(acl_entry_t entry, acl_permset_t *permissions) {
    *permissions = (acl_permset_t)3;
    return 0;
}
static int fake_acl_get_perm_np(acl_permset_t permissions, acl_perm_t permission) {
    return (bad_kind == 4 || bad_kind == 11) ? permission == ACL_WRITE_DATA :
           bad_kind == 7 ? permission == ACL_DELETE_CHILD : 0;
}
static int fake_acl_free(void *value) { return 0; }
#define lstat fake_lstat
#define acl_get_file fake_acl_get_file
#define acl_get_entry fake_acl_get_entry
#define acl_get_tag_type fake_acl_get_tag_type
#define acl_get_permset fake_acl_get_permset
#define acl_get_perm_np fake_acl_get_perm_np
#define acl_free fake_acl_free
''' + '\n#include "' + str(ROOT / "macos" / "AuthorizationBridge.c") + '"\n', encoding="utf-8")
    library = directory / "guard.dylib"
    subprocess.run(["/usr/bin/xcrun", "clang", "-dynamiclib", str(source), "-framework", "Security",
                    "-o", str(library)], check=True, capture_output=True)
    guard = ctypes.CDLL(str(library))
    guard.TestConfigure.argtypes = [ctypes.c_char_p, ctypes.c_int]
    guard.ParatiaRootProtectedAncestors.argtypes = [ctypes.c_char_p]
    guard.ParatiaRootProtectedAncestors.restype = ctypes.c_int
    return guard


def allowed(guard, path=SCRIPT, bad_path="", kind=0):
    guard.TestConfigure(bad_path.encode(), kind)
    return bool(guard.ParatiaRootProtectedAncestors(path.encode()))


def test_root_protected_bootstrap_can_pass(native_guard):
    assert allowed(native_guard)


@pytest.mark.parametrize("bad_path", [BUNDLE, BUNDLE + "/Contents", BUNDLE + "/Contents/Resources",
                                      BUNDLE + "/Contents/Resources/python", SCRIPT, BOOTSTRAP,
                                      "/Library/Application Support", "/Library", "/"])
@pytest.mark.parametrize("kind", [1, 2, 3, 4, 5, 7, 8, 9])
def test_reject_owner_write_links_acls_special_and_missing_at_any_depth(native_guard, bad_path, kind):
    assert not allowed(native_guard, bad_path=bad_path, kind=kind)


@pytest.mark.parametrize("kind", [6, 11])
def test_read_only_or_deny_acl_is_not_a_write_grant(native_guard, kind):
    assert allowed(native_guard, bad_path=BUNDLE, kind=kind)


@pytest.mark.parametrize("kind", [1, 2, 3, 4])
def test_normal_app_directory_is_not_a_bootstrap_ancestor(native_guard, kind):
    # /Applications can retain its normal root:admin 0775 permissions. It is a
    # copy source, never an ancestor of the privileged bootstrap payload.
    assert allowed(native_guard, bad_path="/Applications", kind=kind)


@pytest.mark.parametrize("path", ["relative/Paratia.app", "/Library//Application Support/ParatiaBootstrap/Paratia.app", BUNDLE + "/",
                                  BUNDLE + "/../other", BUNDLE + "/./Contents", BUNDLE + "/..", BUNDLE + "/."])
def test_alias_paths_fail_closed(native_guard, path):
    assert not allowed(native_guard, path=path)


def test_all_bundle_reads_and_fixed_payload_are_guarded_before_authorization():
    swift = (ROOT / "macos" / "NativeInstall.swift").read_text()
    assert f'static let bootstrapBundlePath = "{BUNDLE}"' in swift
    assert "guard bundle.path == bootstrapBundlePath" in swift
    assert "ParatiaRootProtectedAncestors" in swift
    for asset in ("registro_installa.py", "catena.py", "registro.py", "registro_daemon.py"):
        assert '"Contents/Resources/python/' + asset + '"' in swift
    for asset in ("Contents/Info.plist", "Contents/MacOS/Paratia", "Contents/_CodeSignature/CodeResources"):
        assert '"' + asset + '"' in swift
    assert "enumerator(at: bundle" in swift
    assert "try requireProtected(file)" in swift
    assert "FileAttributeType == .typeRegular" in swift
    assert "argv.count == 9" in swift
    assert 'argv[3] == resource.appendingPathComponent("registro_installa.py").path' in swift
    assert "argv[8] == resource.path" in swift
    execute = swift.split("static func execute(plan:", 1)[1]
    assert execute.index("try validate(plan: plan)") < execute.index("ParatiaAuthorizedInstall")
    assert execute.index("try validateBootstrap(bundle:") < execute.index("ParatiaAuthorizedInstall")
    bootstrap = swift.split("static func validateBootstrap(bundle:", 1)[1].split("static func validate(plan:", 1)[0]
    # Both the normal app and any user-selected bundle are refused before the
    # file enumeration, codesign process, worker plan, or administrator dialog.
    assert bootstrap.index("guard bundle.path == bootstrapBundlePath") < bootstrap.index("try requireProtected(bundle)")
    assert bootstrap.index("try requireProtected(bundle)") < bootstrap.index("verifier.run()")
    assert '["--verify", "--deep", "--strict", bundle.path]' in bootstrap
    assert "--sign" not in bootstrap


def test_remediation_is_the_exact_manual_command_and_does_not_bypass_parent_guard():
    swift = (ROOT / "macos" / "NativeInstall.swift").read_text()
    assert swift_preparation_command() == PREPARATION_COMMAND
    assert "Chiudi Paratia ed esegui tu questo unico comando" in swift
    assert "Se il comando termina senza errori, apri \\(bootstrapBundlePath) dal Finder" in swift
    assert "Il comando non modifica /Applications" in swift
    assert "un suo antenato non è protetto da root" in swift
    assert "un ACL concede scrittura" in swift
    bridge = (ROOT / "macos" / "AuthorizationBridge.c").read_text()
    traversal = bridge.split("int ParatiaRootProtectedAncestors", 1)[1].split("int32_t ParatiaAuthorizedInstall", 1)[0]
    assert "ParatiaRootProtected(current) != 1" in traversal
    assert 'strcmp(current, "/")' in traversal
    assert "/Applications" not in traversal


def test_manual_command_shell_syntax_without_executing_sudo_or_payload():
    # -n parses only. No sudo, directory creation, application launch, signing,
    # administrator authorization, or system filesystem mutation occurs.
    subprocess.run(["/bin/sh", "-n", "-c", swift_preparation_command()],
                   check=True, capture_output=True)


def test_preparation_has_a_fixed_separate_staged_payload_and_no_applications_changes():
    command = swift_preparation_command()
    assert command.startswith("sudo /bin/sh -c 'set -eu\n")
    assert command.count("sudo ") == 1
    assert 'install -d -m 755 -o root -g wheel "' + BOOTSTRAP + '"' in command
    assert 'mktemp -d "' + BOOTSTRAP + '/.prepara.XXXXXX"' in command
    assert '--noacl "/Applications/Paratia.app" "$paratia_bootstrap_stage/Paratia.app"' in command
    # Reject copied links/devices before recursive root metadata mutations;
    # verify the staged seal before replacing an existing trusted copy.
    assert command.index("! -type d ! -type f") < command.index("/usr/sbin/chown")
    assert command.index('[ ! -s "$paratia_bootstrap_stage/percorsi-non-ordinari" ]') < command.index("/usr/sbin/chown")
    assert command.index('codesign --verify --deep --strict "$paratia_bootstrap_stage/Paratia.app"') < command.index("/bin/mv")
    assert '"$paratia_bootstrap_stage/precedente.app"' in command
    assert "/Library/Application Support/Paratia/" not in command
    for line in command.splitlines():
        if "/Applications" in line:
            assert line.startswith("[ ") or line.startswith("/usr/bin/ditto --noacl ")
    assert "--sign" not in command
    assert "/usr/bin/open" not in command
