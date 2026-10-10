#include "AuthorizationBridge.h"
#include <Security/Authorization.h>
#include <Security/AuthorizationTags.h>
#include <sys/acl.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

int ParatiaRootProtected(const char *path) {
    struct stat info;
    if (!path || lstat(path, &info) || info.st_uid != 0 || (info.st_mode & 0022) ||
        !(S_ISREG(info.st_mode) || S_ISDIR(info.st_mode))) return 0;
    acl_t acl = acl_get_file(path, ACL_TYPE_EXTENDED);
    if (!acl) return errno == ENOENT || errno == ENOTSUP;
    acl_entry_t entry;
    int position = ACL_FIRST_ENTRY;
    while (acl_get_entry(acl, position, &entry) == 0) {
        position = ACL_NEXT_ENTRY;
        acl_tag_t tag;
        acl_permset_t permissions;
        if (acl_get_tag_type(entry, &tag) || acl_get_permset(entry, &permissions)) { acl_free(acl); return 0; }
        if (tag == ACL_EXTENDED_ALLOW &&
            (acl_get_perm_np(permissions, ACL_WRITE_DATA) || acl_get_perm_np(permissions, ACL_APPEND_DATA) ||
             acl_get_perm_np(permissions, ACL_DELETE) || acl_get_perm_np(permissions, ACL_DELETE_CHILD) ||
             acl_get_perm_np(permissions, ACL_WRITE_ATTRIBUTES) || acl_get_perm_np(permissions, ACL_WRITE_EXTATTRIBUTES) ||
             acl_get_perm_np(permissions, ACL_WRITE_SECURITY) || acl_get_perm_np(permissions, ACL_CHANGE_OWNER))) {
            acl_free(acl); return 0;
        }
    }
    acl_free(acl);
    return 1;
}

int ParatiaRootProtectedAncestors(const char *path) {
    char current[PATH_MAX];
    if (!path || path[0] != '/' || strlen(path) >= sizeof(current)) return 0;
    if (strstr(path, "//") || strstr(path, "/./") || strstr(path, "/../")) return 0;
    size_t size = strlen(path);
    if (size > 1 && path[size - 1] == '/') return 0;
    const char *last = strrchr(path, '/');
    if (!last || !strcmp(last, "/.") || !strcmp(last, "/..")) return 0;
    strcpy(current, path);
    while (1) {
        if (ParatiaRootProtected(current) != 1) return 0;
        if (!strcmp(current, "/")) return 1;
        char *slash = strrchr(current, '/');
        if (!slash) return 0;
        if (slash == current) current[1] = '\0';
        else *slash = '\0';
    }
}

int32_t ParatiaAuthorizedInstall(const char *executable, char *const arguments[], FILE **output) {
    AuthorizationRef authorization = NULL;
    OSStatus result = AuthorizationCreate(NULL, kAuthorizationEmptyEnvironment, kAuthorizationFlagDefaults, &authorization);
    if (result != errAuthorizationSuccess) return result;
    AuthorizationItem item = { kAuthorizationRightExecute, strlen(executable), (void *)executable, 0 };
    AuthorizationRights rights = { 1, &item };
    result = AuthorizationCopyRights(authorization, &rights, kAuthorizationEmptyEnvironment,
                                    kAuthorizationFlagInteractionAllowed | kAuthorizationFlagExtendRights | kAuthorizationFlagPreAuthorize, NULL);
    if (result == errAuthorizationSuccess) {
        // This local ad-hoc app cannot register a notarized SMAppService helper.
        // The deprecated API is confined to the reviewed, fixed installer argv.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
        result = AuthorizationExecuteWithPrivileges(authorization, executable, kAuthorizationFlagDefaults, arguments, output);
#pragma clang diagnostic pop
    }
    AuthorizationFree(authorization, kAuthorizationFlagDestroyRights);
    return result;
}
