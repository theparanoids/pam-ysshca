/*
 * Copyright 2022 Yahoo Inc.
 * Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.
 */

#include "_cgo_export.h"

#ifdef __APPLE__
  #include <sys/ptrace.h>
#elif __linux__
  #include <sys/prctl.h>
#endif
#include <pwd.h>

// pam_sm_authenticate is the entry of this pam module (for C part).
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	return Authenticate(pamh);
}

// pam_sm_setcred alters user credentials, we have no credential to change so just PAM_SUCCESS.
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	return PAM_SUCCESS;
}

// GetCurrentUserName returns the current username.
// It is exported to Go language part.
const char *GetCurrentUserName(pam_handle_t *pamh) {
	if (pamh == NULL)
		return NULL;

	const char *username = NULL;
	int err = pam_get_item(pamh, PAM_USER, (const void **)&username);
	if (err != PAM_SUCCESS)
		return NULL;
	return username;
}

struct passwd *_getpwnam(pam_handle_t *pamh) {
	const char *username = GetCurrentUserName(pamh);
	if (username == NULL)
		return NULL;
	return getpwnam(username);
}

// GetCurrentUserHome returns the current user's home directory.
// It is exported to Go language part.
const char *GetCurrentUserHome(pam_handle_t *pamh) {
	struct passwd *pw = _getpwnam(pamh);
	if (pw == NULL)
		return NULL;
	return pw->pw_dir;
}

// GetCurrentUserUID returns the current user's uid.
// It is exported to Go language part.
uid_t GetCurrentUserUID(pam_handle_t *pamh) {
	struct passwd *pw = _getpwnam(pamh);
	if (pw == NULL)
		return -1;
	return pw->pw_uid;
}

// DisablePtrace disable the ptrace.
// It is exported to Go language part.
int DisablePtrace() {
#ifdef __APPLE__
  return ptrace(PT_DENY_ATTACH, 0, 0, 0);
#elif __linux__
  return prctl(PR_SET_DUMPABLE, 0);
#endif
  return 1;
}
