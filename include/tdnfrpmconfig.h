/*
 * Copyright (C) 2026 VMware, Inc. All Rights Reserved.
 *
 * Licensed under the GNU Lesser General Public License v2.1 (the "License");
 * you may not use this file except in compliance with the License. The terms
 * of the License are located in the COPYING file of this distribution.
 */

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

typedef struct tdnf_rpm_config tdnf_rpm_config;

const char *
tdnf_rpm_config_last_error(
    void
    );

tdnf_rpm_config *
tdnf_rpm_config_create(
    const char *pszInstallRoot
    );

void
tdnf_rpm_config_destroy(
    tdnf_rpm_config *pConfig
    );

int
tdnf_rpm_config_apply_define(
    tdnf_rpm_config *pConfig,
    const char *pszDefinition
    );

char *
tdnf_rpm_config_expand(
    const tdnf_rpm_config *pConfig,
    const char *pszName
    );

char *
tdnf_rpm_config_resolve_path(
    const tdnf_rpm_config *pConfig,
    const char *pszName
    );

void
tdnf_rpm_config_string_free(
    char *pszValue
    );

#ifdef __cplusplus
}
#endif
