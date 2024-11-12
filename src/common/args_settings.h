#ifndef BITCOIN_COMMON_ARGS_SETTINGS_H
#define BITCOIN_COMMON_ARGS_SETTINGS_H

#include <common/setting.h>

#include <string>
#include <vector>

using HelpSetting = common::Setting<
    "-help", common::Unset, common::SettingOptions{.legacy = true},
    "Print this help message and exit (also -h or -?)">;

#endif // BITCOIN_COMMON_ARGS_SETTINGS_H
