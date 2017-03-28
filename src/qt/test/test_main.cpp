// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include "config/bitcoin-config.h"
#endif

#include "chainparams.h"
#include "rpcnestedtests.h"
#include "util.h"
#include "uritests.h"
#include "compattests.h"

#ifdef ENABLE_WALLET
#include "paymentservertests.h"
#include "wallettests.h"
#endif

#include <QApplication>
#include <QObject>
#include <QPluginLoader>
#include <QTest>
#include <QtDebug>

#include <openssl/ssl.h>

#if defined(QT_STATICPLUGIN)
#include <QtPlugin>
#if QT_VERSION < 0x050000
Q_IMPORT_PLUGIN(qcncodecs)
Q_IMPORT_PLUGIN(qjpcodecs)
Q_IMPORT_PLUGIN(qtwcodecs)
Q_IMPORT_PLUGIN(qkrcodecs)
#else
#if defined(QT_QPA_PLATFORM_XCB)
Q_IMPORT_PLUGIN(QXcbIntegrationPlugin);
#elif defined(QT_QPA_PLATFORM_WINDOWS)
Q_IMPORT_PLUGIN(QWindowsIntegrationPlugin);
#elif defined(QT_QPA_PLATFORM_COCOA)
Q_IMPORT_PLUGIN(QCocoaIntegrationPlugin);
#endif
#endif
#endif

static bool UsesXcb() {
    for (QObject* plugin: QPluginLoader::staticInstances()) {
        if (plugin->objectName() == "platforms/qxcb") {
            return true;
        }
    }
    return QPluginLoader("platforms/qxcb").load();
}

extern void noui_connect();

// This is all you need to run all the tests
int main(int argc, char *argv[])
{
    SetupEnvironment();
    SetupNetworking();
    SelectParams(CBaseChainParams::MAIN);
    noui_connect();

    bool fInvalid = false;

    // Don't remove this, it's needed to access
    // QApplication:: and QCoreApplication:: in the tests
    std::unique_ptr<QCoreApplication> app;
    if (!UsesXcb() || getenv("DISPLAY")) {
        app.reset(new QApplication(argc, argv));
    } else {
        // If the test uses XCB but the DISPLAY variable is unset, this will
        // cause a fatal error during QApplication construction, so fall back to
        // using QCoreApplication instead.
        app.reset(new QCoreApplication(argc, argv));
        qWarning() << "DISPLAY variable is unset. Some tests will be skipped.";
    }
    app->setApplicationName("Bitcoin-Qt-test");

    SSL_library_init();

    URITests test1;
    if (QTest::qExec(&test1) != 0) {
        fInvalid = true;
    }
#ifdef ENABLE_WALLET
    PaymentServerTests test2;
    if (QTest::qExec(&test2) != 0) {
        fInvalid = true;
    }
#endif
    RPCNestedTests test3;
    if (QTest::qExec(&test3) != 0) {
        fInvalid = true;
    }
    CompatTests test4;
    if (QTest::qExec(&test4) != 0) {
        fInvalid = true;
    }
#ifdef ENABLE_WALLET
    WalletTests test5;
    if (QTest::qExec(&test5) != 0) {
        fInvalid = true;
    }
#endif

    return fInvalid;
}
