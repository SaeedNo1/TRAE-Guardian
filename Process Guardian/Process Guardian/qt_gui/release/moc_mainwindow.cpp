/****************************************************************************
** Meta object code from reading C++ file 'mainwindow.h'
**
** Created by: The Qt Meta Object Compiler version 68 (Qt 6.8.3)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "../mainwindow.h"
#include <QtGui/qtextcursor.h>
#include <QtCore/qmetatype.h>

#include <QtCore/qtmochelpers.h>

#include <memory>


#include <QtCore/qxptype_traits.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'mainwindow.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 68
#error "This file was generated using the moc from 6.8.3. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

#ifndef Q_CONSTINIT
#define Q_CONSTINIT
#endif

QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
QT_WARNING_DISABLE_GCC("-Wuseless-cast")
namespace {
struct qt_meta_tag_ZN10MainWindowE_t {};
} // unnamed namespace


#ifdef QT_MOC_HAS_STRINGDATA
static constexpr auto qt_meta_stringdata_ZN10MainWindowE = QtMocHelpers::stringData(
    "MainWindow",
    "openGlobalChat",
    "",
    "showPopupConfirmation",
    "title",
    "message",
    "proc",
    "path",
    "onRefresh",
    "onCheckDaemonStatus",
    "onDailyReport",
    "onStartDaemon",
    "onStartAdmin",
    "onStartSystem",
    "onStopDaemon",
    "onOpenSettings",
    "onOpenAiHub",
    "onCheckNotifications",
    "onAutoRefreshToggled",
    "checked",
    "onCheckPopupFlag",
    "onLiveMonitorRequested",
    "processName",
    "onCreateAiTaskRequested",
    "onDaemonStartComplete",
    "success",
    "modeLabel",
    "onAdminStartComplete",
    "onSystemStartComplete"
);
#else  // !QT_MOC_HAS_STRINGDATA
#error "qtmochelpers.h not found or too old."
#endif // !QT_MOC_HAS_STRINGDATA

Q_CONSTINIT static const uint qt_meta_data_ZN10MainWindowE[] = {

 // content:
      12,       // revision
       0,       // classname
       0,    0, // classinfo
      19,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       0,       // signalCount

 // slots: name, argc, parameters, tag, flags, initial metatype offsets
       1,    0,  128,    2, 0x0a,    1 /* Public */,
       3,    4,  129,    2, 0x0a,    2 /* Public */,
       8,    0,  138,    2, 0x08,    7 /* Private */,
       9,    0,  139,    2, 0x08,    8 /* Private */,
      10,    0,  140,    2, 0x08,    9 /* Private */,
      11,    0,  141,    2, 0x08,   10 /* Private */,
      12,    0,  142,    2, 0x08,   11 /* Private */,
      13,    0,  143,    2, 0x08,   12 /* Private */,
      14,    0,  144,    2, 0x08,   13 /* Private */,
      15,    0,  145,    2, 0x08,   14 /* Private */,
      16,    0,  146,    2, 0x08,   15 /* Private */,
      17,    0,  147,    2, 0x08,   16 /* Private */,
      18,    1,  148,    2, 0x08,   17 /* Private */,
      20,    0,  151,    2, 0x08,   19 /* Private */,
      21,    1,  152,    2, 0x08,   20 /* Private */,
      23,    1,  155,    2, 0x08,   22 /* Private */,
      24,    2,  158,    2, 0x08,   24 /* Private */,
      27,    1,  163,    2, 0x08,   27 /* Private */,
      28,    1,  166,    2, 0x08,   29 /* Private */,

 // slots: parameters
    QMetaType::Void,
    QMetaType::Bool, QMetaType::QString, QMetaType::QString, QMetaType::QString, QMetaType::QString,    4,    5,    6,    7,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void, QMetaType::Bool,   19,
    QMetaType::Void,
    QMetaType::Void, QMetaType::QString,   22,
    QMetaType::Void, QMetaType::QString,   22,
    QMetaType::Void, QMetaType::Bool, QMetaType::QString,   25,   26,
    QMetaType::Void, QMetaType::Bool,   25,
    QMetaType::Void, QMetaType::Bool,   25,

       0        // eod
};

Q_CONSTINIT const QMetaObject MainWindow::staticMetaObject = { {
    QMetaObject::SuperData::link<QMainWindow::staticMetaObject>(),
    qt_meta_stringdata_ZN10MainWindowE.offsetsAndSizes,
    qt_meta_data_ZN10MainWindowE,
    qt_static_metacall,
    nullptr,
    qt_incomplete_metaTypeArray<qt_meta_tag_ZN10MainWindowE_t,
        // Q_OBJECT / Q_GADGET
        QtPrivate::TypeAndForceComplete<MainWindow, std::true_type>,
        // method 'openGlobalChat'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'showPopupConfirmation'
        QtPrivate::TypeAndForceComplete<bool, std::false_type>,
        QtPrivate::TypeAndForceComplete<const QString &, std::false_type>,
        QtPrivate::TypeAndForceComplete<const QString &, std::false_type>,
        QtPrivate::TypeAndForceComplete<const QString &, std::false_type>,
        QtPrivate::TypeAndForceComplete<const QString &, std::false_type>,
        // method 'onRefresh'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'onCheckDaemonStatus'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'onDailyReport'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'onStartDaemon'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'onStartAdmin'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'onStartSystem'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'onStopDaemon'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'onOpenSettings'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'onOpenAiHub'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'onCheckNotifications'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'onAutoRefreshToggled'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        QtPrivate::TypeAndForceComplete<bool, std::false_type>,
        // method 'onCheckPopupFlag'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'onLiveMonitorRequested'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        QtPrivate::TypeAndForceComplete<const QString &, std::false_type>,
        // method 'onCreateAiTaskRequested'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        QtPrivate::TypeAndForceComplete<const QString &, std::false_type>,
        // method 'onDaemonStartComplete'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        QtPrivate::TypeAndForceComplete<bool, std::false_type>,
        QtPrivate::TypeAndForceComplete<const QString &, std::false_type>,
        // method 'onAdminStartComplete'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        QtPrivate::TypeAndForceComplete<bool, std::false_type>,
        // method 'onSystemStartComplete'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        QtPrivate::TypeAndForceComplete<bool, std::false_type>
    >,
    nullptr
} };

void MainWindow::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    auto *_t = static_cast<MainWindow *>(_o);
    if (_c == QMetaObject::InvokeMetaMethod) {
        switch (_id) {
        case 0: _t->openGlobalChat(); break;
        case 1: { bool _r = _t->showPopupConfirmation((*reinterpret_cast< std::add_pointer_t<QString>>(_a[1])),(*reinterpret_cast< std::add_pointer_t<QString>>(_a[2])),(*reinterpret_cast< std::add_pointer_t<QString>>(_a[3])),(*reinterpret_cast< std::add_pointer_t<QString>>(_a[4])));
            if (_a[0]) *reinterpret_cast< bool*>(_a[0]) = std::move(_r); }  break;
        case 2: _t->onRefresh(); break;
        case 3: _t->onCheckDaemonStatus(); break;
        case 4: _t->onDailyReport(); break;
        case 5: _t->onStartDaemon(); break;
        case 6: _t->onStartAdmin(); break;
        case 7: _t->onStartSystem(); break;
        case 8: _t->onStopDaemon(); break;
        case 9: _t->onOpenSettings(); break;
        case 10: _t->onOpenAiHub(); break;
        case 11: _t->onCheckNotifications(); break;
        case 12: _t->onAutoRefreshToggled((*reinterpret_cast< std::add_pointer_t<bool>>(_a[1]))); break;
        case 13: _t->onCheckPopupFlag(); break;
        case 14: _t->onLiveMonitorRequested((*reinterpret_cast< std::add_pointer_t<QString>>(_a[1]))); break;
        case 15: _t->onCreateAiTaskRequested((*reinterpret_cast< std::add_pointer_t<QString>>(_a[1]))); break;
        case 16: _t->onDaemonStartComplete((*reinterpret_cast< std::add_pointer_t<bool>>(_a[1])),(*reinterpret_cast< std::add_pointer_t<QString>>(_a[2]))); break;
        case 17: _t->onAdminStartComplete((*reinterpret_cast< std::add_pointer_t<bool>>(_a[1]))); break;
        case 18: _t->onSystemStartComplete((*reinterpret_cast< std::add_pointer_t<bool>>(_a[1]))); break;
        default: ;
        }
    }
}

const QMetaObject *MainWindow::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *MainWindow::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_ZN10MainWindowE.stringdata0))
        return static_cast<void*>(this);
    return QMainWindow::qt_metacast(_clname);
}

int MainWindow::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QMainWindow::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 19)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 19;
    }
    if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 19)
            *reinterpret_cast<QMetaType *>(_a[0]) = QMetaType();
        _id -= 19;
    }
    return _id;
}
QT_WARNING_POP
