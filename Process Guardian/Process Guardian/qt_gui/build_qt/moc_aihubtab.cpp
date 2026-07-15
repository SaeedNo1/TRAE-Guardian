/****************************************************************************
** Meta object code from reading C++ file 'aihubtab.h'
**
** Created by: The Qt Meta Object Compiler version 68 (Qt 6.8.3)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "../aihubtab.h"
#include <QtCore/qmetatype.h>

#include <QtCore/qtmochelpers.h>

#include <memory>


#include <QtCore/qxptype_traits.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'aihubtab.h' doesn't include <QObject>."
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
struct qt_meta_tag_ZN8AiHubTabE_t {};
} // unnamed namespace


#ifdef QT_MOC_HAS_STRINGDATA
static constexpr auto qt_meta_stringdata_ZN8AiHubTabE = QtMocHelpers::stringData(
    "AiHubTab",
    "refresh",
    "",
    "createTaskWithProcess",
    "processName",
    "onSaveSettings",
    "onTaskSelectionChanged",
    "onAddTask",
    "onEditTask",
    "onDeleteTask",
    "onTalkToAi",
    "onGlobalChat",
    "onTestConnection",
    "onSaveSoul",
    "onSaveKnowledge",
    "onSaveSystemPrompt",
    "onShowAiAnalysisLog"
);
#else  // !QT_MOC_HAS_STRINGDATA
#error "qtmochelpers.h not found or too old."
#endif // !QT_MOC_HAS_STRINGDATA

Q_CONSTINIT static const uint qt_meta_data_ZN8AiHubTabE[] = {

 // content:
      12,       // revision
       0,       // classname
       0,    0, // classinfo
      14,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       0,       // signalCount

 // slots: name, argc, parameters, tag, flags, initial metatype offsets
       1,    0,   98,    2, 0x0a,    1 /* Public */,
       3,    1,   99,    2, 0x0a,    2 /* Public */,
       5,    0,  102,    2, 0x08,    4 /* Private */,
       6,    0,  103,    2, 0x08,    5 /* Private */,
       7,    0,  104,    2, 0x08,    6 /* Private */,
       8,    0,  105,    2, 0x08,    7 /* Private */,
       9,    0,  106,    2, 0x08,    8 /* Private */,
      10,    0,  107,    2, 0x08,    9 /* Private */,
      11,    0,  108,    2, 0x08,   10 /* Private */,
      12,    0,  109,    2, 0x08,   11 /* Private */,
      13,    0,  110,    2, 0x08,   12 /* Private */,
      14,    0,  111,    2, 0x08,   13 /* Private */,
      15,    0,  112,    2, 0x08,   14 /* Private */,
      16,    0,  113,    2, 0x08,   15 /* Private */,

 // slots: parameters
    QMetaType::Void,
    QMetaType::Void, QMetaType::QString,    4,
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
    QMetaType::Void,
    QMetaType::Void,

       0        // eod
};

Q_CONSTINIT const QMetaObject AiHubTab::staticMetaObject = { {
    QMetaObject::SuperData::link<QWidget::staticMetaObject>(),
    qt_meta_stringdata_ZN8AiHubTabE.offsetsAndSizes,
    qt_meta_data_ZN8AiHubTabE,
    qt_static_metacall,
    nullptr,
    qt_incomplete_metaTypeArray<qt_meta_tag_ZN8AiHubTabE_t,
        // Q_OBJECT / Q_GADGET
        QtPrivate::TypeAndForceComplete<AiHubTab, std::true_type>,
        // method 'refresh'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'createTaskWithProcess'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        QtPrivate::TypeAndForceComplete<const QString &, std::false_type>,
        // method 'onSaveSettings'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'onTaskSelectionChanged'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'onAddTask'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'onEditTask'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'onDeleteTask'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'onTalkToAi'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'onGlobalChat'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'onTestConnection'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'onSaveSoul'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'onSaveKnowledge'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'onSaveSystemPrompt'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'onShowAiAnalysisLog'
        QtPrivate::TypeAndForceComplete<void, std::false_type>
    >,
    nullptr
} };

void AiHubTab::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    auto *_t = static_cast<AiHubTab *>(_o);
    if (_c == QMetaObject::InvokeMetaMethod) {
        switch (_id) {
        case 0: _t->refresh(); break;
        case 1: _t->createTaskWithProcess((*reinterpret_cast< std::add_pointer_t<QString>>(_a[1]))); break;
        case 2: _t->onSaveSettings(); break;
        case 3: _t->onTaskSelectionChanged(); break;
        case 4: _t->onAddTask(); break;
        case 5: _t->onEditTask(); break;
        case 6: _t->onDeleteTask(); break;
        case 7: _t->onTalkToAi(); break;
        case 8: _t->onGlobalChat(); break;
        case 9: _t->onTestConnection(); break;
        case 10: _t->onSaveSoul(); break;
        case 11: _t->onSaveKnowledge(); break;
        case 12: _t->onSaveSystemPrompt(); break;
        case 13: _t->onShowAiAnalysisLog(); break;
        default: ;
        }
    }
}

const QMetaObject *AiHubTab::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *AiHubTab::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_ZN8AiHubTabE.stringdata0))
        return static_cast<void*>(this);
    return QWidget::qt_metacast(_clname);
}

int AiHubTab::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QWidget::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 14)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 14;
    }
    if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 14)
            *reinterpret_cast<QMetaType *>(_a[0]) = QMetaType();
        _id -= 14;
    }
    return _id;
}
QT_WARNING_POP
