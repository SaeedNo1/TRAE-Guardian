#pragma once

#include <QString>
#include <QDateTime>
#include <QObject>
#include <QRegularExpression>

namespace ChatStyle {

inline QString bubbleCss()
{
    return R"(
        <style>
        body {
            font-family: "Segoe UI", "Microsoft YaHei", sans-serif;
            font-size: 14px;
            line-height: 1.5;
            background: #1c1c1e;
            color: #f2f2f7;
            margin: 0;
            padding: 12px;
        }
        .msg-row {
            display: flex;
            margin: 10px 0;
            width: 100%;
        }
        .msg-row.user {
            justify-content: flex-end;
        }
        .msg-row.ai {
            justify-content: flex-start;
        }
        .msg-avatar {
            width: 34px;
            height: 34px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 13px;
            color: white;
            font-weight: bold;
            flex-shrink: 0;
            margin: 0 8px;
        }
        .msg-avatar.user { background: #0a84ff; }
        .msg-avatar.ai { background: #30d158; }
        .msg-content {
            max-width: 70%;
            display: flex;
            flex-direction: column;
        }
        .msg-name {
            font-size: 11px;
            color: #8e8e93;
            margin-bottom: 2px;
            padding: 0 4px;
        }
        .msg-bubble {
            padding: 10px 14px;
            border-radius: 18px;
            word-wrap: break-word;
            box-shadow: 0 1px 2px rgba(0,0,0,0.25);
        }
        .msg-bubble.user {
            background: #0a84ff;
            color: white;
            border-bottom-right-radius: 4px;
        }
        .msg-bubble.ai {
            background: #2c2c2e;
            color: #f2f2f7;
            border: 1px solid #3a3a3c;
            border-bottom-left-radius: 4px;
        }
        .msg-bubble pre {
            background: rgba(0,0,0,0.35);
            padding: 8px;
            border-radius: 8px;
            overflow-x: auto;
            font-family: Consolas, monospace;
            font-size: 12px;
            color: #f2f2f7;
        }
        .msg-bubble code {
            background: rgba(0,0,0,0.35);
            padding: 2px 4px;
            border-radius: 4px;
            font-family: Consolas, monospace;
            font-size: 12px;
            color: #f2f2f7;
        }
        .msg-time {
            font-size: 10px;
            color: #8e8e93;
            margin-top: 2px;
            padding: 0 4px;
        }
        .msg-row.user .msg-time { text-align: right; }
        .system-msg {
            text-align: center;
            color: #8e8e93;
            font-size: 12px;
            margin: 8px 0;
        }
        </style>
    )";
}

inline QString formatMessage(const QString &role, const QString &text)
{
    QString safe = text.toHtmlEscaped();
    safe.replace("\n", "<br>");

    /* Very simple markdown: code blocks */
    safe.replace(QRegularExpression("```(.*?)```", QRegularExpression::DotMatchesEverythingOption),
                 "<pre>\\1</pre>");
    safe.replace(QRegularExpression("`([^`]+)`"), "<code>\\1</code>");

    QString cls = (role == "User") ? "user" : "ai";
    QString name = (role == "User") ? QObject::tr("You") : QObject::tr("AI");
    QString avatar = (role == "User") ? "U" : "AI";
    QString time = QDateTime::currentDateTime().toString("hh:mm");

    if (role == "User") {
        return QString(
            "<div class=\"msg-row user\">"
            "<div class=\"msg-content\">"
            "<div class=\"msg-name\">%1</div>"
            "<div class=\"msg-bubble user\">%2</div>"
            "<div class=\"msg-time\">%3</div>"
            "</div>"
            "<div class=\"msg-avatar user\">%4</div>"
            "</div>"
        ).arg(name, safe, time, avatar);
    }

    return QString(
        "<div class=\"msg-row ai\">"
        "<div class=\"msg-avatar ai\">%4</div>"
        "<div class=\"msg-content\">"
        "<div class=\"msg-name\">%1</div>"
        "<div class=\"msg-bubble ai\">%2</div>"
        "<div class=\"msg-time\">%3</div>"
        "</div>"
        "</div>"
    ).arg(name, safe, time, avatar);
}

inline QString formatSystem(const QString &text)
{
    return QString("<div class=\"system-msg\">%1</div>").arg(text.toHtmlEscaped());
}

inline QString pageHeader()
{
    return "<!DOCTYPE html><html><head><meta charset=\"UTF-8\">" + bubbleCss() + "</head><body>";
}

} // namespace ChatStyle
