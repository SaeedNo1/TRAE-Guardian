/* gui_ai.h - AI dialogs for process_guardian.exe
 * Sidebar has been removed. AI access is via a single toolbar button
 * ("Ask AI", ID 2008) which launches task_admin.exe (browser-based UI)
 * and right-click "Create AI Monitor Task..." entries on the existing
 * process/service/registry/partition lists.
 *
 * Public functions:
 *   int  GuiAi_HandleCommand(HWND hWnd, int id, WPARAM wParam, LPARAM lParam);
 *          - returns 1 if the command was handled
 *   void GuiAi_OpenAskAiDialog(HWND hParent);     // legacy chat dialog
 *   void GuiAi_LaunchTaskAdmin(HWND hParent);      // ID 2008 target
 *   void GuiAi_OpenNewTask(HWND hParent, const char *type, const char *name,
 *                          int pid, int tree);
 *   void GuiAi_OpenEditTask(HWND hParent, const char *taskId);
 *   void GuiAi_NotifyLastTouched(int type, const char *name);
 */
#ifndef GUI_AI_H
#define GUI_AI_H

#include <windows.h>

/* control IDs (must match gui_ai.rc) */
#define IDC_AI_LISTVIEW    9101
#define IDC_AI_NEW_BTN     9102
#define IDC_AI_DEL_BTN     9103
#define IDC_AI_EDIT_BTN    9104
#define IDC_DLG_NAME       9200
#define IDC_DLG_TARGET_LV  9201
#define IDC_DLG_ADD_BTN    9202
#define IDC_DLG_DEL_BTN    9203
#define IDC_DLG_TYPE_CB    9204
#define IDC_DLG_NAME_EDIT  9205
#define IDC_DLG_START      9206
#define IDC_DLG_END        9207
#define IDC_DLG_INTERVAL   9208
#define IDC_DLG_BYTES      9209
#define IDC_DLG_OK         9210
#define IDC_DLG_CANCEL     9211
#define IDC_DLG_PROC_NAME  9212
#define IDC_DLG_TREE_CHK   9213
#define IDC_DLG_PID_EDIT   9214
#define IDD_NEW_TASK       200
#define IDD_ASK_AI         300
#define IDD_ASK_CHAT       301
/* chat dialog controls (IDD_ASK_CHAT = 301) */
#define IDC_CHAT_TITLE      3010
#define IDC_CHAT_INPUT      3011
#define IDC_CHAT_OUTPUT     3012
#define IDC_CHAT_SEND       3013
#define IDC_CHAT_CLEAR      3014
#define IDC_CHAT_CLOSE      3015
/* key-setup mini-dialog controls (IDD_KEYSET = 400) */
#define IDD_KEYSET         400
#define IDC_KEYSET_EDIT    4001
#define IDC_KEYSET_OK      4002
#define IDC_KEYSET_CANCEL  4003

/* Partition editor */
#define IDD_DISKPICK       401
#define IDD_HEXEDIT        402

/* Process picker */
#define IDD_PROC_PICKER    600
/* partition editor dialog resource IDs */
#define IDD_DISKPICK        401
#define IDD_HEXEDIT         402

int  GuiAi_HandleCommand(HWND hWnd, int id, WPARAM wParam, LPARAM lParam);
void GuiAi_OpenAskAiDialog(HWND hParent);
void GuiAi_LaunchTaskAdmin(HWND hParent);
void GuiAi_OpenNewTask(HWND hParent, const char *type, const char *name,
                       int pid, int tree);
void GuiAi_OpenEditTask(HWND hParent, const char *taskId);
void GuiAi_NotifyLastTouched(int type, const char *name);

#endif
