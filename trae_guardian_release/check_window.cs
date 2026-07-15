using System;
using System.Runtime.InteropServices;

class Program {
    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    static extern IntPtr FindWindow(string lpClassName, string lpWindowName);
    
    [DllImport("user32.dll")]
    static extern bool IsWindowVisible(IntPtr hWnd);
    
    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    static extern int GetWindowText(IntPtr hWnd, System.Text.StringBuilder lpString, int nMaxCount);
    
    static void Main() {
        IntPtr hwnd = FindWindow(null, "Process Guardian");
        Console.WriteLine("FindWindow by title 'Process Guardian': " + hwnd);
        if (hwnd != IntPtr.Zero) {
            Console.WriteLine("IsVisible: " + IsWindowVisible(hwnd));
            System.Text.StringBuilder sb = new System.Text.StringBuilder(256);
            GetWindowText(hwnd, sb, 256);
            Console.WriteLine("Window text: " + sb.ToString());
        }
        
        hwnd = FindWindow("Qt6QWindowIcon", null);
        Console.WriteLine("\nFindWindow by class 'Qt6QWindowIcon': " + hwnd);
        if (hwnd != IntPtr.Zero) {
            Console.WriteLine("IsVisible: " + IsWindowVisible(hwnd));
            System.Text.StringBuilder sb = new System.Text.StringBuilder(256);
            GetWindowText(hwnd, sb, 256);
            Console.WriteLine("Window text: " + sb.ToString());
        }
    }
}