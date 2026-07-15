#define WIN32_LEAN_AND_MEAN
#define UNICODE
#define _UNICODE

#include <windows.h>
#include <stdio.h>
#include <time.h>

int main(void) {
    wprintf(L"TRAE Guardian 截屏工具\n");
    wprintf(L"等待8秒后截取屏幕...\n");
    Sleep(8000);
    
    HWND hWnd = GetDesktopWindow();
    HDC hdcScreen = GetDC(hWnd);
    HDC hdcMem = CreateCompatibleDC(hdcScreen);
    
    int width = GetSystemMetrics(SM_CXSCREEN);
    int height = GetSystemMetrics(SM_CYSCREEN);
    
    wprintf(L"屏幕分辨率: %dx%d\n", width, height);
    
    HBITMAP hBitmap = CreateCompatibleBitmap(hdcScreen, width, height);
    HBITMAP hOldBitmap = (HBITMAP)SelectObject(hdcMem, hBitmap);
    
    BitBlt(hdcMem, 0, 0, width, height, hdcScreen, 0, 0, SRCCOPY);
    
    SelectObject(hdcMem, hOldBitmap);
    
    BITMAP bmp;
    GetObject(hBitmap, sizeof(BITMAP), &bmp);
    
    BITMAPFILEHEADER bfh;
    BITMAPINFOHEADER bih;
    
    bfh.bfType = 0x4D42;
    bfh.bfSize = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER) + bmp.bmWidthBytes * bmp.bmHeight;
    bfh.bfReserved1 = 0;
    bfh.bfReserved2 = 0;
    bfh.bfOffBits = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);
    
    bih.biSize = sizeof(BITMAPINFOHEADER);
    bih.biWidth = bmp.bmWidth;
    bih.biHeight = bmp.bmHeight;
    bih.biPlanes = 1;
    bih.biBitCount = 24;
    bih.biCompression = BI_RGB;
    bih.biSizeImage = 0;
    bih.biXPelsPerMeter = 0;
    bih.biYPelsPerMeter = 0;
    bih.biClrUsed = 0;
    bih.biClrImportant = 0;
    
    time_t now = time(NULL);
    wchar_t filename[256];
    swprintf(filename, 256, L"screen_capture_%lld.bmp", (long long)now);
    
    FILE* f = _wfopen(filename, L"wb");
    if (f) {
        fwrite(&bfh, sizeof(BITMAPFILEHEADER), 1, f);
        fwrite(&bih, sizeof(BITMAPINFOHEADER), 1, f);
        
        BYTE* pBuffer = (BYTE*)malloc(bmp.bmWidthBytes * bmp.bmHeight);
        if (pBuffer) {
            GetDIBits(hdcScreen, hBitmap, 0, bmp.bmHeight, pBuffer, 
                (BITMAPINFO*)&bih, DIB_RGB_COLORS);
            fwrite(pBuffer, bmp.bmWidthBytes * bmp.bmHeight, 1, f);
            free(pBuffer);
            wprintf(L"截图成功！已保存为: %ls\n", filename);
        } else {
            wprintf(L"错误: 内存分配失败\n");
        }
        fclose(f);
    } else {
        wprintf(L"错误: 无法创建文件\n");
    }
    
    DeleteObject(hBitmap);
    DeleteDC(hdcMem);
    ReleaseDC(hWnd, hdcScreen);
    
    return 0;
}