using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;

namespace CACApp.Services;

public class CacReaderService : ICacReaderService
{
    private const int SCARD_S_SUCCESS = 0;
    private const int SCARD_PROTOCOL_T1 = 0x00000001;
    private const int SCARD_SHARE_SHARED = 0x00000002;
    private const int SCARD_LEAVE_CARD = 0x00000000;
    private const int SCARD_SCOPE_USER = 0x00000000;

    [DllImport("winscard.dll")]
    private static extern int SCardEstablishContext(int dwScope, IntPtr pvReserved1, IntPtr pvReserved2, out IntPtr phContext);

    [DllImport("winscard.dll")]
    private static extern int SCardReleaseContext(IntPtr hContext);

    [DllImport("winscard.dll", CharSet = CharSet.Auto)]
    private static extern int SCardListReaders(IntPtr hContext, string? mszGroups, byte[]? mszReaders, ref int pcchReaders);

    [DllImport("winscard.dll", CharSet = CharSet.Auto)]
    private static extern int SCardConnect(IntPtr hContext, string szReader, int dwShareMode, int dwPreferredProtocols, out IntPtr phCard, out int pdwActiveProtocol);

    [DllImport("winscard.dll")]
    private static extern int SCardDisconnect(IntPtr hCard, int dwDisposition);

    [DllImport("winscard.dll", CharSet = CharSet.Auto)]
    private static extern int SCardStatus(IntPtr hCard, StringBuilder szReaderName, ref int pcchReaderLen, out int pdwState, out int pdwProtocol, byte[] pbAtr, ref int pcbAtrLen);

    // Windows API for finding and centering windows
    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    private static extern IntPtr FindWindow(string? lpClassName, string? lpWindowName);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool SetWindowPos(IntPtr hWnd, IntPtr hWndInsertAfter, int X, int Y, int cx, int cy, uint uFlags);

    [DllImport("user32.dll")]
    private static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);

    [DllImport("user32.dll")]
    private static extern int GetSystemMetrics(int nIndex);

    private const int SM_CXSCREEN = 0;
    private const int SM_CYSCREEN = 1;
    private const uint SWP_NOSIZE = 0x0001;
    private const uint SWP_NOZORDER = 0x0004;
    private const uint SWP_SHOWWINDOW = 0x0040;

    [StructLayout(LayoutKind.Sequential)]
    private struct RECT
    {
        public int Left;
        public int Top;
        public int Right;
        public int Bottom;
    }

    public event EventHandler<string>? StatusChanged;

    public async Task<bool> IsReaderAvailableAsync()
    {
        return await Task.Run(() =>
        {
            try
            {
                var readers = GetAvailableReaders();
                return readers.Count > 0;
            }
            catch
            {
                return false;
            }
        });
    }

    public async Task<List<string>> GetAvailableReadersAsync()
    {
        return await Task.Run(() => GetAvailableReaders());
    }

    private List<string> GetAvailableReaders()
    {
        var readers = new List<string>();
        IntPtr hContext = IntPtr.Zero;

        try
        {
            int result = SCardEstablishContext(SCARD_SCOPE_USER, IntPtr.Zero, IntPtr.Zero, out hContext);
            if (result != SCARD_S_SUCCESS)
            {
                string errorMsg = GetScardErrorMessage(result);
                StatusChanged?.Invoke(this, $"Failed to establish smart card context: {errorMsg} (Error code: 0x{result:X8})");
                return readers;
            }

            int pcchReaders = 0;
            result = SCardListReaders(hContext, null, null, ref pcchReaders);
            
            uint error = unchecked((uint)result);
            
            // SCARD_E_NO_READERS_AVAILABLE (0x80100002) is expected when no readers are present
            // but we should still try to get the list if pcchReaders > 0
            if (result != SCARD_S_SUCCESS && error != 0x80100002U)
            {
                string errorMsg = GetScardErrorMessage(result);
                StatusChanged?.Invoke(this, $"Error getting reader list size: {errorMsg} (Error code: 0x{result:X8})");
                return readers;
            }

            // Even if we got SCARD_E_NO_READERS_AVAILABLE, pcchReaders might still be set
            // Try to read the list if there's space allocated
            // Note: With CharSet.Auto, pcchReaders is in characters, but we need bytes for Unicode (2 bytes per char)
            if (pcchReaders > 0)
            {
                // Allocate buffer: pcchReaders is in characters, Unicode needs 2 bytes per character
                byte[] mszReaders = new byte[pcchReaders * 2];
                int bufferSize = pcchReaders;
                result = SCardListReaders(hContext, null, mszReaders, ref bufferSize);

                if (result == SCARD_S_SUCCESS)
                {
                    // The Windows API returns a Unicode multi-string: reader names separated by null characters (2 bytes each), ending with double null (4 bytes)
                    // bufferSize now contains the actual length returned in characters
                    int actualByteLength = bufferSize * 2; // Convert characters to bytes
                    
                    // Parse Unicode multi-string by converting to string and splitting
                    // This handles the multi-string format correctly
                    string multiString = Encoding.Unicode.GetString(mszReaders, 0, actualByteLength);
                    string[] readerNames = multiString.Split(new char[] { '\0' }, StringSplitOptions.RemoveEmptyEntries);
                    
                    foreach (string readerName in readerNames)
                    {
                        if (!string.IsNullOrWhiteSpace(readerName) && !readers.Contains(readerName))
                        {
                            readers.Add(readerName);
                        }
                    }
                    
                    if (readers.Count == 0)
                    {
                        StatusChanged?.Invoke(this, "Smart card context established but no readers found. Please ensure your reader is connected and drivers are installed.");
                    }
                }
                else
                {
                    string errorMsg = GetScardErrorMessage(result);
                    StatusChanged?.Invoke(this, $"Error reading reader list: {errorMsg} (Error code: 0x{result:X8})");
                }
            }
            else
            {
                // No readers available - this is a normal condition
                StatusChanged?.Invoke(this, "No smart card readers detected. Please ensure your reader is connected and drivers are installed.");
            }
        }
        catch (DllNotFoundException ex)
        {
            StatusChanged?.Invoke(this, $"Smart card DLL not found: {ex.Message}. Ensure Windows Smart Card service is running.");
        }
        catch (System.ComponentModel.Win32Exception ex)
        {
            StatusChanged?.Invoke(this, $"Windows API error: {ex.Message} (Error code: {ex.NativeErrorCode}). Ensure Windows Smart Card service is running.");
        }
        catch (Exception ex)
        {
            StatusChanged?.Invoke(this, $"Error reading smart card readers: {ex.GetType().Name} - {ex.Message}");
        }
        finally
        {
            if (hContext != IntPtr.Zero)
            {
                SCardReleaseContext(hContext);
            }
        }

        return readers;
    }

    private string GetScardErrorMessage(int errorCode)
    {
        // Convert to uint for comparison since error codes are unsigned
        uint error = unchecked((uint)errorCode);
        
        // Common error codes
        if (error == 0x80100001 || error == 0x80100002 || error == 0x8010000C || error == 0x80100010 || error == 0x8010007A || error == 0x80100083)
            return "No smart card readers are available";
        if (error == 0x8010000D || error == 0x8010006A)
            return "Smart card service has been stopped";
        if (error == 0x8010000E || error == 0x80100069)
            return "Smart card service is not available";
        if (error == 0x80100004 || error == 0x80100009 || error == 0x8010001C)
            return "No smart card is present";
        if (error == 0x80100007)
            return "The reader is unavailable";
        if (error == 0x80100008 || error == 0x8010001B)
            return "Sharing violation - reader may be in use";
        if (error == 0x80100019)
            return "Unknown reader";
        if (error == 0x8010001A)
            return "Timeout";
        if (error == 0x80100013 || error == 0x80100023)
            return "Invalid handle";
        if (error == 0x80100014 || error == 0x80100024)
            return "Invalid parameter";
        
        return $"Smart card error (Error code: 0x{error:X8})";
    }

    public async Task<X509Certificate2?> ReadCacCertificateAsync(string? readerName = null, string? pin = null)
    {
        return await Task.Run(() =>
        {
            try
            {
                var readers = GetAvailableReaders();
                if (readers.Count == 0)
                {
                    StatusChanged?.Invoke(this, "No smart card readers found");
                    return null;
                }

                string selectedReader = readerName ?? readers.First();
                if (!readers.Contains(selectedReader))
                {
                    StatusChanged?.Invoke(this, $"Reader '{selectedReader}' not found");
                    return null;
                }

                if (!string.IsNullOrEmpty(pin))
                {
                    StatusChanged?.Invoke(this, $"Attempting to read CAC from {selectedReader} with PIN...");
                }
                else
                {
                    StatusChanged?.Invoke(this, $"Attempting to read CAC from {selectedReader}...");
                }

                IntPtr hContext = IntPtr.Zero;
                IntPtr hCard = IntPtr.Zero;

                try
                {
                    int result = SCardEstablishContext(SCARD_SCOPE_USER, IntPtr.Zero, IntPtr.Zero, out hContext);
                    if (result != SCARD_S_SUCCESS)
                    {
                        StatusChanged?.Invoke(this, "Failed to establish smart card context");
                        return null;
                    }

                    result = SCardConnect(hContext, selectedReader, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T1, out hCard, out int protocol);
                    if (result != SCARD_S_SUCCESS)
                    {
                        StatusChanged?.Invoke(this, "Failed to connect to smart card. Please insert your CAC card.");
                        return null;
                    }

                    StatusChanged?.Invoke(this, "CAC card detected. Reading certificate...");

                    var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
                    store.Open(OpenFlags.ReadOnly);

                    var certificates = store.Certificates.Find(X509FindType.FindByTimeValid, DateTime.Now, true);
                    var cacCert = certificates.Cast<X509Certificate2>()
                        .FirstOrDefault(c => c.HasPrivateKey && IsCacCertificate(c));

                    store.Close();

                    if (cacCert != null)
                    {
                        StatusChanged?.Invoke(this, "Certificate found. Verifying private key access...");
                        
                        // Start monitoring for PIN dialog BEFORE attempting to access private key
                        // This ensures we catch the dialog as soon as it appears
                        Task.Run(() => CenterWindowsPinDialog());
                        
                        // Small delay to let monitoring start
                        Thread.Sleep(100);
                        
                        // Verify that we can actually access the private key
                        // This will trigger Windows PIN prompt if needed, or use cached PIN
                        // If PIN is incorrect or not provided, this will fail
                        bool canAccessPrivateKey = VerifyPrivateKeyAccess(cacCert);
                        
                        if (!canAccessPrivateKey)
                        {
                            StatusChanged?.Invoke(this, "Cannot access private key. PIN may be incorrect or required.");
                            return null;
                        }
                        
                        StatusChanged?.Invoke(this, "Certificate accessible. Private key verified.");
                        return cacCert;
                    }
                    else
                    {
                        StatusChanged?.Invoke(this, "No valid CAC certificate found on card");
                        return null;
                    }
                }
                finally
                {
                    if (hCard != IntPtr.Zero)
                    {
                        SCardDisconnect(hCard, SCARD_LEAVE_CARD);
                    }
                    if (hContext != IntPtr.Zero)
                    {
                        SCardReleaseContext(hContext);
                    }
                }
            }
            catch (Exception ex)
            {
                StatusChanged?.Invoke(this, $"Error reading CAC certificate: {ex.Message}");
                return null;
            }
        });
    }

    private bool IsCacCertificate(X509Certificate2 cert)
    {
        try
        {
            var subject = cert.Subject;
            return subject.Contains("CN=") && 
                   (subject.Contains("GOV") || subject.Contains("MIL") || 
                    subject.Contains("DoD") || subject.Contains("EMAILADDRESS"));
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Verifies that the private key is accessible by attempting a cryptographic operation.
    /// Windows will prompt for PIN if needed, or use cached credentials.
    /// This ensures that PIN authentication actually occurs (either through Windows prompt or cached PIN).
    /// </summary>
    private bool VerifyPrivateKeyAccess(X509Certificate2 certificate)
    {
        try
        {
            // Attempt to access the private key
            var privateKey = certificate.GetRSAPrivateKey();
            if (privateKey == null)
            {
                StatusChanged?.Invoke(this, "Private key not available");
                return false;
            }

            // Try to perform a small cryptographic operation to verify we can actually use the key
            // This will trigger Windows PIN prompt if PIN is not cached, or use cached PIN
            byte[] testData = Encoding.UTF8.GetBytes("VERIFY_KEY_ACCESS");
            
            try
            {
                // Attempt to sign data - this requires PIN authentication (either cached or prompted)
                // If PIN is wrong or access is denied, this will throw an exception
                byte[] signature = privateKey.SignData(testData, System.Security.Cryptography.HashAlgorithmName.SHA256, System.Security.Cryptography.RSASignaturePadding.Pkcs1);
                
                // If we get here, the private key is accessible (PIN was correct or cached)
                return true;
            }
            catch (System.Security.Cryptography.CryptographicException ex)
            {
                // Cryptographic exceptions typically indicate:
                // - PIN failure (user entered wrong PIN or cancelled)
                // - Access denied
                // - Key not accessible
                StatusChanged?.Invoke(this, $"Private key access failed: {ex.Message}");
                return false;
            }
            catch (UnauthorizedAccessException ex)
            {
                StatusChanged?.Invoke(this, $"Access denied: {ex.Message}");
                return false;
            }
            catch (Exception ex)
            {
                // Other exceptions might indicate different issues
                StatusChanged?.Invoke(this, $"Error accessing private key: {ex.Message}");
                return false;
            }
        }
        catch (Exception ex)
        {
            StatusChanged?.Invoke(this, $"Failed to verify private key access: {ex.Message}");
            return false;
        }
    }

    private HashSet<IntPtr> processedWindows = new HashSet<IntPtr>();

    /// <summary>
    /// Attempts to find and center the Windows Smart Card PIN dialog window.
    /// This runs in a background thread and aggressively polls for ANY new dialog windows.
    /// </summary>
    private void CenterWindowsPinDialog()
    {
        try
        {
            processedWindows.Clear();
            
            // Poll for up to 15 seconds, checking every 25ms (very aggressive)
            for (int i = 0; i < 600; i++)
            {
                Thread.Sleep(25);

                // Method 1: Check foreground window first (fastest)
                IntPtr foregroundWnd = GetForegroundWindow();
                if (foregroundWnd != IntPtr.Zero && IsWindowVisible(foregroundWnd) && !processedWindows.Contains(foregroundWnd))
                {
                    if (IsPinDialog(foregroundWnd))
                    {
                        processedWindows.Add(foregroundWnd);
                        CenterWindow(foregroundWnd);
                        // Keep monitoring this specific window
                        MonitorAndCenterWindow(foregroundWnd);
                        return;
                    }
                }

                // Method 2: Enum ALL visible windows and check for dialogs (most thorough)
                // Do this more frequently to catch dialogs as soon as they appear
                if (i % 4 == 0) // Every 100ms
                {
                    EnumWindows((hWnd, lParam) =>
                    {
                        try
                        {
                            if (hWnd != IntPtr.Zero && 
                                IsWindowVisible(hWnd) && 
                                !processedWindows.Contains(hWnd))
                            {
                                if (IsPinDialog(hWnd))
                                {
                                    processedWindows.Add(hWnd);
                                    CenterWindow(hWnd);
                                    // Start monitoring this window
                                    Task.Run(() => MonitorAndCenterWindow(hWnd));
                                    return false; // Stop enumeration - found it
                                }
                            }
                        }
                        catch
                        {
                            // Continue enumeration on error
                        }
                        return true; // Continue enumeration
                    }, IntPtr.Zero);
                }

                // Method 3: Also check common dialog class names directly
                if (i % 8 == 0) // Every 200ms
                {
                    string[] possibleClasses = new[]
                    {
                        "#32770", // Standard dialog class - most common
                        "Credential Dialog Xaml Host",
                        "Microsoft.Windows.SecureAssessmentBrowser",
                        "Windows.Security.Credentials.UI.CredentialPicker",
                        "CredUI" // Credential UI
                    };

                    foreach (string className in possibleClasses)
                    {
                        IntPtr hWnd = FindWindow(className, null);
                        if (hWnd != IntPtr.Zero && 
                            IsWindowVisible(hWnd) && 
                            !processedWindows.Contains(hWnd))
                        {
                            if (IsPinDialog(hWnd))
                            {
                                processedWindows.Add(hWnd);
                                CenterWindow(hWnd);
                                MonitorAndCenterWindow(hWnd);
                                return;
                            }
                        }
                    }
                }
            }
        }
        catch
        {
            // Silently fail - this is a best-effort feature
        }
    }

    /// <summary>
    /// Continuously monitors and centers a specific window until it's closed.
    /// </summary>
    private void MonitorAndCenterWindow(IntPtr hWnd)
    {
        try
        {
            for (int i = 0; i < 200; i++) // Monitor for up to 5 seconds
            {
                Thread.Sleep(25);
                
                if (!IsWindowVisible(hWnd))
                {
                    break; // Window closed
                }
                
                // Re-center the window periodically in case it moves
                if (i % 4 == 0) // Every 100ms
                {
                    CenterWindow(hWnd);
                }
            }
        }
        catch
        {
            // Silently fail
        }
    }

    /// <summary>
    /// Checks if a window is likely the Windows PIN dialog.
    /// Uses more lenient criteria to catch any dialog that might be the PIN prompt.
    /// </summary>
    private bool IsPinDialog(IntPtr hWnd)
    {
        try
        {
            if (hWnd == IntPtr.Zero) return false;

            StringBuilder className = new StringBuilder(256);
            StringBuilder windowText = new StringBuilder(256);

            GetClassName(hWnd, className, className.Capacity);
            GetWindowText(hWnd, windowText, windowText.Capacity);

            string classNameStr = className.ToString().ToLower();
            string windowTextStr = windowText.ToString().ToLower();

            // Check if window is dialog-sized (typical for dialogs)
            GetWindowRect(hWnd, out RECT rect);
            int width = rect.Right - rect.Left;
            int height = rect.Bottom - rect.Top;
            bool isDialogSize = width > 150 && width < 1000 && height > 80 && height < 800;

            if (!isDialogSize) return false;

            // Check for common PIN dialog indicators in window text
            bool hasPinKeywords = windowTextStr.Contains("pin") || 
                                  windowTextStr.Contains("smart card") ||
                                  windowTextStr.Contains("credential") ||
                                  windowTextStr.Contains("password") ||
                                  windowTextStr.Contains("enter") ||
                                  windowTextStr.Contains("security");

            // Check for dialog class names
            bool isDialogClass = classNameStr == "#32770" || // Standard dialog
                                 classNameStr.Contains("credential") ||
                                 classNameStr.Contains("dialog") ||
                                 classNameStr.Contains("xaml") ||
                                 classNameStr.Contains("cred") ||
                                 classNameStr == "credui" ||
                                 classNameStr.Contains("secure");

            // If it's a dialog class OR has PIN keywords, consider it a candidate
            // Be more lenient - center any dialog that appears during PIN verification
            return isDialogClass || hasPinKeywords;
        }
        catch
        {
            return false;
        }
    }

    [DllImport("user32.dll")]
    private static extern bool IsWindowVisible(IntPtr hWnd);

    [DllImport("user32.dll")]
    private static extern IntPtr GetForegroundWindow();

    [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern int GetWindowText(IntPtr hWnd, StringBuilder lpString, int nMaxCount);

    [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern int GetClassName(IntPtr hWnd, StringBuilder lpClassName, int nMaxCount);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);

    private delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

    [DllImport("user32.dll")]
    private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);

    [DllImport("user32.dll")]
    private static extern bool BringWindowToTop(IntPtr hWnd);

    [DllImport("user32.dll")]
    private static extern bool SetForegroundWindow(IntPtr hWnd);

    [DllImport("user32.dll")]
    private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

    [DllImport("user32.dll")]
    private static extern bool MoveWindow(IntPtr hWnd, int X, int Y, int nWidth, int nHeight, bool bRepaint);

    private const int SW_RESTORE = 9;
    private const int SW_SHOW = 5;

    /// <summary>
    /// Centers a window on the primary screen and brings it to foreground.
    /// Uses multiple methods to ensure the window is centered.
    /// </summary>
    private void CenterWindow(IntPtr hWnd)
    {
        try
        {
            if (hWnd == IntPtr.Zero) return;

            // Show and restore window if minimized
            ShowWindow(hWnd, SW_SHOW);
            ShowWindow(hWnd, SW_RESTORE);

            // Get window dimensions
            GetWindowRect(hWnd, out RECT rect);
            int windowWidth = rect.Right - rect.Left;
            int windowHeight = rect.Bottom - rect.Top;

            // Get screen dimensions
            int screenWidth = GetSystemMetrics(SM_CXSCREEN);
            int screenHeight = GetSystemMetrics(SM_CYSCREEN);

            // Calculate center position
            int x = (screenWidth - windowWidth) / 2;
            int y = (screenHeight - windowHeight) / 2;

            // Try multiple methods to center the window
            // Method 1: SetWindowPos
            SetWindowPos(hWnd, IntPtr.Zero, x, y, 0, 0, SWP_NOSIZE | SWP_NOZORDER | SWP_SHOWWINDOW);
            
            // Method 2: MoveWindow (sometimes works better for system dialogs)
            MoveWindow(hWnd, x, y, windowWidth, windowHeight, true);
            
            // Method 3: SetWindowPos again with show flag
            SetWindowPos(hWnd, IntPtr.Zero, x, y, 0, 0, SWP_NOSIZE | SWP_NOZORDER | SWP_SHOWWINDOW);
            
            // Bring to foreground
            BringWindowToTop(hWnd);
            SetForegroundWindow(hWnd);
            
            // Small delay then try again (sometimes Windows needs a moment)
            Thread.Sleep(50);
            SetWindowPos(hWnd, IntPtr.Zero, x, y, 0, 0, SWP_NOSIZE | SWP_NOZORDER | SWP_SHOWWINDOW);
        }
        catch
        {
            // Silently fail
        }
    }

    public async Task<bool> PromptForPinAsync()
    {
        return await Task.Run(() =>
        {
            try
            {
                StatusChanged?.Invoke(this, "Please enter your PIN when prompted");
                
                var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
                store.Open(OpenFlags.ReadOnly);
                
                var certificates = store.Certificates.Find(X509FindType.FindByTimeValid, DateTime.Now, true);
                var hasCacCert = certificates.Cast<X509Certificate2>()
                    .Any(c => c.HasPrivateKey && IsCacCertificate(c));
                
                store.Close();
                
                return hasCacCert;
            }
            catch
            {
                return false;
            }
        });
    }
}

