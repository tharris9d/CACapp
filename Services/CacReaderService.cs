using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;

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
                        if (!string.IsNullOrEmpty(pin))
                        {
                            StatusChanged?.Invoke(this, "PIN provided. Accessing certificate private key...");
                            try
                            {
                                var privateKey = cacCert.GetRSAPrivateKey();
                                if (privateKey != null)
                                {
                                    StatusChanged?.Invoke(this, "Certificate found and accessible successfully");
                                }
                                else
                                {
                                    StatusChanged?.Invoke(this, "Certificate found but private key access may require PIN entry");
                                }
                            }
                            catch (Exception ex)
                            {
                                StatusChanged?.Invoke(this, $"Certificate found but private key access failed: {ex.Message}. Windows may prompt for PIN.");
                            }
                        }
                        else
                        {
                            StatusChanged?.Invoke(this, "Certificate found successfully. Windows may prompt for PIN when accessing private key.");
                        }
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

