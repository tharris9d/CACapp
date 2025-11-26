using Microsoft.AspNetCore.Mvc;
using CACApp.Services;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace CACApp.Controllers;

[ApiController]
[Route("api/[controller]")]
public class CacReaderController : ControllerBase
{
    private readonly ICacReaderService _cacReaderService;
    private readonly ILogger<CacReaderController> _logger;

    public CacReaderController(ICacReaderService cacReaderService, ILogger<CacReaderController> logger)
    {
        _cacReaderService = cacReaderService;
        _logger = logger;
    }

    [HttpGet("readers")]
    public async Task<ActionResult<object>> GetAvailableReaders()
    {
        try
        {
            var readers = await _cacReaderService.GetAvailableReadersAsync();
            _logger.LogInformation($"Found {readers.Count} smart card reader(s)");
            
            return Ok(new 
            { 
                readers = readers,
                count = readers.Count,
                message = readers.Count > 0 
                    ? $"Found {readers.Count} reader(s)" 
                    : "No readers found. Ensure your smart card reader is connected and drivers are installed."
            });
        }
        catch (DllNotFoundException ex)
        {
            _logger.LogError(ex, "Smart card DLL not found");
            return StatusCode(500, new 
            { 
                error = "Smart card service not available", 
                message = "Ensure Windows Smart Card service is running. Run 'sc start SCardSvr' as administrator.",
                details = ex.Message,
                readers = new List<string>(),
                count = 0
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting available readers");
            return StatusCode(500, new 
            { 
                error = "Failed to get available readers", 
                message = ex.Message,
                details = ex.ToString(),
                readers = new List<string>(),
                count = 0
            });
        }
    }

    [HttpPost("read")]
    public async Task<ActionResult<CertificateDto>> ReadCacCertificate([FromBody] ReadCacRequest request)
    {
        try
        {
            var certificate = await _cacReaderService.ReadCacCertificateAsync(request.ReaderName, request.Pin);
            
            if (certificate == null)
            {
                return Unauthorized(new { error = "Certificate access failed", details = "Unable to access certificate. PIN may be incorrect, required, or private key access was denied. Windows may prompt for PIN." });
            }

            byte[] certBytes;
            try
            {
                certBytes = certificate.Export(X509ContentType.Cert);
            }
            catch
            {
                certBytes = certificate.RawData;
            }

            var certDto = new CertificateDto
            {
                Subject = certificate.Subject,
                Issuer = certificate.Issuer,
                NotBefore = certificate.NotBefore,
                NotAfter = certificate.NotAfter,
                Thumbprint = certificate.Thumbprint,
                SerialNumber = certificate.SerialNumber,
                CertificateBase64 = Convert.ToBase64String(certBytes)
            };

            return Ok(certDto);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error reading CAC certificate");
            return StatusCode(500, new { error = "Failed to read CAC certificate", details = ex.Message });
        }
    }

    [HttpGet("available")]
    public async Task<ActionResult<bool>> IsReaderAvailable()
    {
        try
        {
            var available = await _cacReaderService.IsReaderAvailableAsync();
            return Ok(new { available });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error checking reader availability");
            return StatusCode(500, new { error = "Failed to check reader availability" });
        }
    }

    [HttpGet("diagnostics")]
    public ActionResult<object> GetDiagnostics()
    {
        try
        {
            var diagnostics = new
            {
                platform = System.Runtime.InteropServices.RuntimeInformation.OSDescription,
                isWindows = System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform(System.Runtime.InteropServices.OSPlatform.Windows),
                processArchitecture = System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture.ToString(),
                smartCardServiceRunning = CheckSmartCardService(),
                timestamp = DateTime.UtcNow
            };
            return Ok(diagnostics);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting diagnostics");
            return StatusCode(500, new { error = "Failed to get diagnostics", details = ex.Message });
        }
    }

    private bool CheckSmartCardService()
    {
        try
        {
            if (!System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform(System.Runtime.InteropServices.OSPlatform.Windows))
                return false;

            using var process = new System.Diagnostics.Process
            {
                StartInfo = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "sc",
                    Arguments = "query SCardSvr",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true
                }
            };
            process.Start();
            string output = process.StandardOutput.ReadToEnd();
            process.WaitForExit();
            
            return output.Contains("RUNNING");
        }
        catch
        {
            return false;
        }
    }
}

public class ReadCacRequest
{
    public string? ReaderName { get; set; }
    public string? Pin { get; set; }
}

public class CertificateDto
{
    public string Subject { get; set; } = string.Empty;
    public string Issuer { get; set; } = string.Empty;
    public DateTime NotBefore { get; set; }
    public DateTime NotAfter { get; set; }
    public string Thumbprint { get; set; } = string.Empty;
    public string SerialNumber { get; set; } = string.Empty;
    public string CertificateBase64 { get; set; } = string.Empty;
}

