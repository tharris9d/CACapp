using Microsoft.AspNetCore.Mvc;
using CACApp.Services;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.Text;

namespace CACApp.Controllers;

[ApiController]
[Route("api/[controller]")]
public class CertificateExportController : ControllerBase
{
    private readonly ICertificateExportService _exportService;
    private readonly ILogger<CertificateExportController> _logger;

    public CertificateExportController(ICertificateExportService exportService, ILogger<CertificateExportController> logger)
    {
        _exportService = exportService;
        _logger = logger;
    }

    [HttpPost("export")]
    public async Task<IActionResult> ExportCertificate([FromBody] CertificateExportRequest request)
    {
        try
        {
            var certificate = ConvertFromBase64(request.CertificateBase64);
            if (certificate == null)
            {
                return BadRequest(new { error = "Invalid certificate data" });
            }

            var result = await _exportService.ExportCertificateAsync(certificate, request.Format, request.Password);
            
            return File(result.Data, result.MimeType, result.FileName);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error exporting certificate");
            return StatusCode(500, new { error = "Failed to export certificate", details = ex.Message });
        }
    }

    [HttpPost("import")]
    public async Task<ActionResult<CertificateImportDto>> ImportCertificate([FromForm] IFormFile file, [FromForm] string? password = null)
    {
        try
        {
            if (file == null || file.Length == 0)
            {
                return BadRequest(new { error = "No file provided" });
            }

            using var memoryStream = new MemoryStream();
            await file.CopyToAsync(memoryStream);
            var fileData = memoryStream.ToArray();

            CertificateImportFormat format = DetermineImportFormat(file.FileName, fileData);
            
            var certificate = await _exportService.ImportCertificateAsync(fileData, format, password);
            
            if (certificate == null)
            {
                return BadRequest(new { error = "Failed to import certificate. Invalid format or password." });
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

            var certDto = new CertificateImportDto
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
            _logger.LogError(ex, "Error importing certificate");
            return StatusCode(500, new { error = "Failed to import certificate", details = ex.Message });
        }
    }

    private CertificateImportFormat DetermineImportFormat(string fileName, byte[] data)
    {
        var extension = Path.GetExtension(fileName).ToLowerInvariant();
        
        if (extension == ".pem" || extension == ".crt" || extension == ".cer")
        {
            var text = Encoding.UTF8.GetString(data);
            if (text.Contains("-----BEGIN"))
            {
                return CertificateImportFormat.Pem;
            }
        }
        
        if (extension == ".pfx" || extension == ".p12")
        {
            return CertificateImportFormat.Pfx;
        }
        
        return CertificateImportFormat.Der;
    }

    private X509Certificate2? ConvertFromBase64(string base64)
    {
        try
        {
            var bytes = Convert.FromBase64String(base64);
            
            try
            {
                var pemString = System.Text.Encoding.UTF8.GetString(bytes);
                if (pemString.Contains("-----BEGIN"))
                {
                    return X509Certificate2.CreateFromPem(pemString);
                }
            }
            catch
            {
                // Not PEM format, continue to DER
            }
            
#pragma warning disable SYSLIB0057
            return new X509Certificate2(bytes);
#pragma warning restore SYSLIB0057
        }
        catch
        {
            return null;
        }
    }
}

public class CertificateExportRequest
{
    public string CertificateBase64 { get; set; } = string.Empty;
    public CertificateExportFormat Format { get; set; }
    public string? Password { get; set; }
}

public class CertificateImportDto
{
    public string Subject { get; set; } = string.Empty;
    public string Issuer { get; set; } = string.Empty;
    public DateTime NotBefore { get; set; }
    public DateTime NotAfter { get; set; }
    public string Thumbprint { get; set; } = string.Empty;
    public string SerialNumber { get; set; } = string.Empty;
    public string CertificateBase64 { get; set; } = string.Empty;
}


