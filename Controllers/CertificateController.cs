using Microsoft.AspNetCore.Mvc;
using CACApp.Services;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;

namespace CACApp.Controllers;

[ApiController]
[Route("api/[controller]")]
public class CertificateController : ControllerBase
{
    private readonly ICertificateService _certificateService;
    private readonly ILogger<CertificateController> _logger;

    public CertificateController(ICertificateService certificateService, ILogger<CertificateController> logger)
    {
        _certificateService = certificateService;
        _logger = logger;
    }

    [HttpPost("validate-chain")]
    public async Task<ActionResult<CertificateChainInfoDto>> ValidateChain([FromBody] CertificateRequest request)
    {
        try
        {
            var certificate = ConvertFromBase64(request.CertificateBase64);
            if (certificate == null)
            {
                return BadRequest(new { error = "Invalid certificate data" });
            }

            var chainInfo = await _certificateService.GetChainInfoAsync(certificate);

            var dto = new CertificateChainInfoDto
            {
                IsValid = chainInfo.IsValid,
                ChainErrors = chainInfo.ChainErrors,
                Chain = chainInfo.Chain.Select(c => new CertificateInfoDto
                {
                    Subject = c.Subject,
                    Issuer = c.Issuer,
                    NotBefore = c.NotBefore,
                    NotAfter = c.NotAfter,
                    IsValid = c.IsValid,
                    Thumbprint = c.Thumbprint
                }).ToList(),
                OnlineValidationFailed = chainInfo.OnlineValidationFailed,
                OnlineValidationFailureReason = chainInfo.OnlineValidationFailureReason
            };

            return Ok(dto);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error validating certificate chain");
            return StatusCode(500, new { error = "Failed to validate certificate chain" });
        }
    }

    [HttpPost("is-active")]
    public ActionResult<bool> IsCertificateActive([FromBody] CertificateRequest request)
    {
        try
        {
            var certificate = ConvertFromBase64(request.CertificateBase64);
            if (certificate == null)
            {
                return BadRequest(new { error = "Invalid certificate data" });
            }

            var isActive = _certificateService.IsCertificateActive(certificate);
            return Ok(new { isActive });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error checking certificate status");
            return StatusCode(500, new { error = "Failed to check certificate status" });
        }
    }

    [HttpPost("details")]
    public async Task<ActionResult<CertificateDetailsDto>> GetCertificateDetails([FromBody] CertificateRequest request)
    {
        try
        {
            var certificate = ConvertFromBase64(request.CertificateBase64);
            if (certificate == null)
            {
                return BadRequest(new { error = "Invalid certificate data" });
            }

            var details = await _certificateService.GetCertificateDetailsAsync(certificate);

            var dto = new CertificateDetailsDto
            {
                Subject = details.Subject,
                Issuer = details.Issuer,
                SerialNumber = details.SerialNumber,
                Thumbprint = details.Thumbprint,
                NotBefore = details.NotBefore,
                NotAfter = details.NotAfter,
                Version = details.Version,
                SignatureAlgorithm = details.SignatureAlgorithm,
                PublicKeyAlgorithm = details.PublicKeyAlgorithm,
                KeySize = details.KeySize,
                HasPrivateKey = details.HasPrivateKey,
                KeyUsage = details.KeyUsage,
                ExtendedKeyUsage = details.ExtendedKeyUsage,
                SubjectAlternativeNames = details.SubjectAlternativeNames,
                CertificatePolicies = details.CertificatePolicies,
                CrlDistributionPoints = details.CrlDistributionPoints,
                OcspUrls = details.OcspUrls,
                SubjectNameParts = details.SubjectNameParts,
                IssuerNameParts = details.IssuerNameParts,
                DaysUntilExpiration = details.DaysUntilExpiration,
                IsExpiringSoon = details.IsExpiringSoon
            };

            return Ok(dto);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting certificate details");
            return StatusCode(500, new { error = "Failed to get certificate details", details = ex.Message });
        }
    }

    private X509Certificate2? ConvertFromBase64(string base64)
    {
        try
        {
            var bytes = Convert.FromBase64String(base64);

            // Try loading as PEM first
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

            // For DER format, use the constructor with warning suppression
            // Note: The recommended X509CertificateLoader API doesn't have a direct
            // method for loading from byte arrays in .NET 9.0.305
            // This is a known limitation and the constructor still works correctly.
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

public class CertificateRequest
{
    public string CertificateBase64 { get; set; } = string.Empty;
}

public class CertificateChainInfoDto
{
    public bool IsValid { get; set; }
    public List<string> ChainErrors { get; set; } = new();
    public List<CertificateInfoDto> Chain { get; set; } = new();
    public bool OnlineValidationFailed { get; set; }
    public string? OnlineValidationFailureReason { get; set; }
}

public class CertificateInfoDto
{
    public string Subject { get; set; } = string.Empty;
    public string Issuer { get; set; } = string.Empty;
    public DateTime NotBefore { get; set; }
    public DateTime NotAfter { get; set; }
    public bool IsValid { get; set; }
    public string Thumbprint { get; set; } = string.Empty;
}

public class CertificateDetailsDto
{
    public string Subject { get; set; } = string.Empty;
    public string Issuer { get; set; } = string.Empty;
    public string SerialNumber { get; set; } = string.Empty;
    public string Thumbprint { get; set; } = string.Empty;
    public DateTime NotBefore { get; set; }
    public DateTime NotAfter { get; set; }
    public string Version { get; set; } = string.Empty;
    public string SignatureAlgorithm { get; set; } = string.Empty;
    public string PublicKeyAlgorithm { get; set; } = string.Empty;
    public int KeySize { get; set; }
    public bool HasPrivateKey { get; set; }
    public List<string> KeyUsage { get; set; } = new();
    public List<string> ExtendedKeyUsage { get; set; } = new();
    public List<string> SubjectAlternativeNames { get; set; } = new();
    public List<string> CertificatePolicies { get; set; } = new();
    public List<string> CrlDistributionPoints { get; set; } = new();
    public List<string> OcspUrls { get; set; } = new();
    public Dictionary<string, string> SubjectNameParts { get; set; } = new();
    public Dictionary<string, string> IssuerNameParts { get; set; } = new();
    public int DaysUntilExpiration { get; set; }
    public bool IsExpiringSoon { get; set; }
}

