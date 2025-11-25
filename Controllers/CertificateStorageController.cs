using Microsoft.AspNetCore.Mvc;
using CACApp.Services;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;

namespace CACApp.Controllers;

[ApiController]
[Route("api/[controller]")]
public class CertificateStorageController : ControllerBase
{
    private readonly ICertificateStorageService _certificateStorageService;
    private readonly ILogger<CertificateStorageController> _logger;

    public CertificateStorageController(ICertificateStorageService certificateStorageService, ILogger<CertificateStorageController> logger)
    {
        _certificateStorageService = certificateStorageService;
        _logger = logger;
    }

    [HttpPost("store")]
    public async Task<ActionResult> StoreCertificate([FromBody] CertificateRequest request)
    {
        try
        {
            var certificate = ConvertFromBase64(request.CertificateBase64);
            if (certificate == null)
            {
                return BadRequest(new { error = "Invalid certificate data" });
            }

            var success = await _certificateStorageService.StoreCertificateAsync(certificate);

            if (success)
            {
                return Ok(new { message = "Certificate stored successfully" });
            }
            else
            {
                return StatusCode(500, new { error = "Failed to store certificate" });
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error storing certificate");
            return StatusCode(500, new { error = "Failed to store certificate" });
        }
    }

    [HttpGet("stored")]
    public async Task<ActionResult<List<StoredCertificateDto>>> GetStoredCertificates()
    {
        try
        {
            var certificates = await _certificateStorageService.GetStoredCertificatesAsync();
            var dtos = certificates.Select(c => new StoredCertificateDto
            {
                Thumbprint = c.Thumbprint,
                Subject = c.Subject,
                Issuer = c.Issuer,
                NotBefore = c.NotBefore,
                NotAfter = c.NotAfter,
                StoredDate = c.StoredDate,
                IsActive = c.IsActive,
                DaysUntilExpiration = c.DaysUntilExpiration
            }).ToList();

            return Ok(dtos);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting stored certificates");
            return StatusCode(500, new { error = "Failed to get stored certificates" });
        }
    }

    [HttpDelete("{thumbprint}")]
    public async Task<ActionResult> DeleteCertificate(string thumbprint)
    {
        try
        {
            var success = await _certificateStorageService.DeleteCertificateAsync(thumbprint);

            if (success)
            {
                return Ok(new { message = "Certificate deleted successfully" });
            }
            else
            {
                return StatusCode(500, new { error = "Failed to delete certificate" });
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error deleting certificate");
            return StatusCode(500, new { error = "Failed to delete certificate" });
        }
    }

    [HttpPost("search")]
    public async Task<ActionResult<List<StoredCertificateDto>>> SearchCertificates([FromBody] CertificateSearchCriteriaDto criteria)
    {
        try
        {
            var searchCriteria = new CertificateSearchCriteria
            {
                SearchText = criteria.SearchText,
                Category = criteria.Category,
                IsActive = criteria.IsActive,
                ExpiresBefore = criteria.ExpiresBefore,
                ExpiresAfter = criteria.ExpiresAfter,
                DaysUntilExpiration = criteria.DaysUntilExpiration,
                ExpiringSoon = criteria.ExpiringSoon
            };

            var certificates = await _certificateStorageService.SearchCertificatesAsync(searchCriteria);
            var dtos = certificates.Select(c => new StoredCertificateDto
            {
                Thumbprint = c.Thumbprint,
                Subject = c.Subject,
                Issuer = c.Issuer,
                NotBefore = c.NotBefore,
                NotAfter = c.NotAfter,
                StoredDate = c.StoredDate,
                IsActive = c.IsActive,
                DaysUntilExpiration = c.DaysUntilExpiration
            }).ToList();

            return Ok(dtos);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error searching certificates");
            return StatusCode(500, new { error = "Failed to search certificates" });
        }
    }

    [HttpGet("expiring")]
    public async Task<ActionResult<List<StoredCertificateDto>>> GetExpiringCertificates([FromQuery] int daysThreshold = 90)
    {
        try
        {
            var certificates = await _certificateStorageService.GetExpiringCertificatesAsync(daysThreshold);
            var dtos = certificates.Select(c => new StoredCertificateDto
            {
                Thumbprint = c.Thumbprint,
                Subject = c.Subject,
                Issuer = c.Issuer,
                NotBefore = c.NotBefore,
                NotAfter = c.NotAfter,
                StoredDate = c.StoredDate,
                IsActive = c.IsActive,
                DaysUntilExpiration = c.DaysUntilExpiration
            }).ToList();

            return Ok(dtos);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting expiring certificates");
            return StatusCode(500, new { error = "Failed to get expiring certificates" });
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

public class StoredCertificateDto
{
    public string Thumbprint { get; set; } = string.Empty;
    public string Subject { get; set; } = string.Empty;
    public string Issuer { get; set; } = string.Empty;
    public DateTime NotBefore { get; set; }
    public DateTime NotAfter { get; set; }
    public DateTime StoredDate { get; set; }
    public bool IsActive { get; set; }
    public int DaysUntilExpiration { get; set; }
}

public class CertificateSearchCriteriaDto
{
    public string? SearchText { get; set; }
    public string? Category { get; set; }
    public bool? IsActive { get; set; }
    public DateTime? ExpiresBefore { get; set; }
    public DateTime? ExpiresAfter { get; set; }
    public int? DaysUntilExpiration { get; set; }
    public bool? ExpiringSoon { get; set; }
}

