using Microsoft.AspNetCore.Mvc;
using CACApp.Services;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;

namespace CACApp.Controllers;

[ApiController]
[Route("api/[controller]")]
public class CrlOcspMonitoringController : ControllerBase
{
    private readonly ICrlOcspMonitoringService _monitoringService;
    private readonly ILogger<CrlOcspMonitoringController> _logger;

    public CrlOcspMonitoringController(ICrlOcspMonitoringService monitoringService, ILogger<CrlOcspMonitoringController> logger)
    {
        _monitoringService = monitoringService;
        _logger = logger;
    }

    [HttpPost("check-certificate")]
    public async Task<ActionResult<CrlOcspStatusDto>> CheckCertificateRevocationStatus([FromBody] CertificateRequest request)
    {
        try
        {
            var certificate = ConvertFromBase64(request.CertificateBase64);
            if (certificate == null)
            {
                return BadRequest(new { error = "Invalid certificate data" });
            }

            var status = await _monitoringService.CheckCertificateRevocationStatusAsync(certificate);
            
            var dto = new CrlOcspStatusDto
            {
                IsAvailable = status.IsAvailable,
                CheckTime = status.CheckTime,
                ErrorMessage = status.ErrorMessage,
                CrlStatuses = status.CrlStatuses.Select(s => new CrlStatusDto
                {
                    Url = s.Url,
                    IsAccessible = s.IsAccessible,
                    ResponseTimeMs = s.ResponseTime?.TotalMilliseconds,
                    LastUpdate = s.LastUpdate,
                    NextUpdate = s.NextUpdate,
                    RevokedCertificateCount = s.RevokedCertificateCount,
                    ErrorMessage = s.ErrorMessage,
                    CheckTime = s.CheckTime
                }).ToList(),
                OcspStatuses = status.OcspStatuses.Select(s => new OcspStatusDto
                {
                    Url = s.Url,
                    IsAccessible = s.IsAccessible,
                    ResponseTimeMs = s.ResponseTime?.TotalMilliseconds,
                    ResponseStatus = s.ResponseStatus,
                    IsRevoked = s.IsRevoked,
                    ThisUpdate = s.ThisUpdate,
                    NextUpdate = s.NextUpdate,
                    ErrorMessage = s.ErrorMessage,
                    CheckTime = s.CheckTime
                }).ToList()
            };

            return Ok(dto);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error checking certificate revocation status");
            return StatusCode(500, new { error = "Failed to check revocation status" });
        }
    }

    [HttpPost("check-crl")]
    public async Task<ActionResult<CrlStatusDto>> CheckCrlStatus([FromBody] CrlCheckRequest request)
    {
        try
        {
            var status = await _monitoringService.CheckCrlStatusAsync(request.Url);
            
            var dto = new CrlStatusDto
            {
                Url = status.Url,
                IsAccessible = status.IsAccessible,
                ResponseTimeMs = status.ResponseTime?.TotalMilliseconds,
                LastUpdate = status.LastUpdate,
                NextUpdate = status.NextUpdate,
                RevokedCertificateCount = status.RevokedCertificateCount,
                ErrorMessage = status.ErrorMessage,
                CheckTime = status.CheckTime
            };

            return Ok(dto);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error checking CRL status");
            return StatusCode(500, new { error = "Failed to check CRL status" });
        }
    }

    [HttpPost("check-ocsp")]
    public async Task<ActionResult<OcspStatusDto>> CheckOcspStatus([FromBody] OcspCheckRequest request)
    {
        try
        {
            var certificate = ConvertFromBase64(request.CertificateBase64);
            if (certificate == null)
            {
                return BadRequest(new { error = "Invalid certificate data" });
            }

            var status = await _monitoringService.CheckOcspStatusAsync(request.Url, certificate);
            
            var dto = new OcspStatusDto
            {
                Url = status.Url,
                IsAccessible = status.IsAccessible,
                ResponseTimeMs = status.ResponseTime?.TotalMilliseconds,
                ResponseStatus = status.ResponseStatus,
                IsRevoked = status.IsRevoked,
                ThisUpdate = status.ThisUpdate,
                NextUpdate = status.NextUpdate,
                ErrorMessage = status.ErrorMessage,
                CheckTime = status.CheckTime
            };

            return Ok(dto);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error checking OCSP status");
            return StatusCode(500, new { error = "Failed to check OCSP status" });
        }
    }

    [HttpPost("distribution-points")]
    public async Task<ActionResult<List<RevocationDistributionPointDto>>> GetRevocationDistributionPoints([FromBody] CertificateRequest request)
    {
        try
        {
            var certificate = ConvertFromBase64(request.CertificateBase64);
            if (certificate == null)
            {
                return BadRequest(new { error = "Invalid certificate data" });
            }

            var distributionPoints = await _monitoringService.GetRevocationDistributionPointsAsync(certificate);
            
            var dto = distributionPoints.Select(dp => new RevocationDistributionPointDto
            {
                Type = dp.Type,
                Url = dp.Url,
                Description = dp.Description
            }).ToList();

            return Ok(dto);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting revocation distribution points");
            return StatusCode(500, new { error = "Failed to get revocation distribution points" });
        }
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

public class CrlCheckRequest
{
    public string Url { get; set; } = string.Empty;
}

public class OcspCheckRequest
{
    public string Url { get; set; } = string.Empty;
    public string CertificateBase64 { get; set; } = string.Empty;
}

public class CrlOcspStatusDto
{
    public bool IsAvailable { get; set; }
    public List<CrlStatusDto> CrlStatuses { get; set; } = new();
    public List<OcspStatusDto> OcspStatuses { get; set; } = new();
    public DateTime CheckTime { get; set; }
    public string? ErrorMessage { get; set; }
}

public class CrlStatusDto
{
    public string Url { get; set; } = string.Empty;
    public bool IsAccessible { get; set; }
    public double? ResponseTimeMs { get; set; }
    public DateTime? LastUpdate { get; set; }
    public DateTime? NextUpdate { get; set; }
    public int? RevokedCertificateCount { get; set; }
    public string? ErrorMessage { get; set; }
    public DateTime CheckTime { get; set; }
}

public class OcspStatusDto
{
    public string Url { get; set; } = string.Empty;
    public bool IsAccessible { get; set; }
    public double? ResponseTimeMs { get; set; }
    public string? ResponseStatus { get; set; }
    public bool? IsRevoked { get; set; }
    public DateTime? ThisUpdate { get; set; }
    public DateTime? NextUpdate { get; set; }
    public string? ErrorMessage { get; set; }
    public DateTime CheckTime { get; set; }
}

public class RevocationDistributionPointDto
{
    public string Type { get; set; } = string.Empty;
    public string Url { get; set; } = string.Empty;
    public string? Description { get; set; }
}

