using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Xunit.Abstractions;

namespace TlsResumptionBugTest;

/// <summary>
/// Demonstrates a potential bug in .NET 10 where TLS 1.3 session resumption
/// causes client-side SslStream to report IsMutuallyAuthenticated=false and
/// LocalCertificate=null on resumed connections, even though the server
/// correctly reports mutual authentication.
/// 
/// This test passes on .NET 8 but fails on .NET 10.
/// </summary>
public sealed class Tls13SessionResumptionBugTest : IDisposable
{
    private readonly ITestOutputHelper _output;
    private readonly X509Certificate2 _caCert;
    private readonly X509Certificate2 _serverCert;
    private readonly X509Certificate2 _clientCert;
    
    public Tls13SessionResumptionBugTest(ITestOutputHelper output)
    {
        _output = output;
        
        // Generate self-signed certificates
        (_caCert, _serverCert, _clientCert) = GenerateCertificates();
    }

    /// <summary>
    /// Validates certificates against the CA - used for proper certificate validation
    /// instead of trusting all certificates blindly.
    /// </summary>
    private bool ValidateCertificate(object sender, X509Certificate? certificate, X509Chain? chain, SslPolicyErrors sslPolicyErrors)
    {
        if (certificate is not X509Certificate2 cert) return false;
        
        using var customChain = new X509Chain();
        customChain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        customChain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        customChain.ChainPolicy.CustomTrustStore.Add(_caCert);
        return customChain.Build(cert);
    }

    [Fact]
    public async Task ClientShouldReportMutualAuthOnResumedSessions()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var actualPort = ((IPEndPoint)listener.LocalEndpoint).Port;

        var serverContext = SslStreamCertificateContext.Create(_serverCert, new X509Certificate2Collection { _caCert }, offline: true);
        var clientContext = SslStreamCertificateContext.Create(_clientCert, null);

        var serverTask = Task.Run(async () =>
        {
            for (int i = 0; i < 3; i++)
            {
                using var client = await listener.AcceptTcpClientAsync();
                await using var sslStream = new SslStream(client.GetStream(), false);
                
                await sslStream.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
                {
                    ServerCertificateContext = serverContext,
                    ClientCertificateRequired = true,
                    EnabledSslProtocols = SslProtocols.Tls13,
                    AllowTlsResume = true,
                    RemoteCertificateValidationCallback = ValidateCertificate
                });

                _output.WriteLine($"Server connection {i}: MutuallyAuth={sslStream.IsMutuallyAuthenticated}, " +
                                  $"RemoteCert={sslStream.RemoteCertificate?.Subject ?? "null"}");
                
                // Simple echo
                var buffer = new byte[1];
                await sslStream.ReadExactlyAsync(buffer, 0, 1);
                await sslStream.WriteAsync(buffer);
            }
        });

        // Client connections - all should report mutual auth
        var clientResults = new List<(bool IsMutuallyAuthenticated, string? LocalCert)>();
        
        for (int i = 0; i < 3; i++)
        {
            using var tcpClient = new TcpClient();
            await tcpClient.ConnectAsync(IPAddress.Loopback, actualPort);
            
            await using var sslStream = new SslStream(tcpClient.GetStream(), false);

            await sslStream.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = "server.test",
                ClientCertificateContext = clientContext,
                EnabledSslProtocols = SslProtocols.Tls13,
                AllowTlsResume = true,
                RemoteCertificateValidationCallback = ValidateCertificate
            });

            var result = (IsMutuallyAuthenticated: sslStream.IsMutuallyAuthenticated, 
                          LocalCert: sslStream.LocalCertificate?.Subject);
            clientResults.Add(result);
            
            _output.WriteLine($"Client connection {i}: MutuallyAuth={result.IsMutuallyAuthenticated}, " +
                              $"LocalCert={result.LocalCert ?? "null"}, " +
                              $"Protocol={sslStream.SslProtocol}");

            // Simple ping-pong to complete the connection
            await sslStream.WriteAsync(new byte[] { 0x42 });
            var response = new byte[1];
            await sslStream.ReadExactlyAsync(response, 0, 1);
        }

        await serverTask;

        // All connections should report mutual authentication
        // BUG: In .NET 10 with AllowTlsResume=true, connections after the first
        // report IsMutuallyAuthenticated=false and LocalCertificate=null
        for (int i = 0; i < clientResults.Count; i++)
        {
            var (isMutual, localCert) = clientResults[i];
            Assert.True(isMutual, 
                $"Client connection {i} should report IsMutuallyAuthenticated=true. " +
                "This fails on .NET 10 with TLS 1.3 session resumption enabled.");
            Assert.NotNull(localCert);
        }
    }

    private static (X509Certificate2 ca, X509Certificate2 server, X509Certificate2 client) GenerateCertificates()
    {
        // Generate CA
        using var caKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var caReq = new CertificateRequest("CN=Test CA", caKey, HashAlgorithmName.SHA256);
        caReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        caReq.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        using var caCert = caReq.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddYears(1));

        // Generate server cert
        using var serverKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var serverReq = new CertificateRequest("CN=server.test", serverKey, HashAlgorithmName.SHA256);
        serverReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        serverReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        serverReq.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, false)); // serverAuth
        
        var sanBuilder = new SubjectAlternativeNameBuilder();
        sanBuilder.AddDnsName("server.test");
        sanBuilder.AddIpAddress(IPAddress.Loopback);
        serverReq.CertificateExtensions.Add(sanBuilder.Build());
        
        using var serverCertPub = serverReq.Create(caCert, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddYears(1),
            Guid.NewGuid().ToByteArray());
        using var serverCert = serverCertPub.CopyWithPrivateKey(serverKey);

        // Generate client cert
        using var clientKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var clientReq = new CertificateRequest("CN=client.test", clientKey, HashAlgorithmName.SHA256);
        clientReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        clientReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        clientReq.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            new OidCollection { new Oid("1.3.6.1.5.5.7.3.2") }, false)); // clientAuth
        
        using var clientCertPub = clientReq.Create(caCert, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddYears(1),
            Guid.NewGuid().ToByteArray());
        using var clientCert = clientCertPub.CopyWithPrivateKey(clientKey);

        // Export and reimport to get proper key storage
        var caBytes = caCert.Export(X509ContentType.Pfx, "");
        var serverBytes = serverCert.Export(X509ContentType.Pfx, "");
        var clientBytes = clientCert.Export(X509ContentType.Pfx, "");

#if NET10_0_OR_GREATER
        return (
            X509CertificateLoader.LoadPkcs12(caBytes, "", X509KeyStorageFlags.Exportable),
            X509CertificateLoader.LoadPkcs12(serverBytes, "", X509KeyStorageFlags.Exportable),
            X509CertificateLoader.LoadPkcs12(clientBytes, "", X509KeyStorageFlags.Exportable)
        );
#else
        return (
            new X509Certificate2(caBytes, "", X509KeyStorageFlags.Exportable),
            new X509Certificate2(serverBytes, "", X509KeyStorageFlags.Exportable),
            new X509Certificate2(clientBytes, "", X509KeyStorageFlags.Exportable)
        );
#endif
    }

    public void Dispose()
    {
        _caCert.Dispose();
        _serverCert.Dispose();
        _clientCert.Dispose();
    }
}
