using System.Collections.Concurrent;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json.Serialization;

var builder = WebApplication.CreateBuilder(args);
// builder.Services.AddCors();
builder.Services.ConfigureHttpJsonOptions(options =>
{
    options.SerializerOptions.TypeInfoResolverChain.Insert(0, AppJsonSerializerContext.Default);
});

var app = builder.Build();

var privateKeys = new ConcurrentDictionary<string, AsymmetricAlgorithm>();

// app.UseCors(options => options.WithOrigins("http://localhost:8090").AllowAnyMethod());

app.MapGet("/", (HttpContext ctx) =>
{
    var ipv6 = ctx.Connection.LocalIpAddress!.AddressFamily is AddressFamily.InterNetworkV6;
    var addr = ipv6 ? $"[{ctx.Connection.LocalIpAddress}]" : $"{ctx.Connection.LocalIpAddress}";
    addr += $":{ctx.Connection.LocalPort}";
    var response = $$"""
                     <html>
                         <head>
                             <title>keyinfra</title>
                             <meta charset="utf-8" />
                             <meta name="viewport" content="width=device-width, initial-scale=1.0" />
                             <meta name="color-scheme" content="light dark" />
                         </head>
                         <body>
                             <p><strong>step 1:</strong>create ca.crt and ca.key</p>
                             <pre>
                     $ca  = "ca.crt"; $key = "ca.key"
                     if (Test-Path $ca) {
                         Write-Host "Certificate already generated at $ca. Delete or rename this file before generating a new certificate."
                         exit 1
                     }

                     if (Test-Path $key) {
                         Write-Host "Key already generated at $key. Delete or rename this file before generating a new certificate."
                         exit 1
                     }

                     # create key
                     openssl ecparam -name prime256v1 -genkey -noout -out $key

                     # create cert
                     $uuid = [guid]::NewGuid().ToString()
                     openssl req -x509 -new -nodes `
                       -subj "/CN=$uuid" `
                       -addext 'basicConstraints=critical,CA:TRUE' `
                       -addext 'keyUsage=critical,keyCertSign,cRLSign' `
                       -addext 'subjectKeyIdentifier=hash' `
                       -key $key `
                       -sha256 `
                       -days 3650 `
                       -out $ca
                             </pre>
                             <p><strong>step 2:</strong>run the following to trigger csr creation, sign it (no CN/SAN checks, copies no extensions, valid 1y) and return</p>
                             <pre>
                     $ca  = "ca.crt"; $key = "ca.key"; $csr = "leaf.csr"; $out = "leaf.crt"
                     curl.exe --fail -XPOST --output $csr http://{{addr}}/csr
                     openssl x509 -req -in $csr -CA $ca -CAkey $key -CAcreateserial -out $out -days 365 -sha256
                     $id = (openssl x509 -in $out -noout -subject -nameopt RFC2253) -replace '^subject=', '' -replace '^CN=', ''
                     $json = '["'
                     $json += Get-Content $out
                     $json += '","'
                     $json += Get-Content $ca
                     $json += '"]'
                     $json | Set-Content -Encoding ascii "$id.json"
                     curl.exe --fail --data "@$id.json" -H "content-type: application/json" "http://{{addr}}/crt/$id"
                             </pre>
                         </body>
                     </html>
                     """;
    return Results.Text(response, "text/html");
});

app.MapPost("/csr", () =>
{
    try
    {
        var uuid = Guid.NewGuid().ToString();
        var csp = new CspParameters();
        csp.KeyContainerName = uuid;
        csp.Flags |= CspProviderFlags.UseMachineKeyStore | CspProviderFlags.UseNonExportableKey;
        var ecdsaPrivate = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var subjectName = "CN=" + uuid;
        var certRequest = new CertificateRequest(
            subjectName,
            ecdsaPrivate,
            HashAlgorithmName.SHA256);

        certRequest.CertificateExtensions.Add(
            new X509KeyUsageExtension(
                X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment,
                true));

        certRequest.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension(
                new OidCollection
                {
                    new Oid("1.3.6.1.5.5.7.3.2"), // client authentication
                    new Oid("1.3.6.1.5.5.7.3.1") // server authentication
                },
                true));

        // stash private key
        privateKeys[uuid] = ecdsaPrivate;

        return Results.Text(certRequest.CreateSigningRequestPem(), "text/plain");
    }
    catch (Exception e)
    {
        return Results.Text(e.Message, "text/plain", statusCode: 500);
    }
});

app.MapPost("/crt/{uuid}", (string uuid, string[] chain) =>
{
    try
    {
        // using var ca = X509CertificateLoader.LoadCertificate(Encoding.ASCII.GetBytes(chain.Last()));
        // if (File.Exists("ca.crt"))
        // {
        //     var existing = X509Certificate2.CreateFromPemFile("ca.crt");
        //     if (!existing.Thumbprint.Equals(ca.Thumbprint))
        //     {
        //         return Results.Text("refusing to replace existing ca.crt", "text/plain", statusCode: 500);
        //     }
        // }
        // else
        // {
        //     using var w = new FileStream("ca.crt", FileMode.CreateNew);
        //     w.Write(Encoding.ASCII.GetBytes(ca.ExportCertificatePem()));
        // }

        var privateKey = (ECDsa)privateKeys[uuid];

        using var caCertificate = X509CertificateLoader
            .LoadCertificate(Encoding.ASCII.GetBytes(chain.Last()));

        using var leafCertificate = X509CertificateLoader
            .LoadCertificate(Encoding.ASCII.GetBytes(chain.First()))
            .CopyWithPrivateKey(privateKey); // will throw if private key does not match certificate

        if (!leafCertificate.Subject.Equals("CN=uuid"))
            return Results.Text($"Certificate subject {leafCertificate.Subject} does not match URL path", "text/plain",
                statusCode: 400);

        var x509Chain = new X509Chain();
        x509Chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        x509Chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
        foreach (var cert in chain)
        {
            var x509 = X509CertificateLoader.LoadCertificate(Encoding.ASCII.GetBytes(cert));
            x509Chain.ChainPolicy.ExtraStore.Add(x509);
        }

        x509Chain.Build(leafCertificate);
        if (x509Chain.ChainElements.All(a => a.Certificate.Thumbprint != caCertificate.Thumbprint))
            return Results.Text("Invalid chain", "text/plain", statusCode: 400);

        using var w1 = new StreamWriter($"{uuid}.key");
        w1.WriteLine(privateKey.ExportECPrivateKeyPem());

        using var w2 = new StreamWriter($"{uuid}.crt");
        foreach (var cert in chain)
        {
            var x509 = X509CertificateLoader.LoadCertificate(Encoding.ASCII.GetBytes(cert));
            w2.WriteLine(x509.ExportCertificatePem());
        }

        return Results.Text("ok", "text/plain");
    }
    catch (KeyNotFoundException)
    {
        return Results.Text("Refusing to handle request for unknown private key", "text/plain", statusCode: 400);
    }
    catch (Exception e)
    {
        return Results.Text(e.Message, "text/plain", statusCode: 500);
    }
});

app.Run();

[JsonSerializable(typeof(string[]))]
internal partial class AppJsonSerializerContext : JsonSerializerContext
{
}
