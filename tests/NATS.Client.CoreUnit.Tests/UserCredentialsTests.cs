using System.Text.Json;
using NATS.Client.Core.Internal;

namespace NATS.Client.Core.Tests;

public class UserCredentialsTests
{
    [Fact]
    public async Task Should_generate_signature_when_nonce_present_regardless_of_auth_required()
    {
        // Arrange - Test with AuthRequired = false but Nonce present
        var serverInfo = new ServerInfo
        {
            Id = "test-server",
            Name = "test",
            Version = "2.0.0",
            ProtocolVersion = 1,
            AuthRequired = false, // AuthRequired is false
            Nonce = "test-nonce-12345", // But nonce is present
        };

        var authOpts = new NatsAuthOpts
        {
            NKey = "UALQSMXRSAA7ZXIGDDJBJ2JOYJVQIWM3LQVDM5KYIPG4EP3FAGJ47BOJ",
            Seed = "SUAAVWRZG6M5FA5VRRGWSCIHKTOJC7EWNIT4JV3FTOIPO4OBFR5WA7X5TE",
        };

        var userCredentials = new UserCredentials(authOpts);
        var natsOpts = NatsOpts.Default with { AuthOpts = authOpts };
        var clientOpts = ClientOpts.Create(natsOpts);
        var uri = new NatsUri("nats://localhost:4222", true);

        // Act
        await userCredentials.AuthenticateAsync(clientOpts, serverInfo, uri, TimeSpan.FromSeconds(5), CancellationToken.None);

        // Assert - Signature should be generated even though AuthRequired is false
        Assert.NotNull(clientOpts.Sig);
        Assert.NotEmpty(clientOpts.Sig);
        Assert.Equal(authOpts.NKey, clientOpts.NKey);
    }

    [Fact]
    public async Task Should_generate_signature_when_auth_required_true_and_nonce_present()
    {
        // Arrange - Traditional case: AuthRequired = true and Nonce present
        var serverInfo = new ServerInfo
        {
            Id = "test-server",
            Name = "test",
            Version = "2.0.0",
            ProtocolVersion = 1,
            AuthRequired = true, // AuthRequired is true
            Nonce = "test-nonce-67890", // Nonce is present
        };

        var authOpts = new NatsAuthOpts
        {
            NKey = "UALQSMXRSAA7ZXIGDDJBJ2JOYJVQIWM3LQVDM5KYIPG4EP3FAGJ47BOJ",
            Seed = "SUAAVWRZG6M5FA5VRRGWSCIHKTOJC7EWNIT4JV3FTOIPO4OBFR5WA7X5TE",
        };

        var userCredentials = new UserCredentials(authOpts);
        var natsOpts = NatsOpts.Default with { AuthOpts = authOpts };
        var clientOpts = ClientOpts.Create(natsOpts);
        var uri = new NatsUri("nats://localhost:4222", true);

        // Act
        await userCredentials.AuthenticateAsync(clientOpts, serverInfo, uri, TimeSpan.FromSeconds(5), CancellationToken.None);

        // Assert
        Assert.NotNull(clientOpts.Sig);
        Assert.NotEmpty(clientOpts.Sig);
        Assert.Equal(authOpts.NKey, clientOpts.NKey);
    }

    [Fact]
    public async Task Should_not_generate_signature_when_nonce_is_null()
    {
        // Arrange - No nonce provided
        var serverInfo = new ServerInfo
        {
            Id = "test-server",
            Name = "test",
            Version = "2.0.0",
            ProtocolVersion = 1,
            AuthRequired = false,
            Nonce = null, // No nonce
        };

        var authOpts = new NatsAuthOpts
        {
            NKey = "UALQSMXRSAA7ZXIGDDJBJ2JOYJVQIWM3LQVDM5KYIPG4EP3FAGJ47BOJ",
            Seed = "SUAAVWRZG6M5FA5VRRGWSCIHKTOJC7EWNIT4JV3FTOIPO4OBFR5WA7X5TE",
        };

        var userCredentials = new UserCredentials(authOpts);
        var natsOpts = NatsOpts.Default with { AuthOpts = authOpts };
        var clientOpts = ClientOpts.Create(natsOpts);
        var uri = new NatsUri("nats://localhost:4222", true);

        // Act
        await userCredentials.AuthenticateAsync(clientOpts, serverInfo, uri, TimeSpan.FromSeconds(5), CancellationToken.None);

        // Assert - No signature should be generated
        Assert.Null(clientOpts.Sig);
        Assert.Equal(authOpts.NKey, clientOpts.NKey);
    }

    [Fact]
    public async Task Should_not_generate_signature_when_server_info_is_null()
    {
        // Arrange - No server info
        var authOpts = new NatsAuthOpts
        {
            NKey = "UALQSMXRSAA7ZXIGDDJBJ2JOYJVQIWM3LQVDM5KYIPG4EP3FAGJ47BOJ",
            Seed = "SUAAVWRZG6M5FA5VRRGWSCIHKTOJC7EWNIT4JV3FTOIPO4OBFR5WA7X5TE",
        };

        var userCredentials = new UserCredentials(authOpts);
        var natsOpts = NatsOpts.Default with { AuthOpts = authOpts };
        var clientOpts = ClientOpts.Create(natsOpts);
        var uri = new NatsUri("nats://localhost:4222", true);

        // Act
        await userCredentials.AuthenticateAsync(clientOpts, null, uri, TimeSpan.FromSeconds(5), CancellationToken.None);

        // Assert - No signature should be generated
        Assert.Null(clientOpts.Sig);
        Assert.Equal(authOpts.NKey, clientOpts.NKey);
    }

    [Fact]
    public async Task Should_generate_signature_with_jwt_auth()
    {
        // Arrange - JWT authentication with nonce
        var serverInfo = new ServerInfo
        {
            Id = "test-server",
            Name = "test",
            Version = "2.0.0",
            ProtocolVersion = 1,
            AuthRequired = false, // AuthRequired is false
            Nonce = "jwt-nonce-abc123", // But nonce is present
        };

        var authOpts = new NatsAuthOpts
        {
            Jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJlZDI1NTE5LW5rZXkifQ.eyJqdGkiOiJOVDJTRkVIN0pNSUpUTzZIQ09GNUpYRFNDUU1WRlFNV0MyWjI1TFk3QVNPTklYTjZFVlhBIiwiaWF0IjoxNjc5MTQ0MDkwLCJpc3MiOiJBREpOSlpZNUNXQlI0M0NOSzJBMjJBMkxPSkVBSzJSS1RaTk9aVE1HUEVCRk9QVE5FVFBZTUlLNSIsIm5hbWUiOiJteS11c2VyIiwic3ViIjoiVUJPWjVMUVJPTEpRRFBBQUNYSk1VRkJaS0Q0R0JaSERUTFo3TjVQS1dSWFc1S1dKM0VBMlc0UloiLCJuYXRzIjp7InB1YiI6e30sInN1YiI6e30sInN1YnMiOi0xLCJkYXRhIjotMSwicGF5bG9hZCI6LTEsInR5cGUiOiJ1c2VyIiwidmVyc2lvbiI6Mn19.ElYEknDixe9pZdl55S9PjduQhhqR1OQLglI1JO7YK7ECYb1mLUjGd8ntcR7ISS04-_yhygSDzX8OS8buBIxMDA",
            Seed = "SUAJR32IC6D45J3URHJ5AOQZWBBO6QTID27NZQKXE3GC5U3SPFEYDJK6RQ",
        };

        var userCredentials = new UserCredentials(authOpts);
        var natsOpts = NatsOpts.Default with { AuthOpts = authOpts };
        var clientOpts = ClientOpts.Create(natsOpts);
        var uri = new NatsUri("nats://localhost:4222", true);

        // Act
        await userCredentials.AuthenticateAsync(clientOpts, serverInfo, uri, TimeSpan.FromSeconds(5), CancellationToken.None);

        // Assert - Signature should be generated for JWT auth
        Assert.NotNull(clientOpts.Sig);
        Assert.NotEmpty(clientOpts.Sig);
        Assert.Equal(authOpts.Jwt, clientOpts.JWT);
    }

    [Fact]
    public async Task Should_generate_signature_with_auth_callback_nkey()
    {
        // Arrange - Auth callback with NKey
        var serverInfo = new ServerInfo
        {
            Id = "test-server",
            Name = "test",
            Version = "2.0.0",
            ProtocolVersion = 1,
            AuthRequired = false, // AuthRequired is false
            Nonce = "callback-nonce-xyz789", // But nonce is present
        };

        var authOpts = new NatsAuthOpts
        {
            AuthCredCallback = async (_, _) =>
                await Task.FromResult(NatsAuthCred.FromNkey("SUAAVWRZG6M5FA5VRRGWSCIHKTOJC7EWNIT4JV3FTOIPO4OBFR5WA7X5TE")),
        };

        var userCredentials = new UserCredentials(authOpts);
        var natsOpts = NatsOpts.Default with { AuthOpts = authOpts };
        var clientOpts = ClientOpts.Create(natsOpts);
        var uri = new NatsUri("nats://localhost:4222", true);

        // Act
        await userCredentials.AuthenticateAsync(clientOpts, serverInfo, uri, TimeSpan.FromSeconds(5), CancellationToken.None);

        // Assert - Signature should be generated from callback
        Assert.NotNull(clientOpts.Sig);
        Assert.NotEmpty(clientOpts.Sig);
        Assert.NotNull(clientOpts.NKey);
        Assert.Equal("UALQSMXRSAA7ZXIGDDJBJ2JOYJVQIWM3LQVDM5KYIPG4EP3FAGJ47BOJ", clientOpts.NKey);
    }

    [Fact]
    public void Sign_should_return_valid_signature()
    {
        // Arrange
        const string seed = "SUAAVWRZG6M5FA5VRRGWSCIHKTOJC7EWNIT4JV3FTOIPO4OBFR5WA7X5TE";
        const string nonce = "test-nonce";

        var authOpts = new NatsAuthOpts { Seed = seed };
        var userCredentials = new UserCredentials(authOpts);

        // Act
        var signature = userCredentials.Sign(nonce);

        // Assert
        Assert.NotNull(signature);
        Assert.NotEmpty(signature);
    }

    [Fact]
    public void Sign_should_return_null_when_seed_is_null()
    {
        // Arrange
        var authOpts = new NatsAuthOpts(); // No seed
        var userCredentials = new UserCredentials(authOpts);

        // Act
        var signature = userCredentials.Sign("test-nonce");

        // Assert
        Assert.Null(signature);
    }

    [Fact]
    public void Sign_should_return_null_when_nonce_is_null()
    {
        // Arrange
        const string seed = "SUAAVWRZG6M5FA5VRRGWSCIHKTOJC7EWNIT4JV3FTOIPO4OBFR5WA7X5TE";
        var authOpts = new NatsAuthOpts { Seed = seed };
        var userCredentials = new UserCredentials(authOpts);

        // Act
        var signature = userCredentials.Sign(null);

        // Assert
        Assert.Null(signature);
    }
}
