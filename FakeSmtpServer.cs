using System.Diagnostics;
using Microsoft.AspNetCore.Authentication.Negotiate;
using System.Net;
using System.Net.Security;
using System.Buffers.Binary;

internal class FakeSmtpServer
{
    enum State
    {
        Unauthenticated,
        InAuthentication,
        Authenticated,
        Data,
    }

    enum GssAuthenticationState
    {
        InitialExchange,
        ConfidentialityExchange,
    }

    private State _currentState = State.Unauthenticated;
    private GssAuthenticationState _currentAuthenticationState = GssAuthenticationState.InitialExchange;
    private NTAuthentication? _negotiateState;
    private byte[]? _saslToken;
    //private static INegotiateStateFactory _negotiateStateFactory = new ReflectedNegotiateStateFactory();

    private static bool IsCredentialError(SecurityStatusPalErrorCode error)
    {
        return error == SecurityStatusPalErrorCode.LogonDenied ||
            error == SecurityStatusPalErrorCode.UnknownCredentials ||
            error == SecurityStatusPalErrorCode.NoImpersonation ||
            error == SecurityStatusPalErrorCode.NoAuthenticatingAuthority ||
            error == SecurityStatusPalErrorCode.UntrustedRoot ||
            error == SecurityStatusPalErrorCode.CertExpired ||
            error == SecurityStatusPalErrorCode.SmartcardLogonRequired ||
            error == SecurityStatusPalErrorCode.BadBinding;
    }

    private void ProcessAuthenticationLine(ReadOnlySpan<char> buffer, TextWriter writer)
    {
        try
        {
            Debug.Assert(_negotiateState != null);

            if (_currentAuthenticationState == GssAuthenticationState.InitialExchange)
            {
                byte[]? blob = _negotiateState.GetOutgoingBlob(Convert.FromBase64String(buffer.ToString()), false, out var status);
                if (IsCredentialError(status.ErrorCode))
                {
                    writer.WriteLine("535 5.7.8 Authentication credentials invalid");
                    _currentState = State.Unauthenticated;
                }
                else if (status.ErrorCode != SecurityStatusPalErrorCode.OK &&
                    status.ErrorCode != SecurityStatusPalErrorCode.ContinueNeeded &&
                    status.ErrorCode != SecurityStatusPalErrorCode.CompleteNeeded)
                {
                    writer.WriteLine($"454 4.7.0 Temporary authentication failure ({status})");
                    _currentState = State.Unauthenticated;
                }
                else if (blob != null)
                {
                    writer.WriteLine("334 " + Convert.ToBase64String(blob));
                }
                else
                {
                    if (_negotiateState.IsCompleted)
                    {
                        // TODO: Restrict users

                        _currentAuthenticationState = GssAuthenticationState.ConfidentialityExchange;

                        // TODO: Return real flags
                        _saslToken = new byte[] { /*0x06, 0xff, 0xff, 0xff*/ 1, 0, 0, 0 };

                        byte[]? encryptedSaslToken = null;
                        var context = _negotiateState.GetContext(out status);
                        NegotiateStreamPal.Encrypt(context, _saslToken, _negotiateState.IsNTLM, _negotiateState.IsNTLM, ref encryptedSaslToken, 0);
                        // Encrypt result is length prefixed, drop that
                        writer.WriteLine("334 " + Convert.ToBase64String(encryptedSaslToken, 4, encryptedSaslToken.Length - 4));
                    }
                    else
                    {
                        writer.WriteLine($"454 4.7.0 Temporary authentication failure (Incomplete)");
                        _currentState = State.Unauthenticated;
                    }
                }
            }
            else if (_currentAuthenticationState == GssAuthenticationState.ConfidentialityExchange)
            {
                byte[] encryptedSaslToken = Convert.FromBase64String(buffer.ToString());

                // Add length-prefix to make Decrypt happy
                byte[] encryptedSaslToken2 = new byte[encryptedSaslToken.Length + 4];
                encryptedSaslToken.AsSpan().CopyTo(encryptedSaslToken2.AsSpan(4));
                BinaryPrimitives.WriteInt32LittleEndian(encryptedSaslToken2, encryptedSaslToken.Length);

                var context = _negotiateState.GetContext(out var status);
                NegotiateStreamPal.Decrypt(context, encryptedSaslToken, 0, encryptedSaslToken.Length, _negotiateState.IsNTLM, _negotiateState.IsNTLM, out var newOffset, 0);
                //_negotiateState.VerifySignature(encryptedSaslToken, 0, encryptedSaslToken.Length);
                // TODO: Verify content

                writer.WriteLine("235 2.7.0 Authentication successful");
                _currentState = State.Authenticated;
            }
        }
        catch (Exception e)
        {
            Console.WriteLine(e);
            _currentState = State.Unauthenticated;
            writer.WriteLine("454 4.7.0 Temporary authentication failure");
        }
    }


    public void SayHello(TextWriter writer)
    {
        writer.WriteLine("220 Ready");
    }

    public void ProcessLine(ReadOnlySpan<char> buffer, TextWriter writer)
    {
        buffer = buffer.TrimEnd(" \r\n");

        Console.WriteLine(buffer.Length + " " + buffer.ToString());

        if (_currentState == State.Unauthenticated)
        {
            if (buffer.StartsWith("EHLO", StringComparison.OrdinalIgnoreCase))
            {
                writer.WriteLine("250-Greetings");
                writer.WriteLine("250 AUTH GSSAPI");
            }
            else if (buffer.StartsWith("AUTH GSSAPI ", StringComparison.OrdinalIgnoreCase))
            {
                try
                {
                    _currentState = State.InAuthentication;
                    _currentAuthenticationState = GssAuthenticationState.InitialExchange;
                    _negotiateState = new NTAuthentication(true, "Negotiate", CredentialCache.DefaultNetworkCredentials, null, 0, null);// _negotiateStateFactory.CreateInstance();
                    ProcessAuthenticationLine(buffer.Slice(12), writer);
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
                    _currentState = State.Unauthenticated;
                    writer.WriteLine("454 4.7.0 Temporary authentication failure (failure to get authenticator)");
                }
            }
            else if (buffer.StartsWith("QUIT", StringComparison.OrdinalIgnoreCase))
            {
                writer.WriteLine("221 Bye");
            }
            else
            {
                writer.WriteLine("530 5.7.0 Authentication required");
            }
        }
        else if (_currentState == State.InAuthentication)
        {
            ProcessAuthenticationLine(buffer, writer);
        }
        else if (_currentState == State.Authenticated)
        {
            if (buffer.StartsWith("MAIL FROM:", StringComparison.OrdinalIgnoreCase) ||
                buffer.StartsWith("RCPT TO:", StringComparison.OrdinalIgnoreCase))
            {
                writer.WriteLine("250 OK");
            }
            else if (buffer.StartsWith("QUIT", StringComparison.OrdinalIgnoreCase))
            {
                writer.WriteLine("221 Bye");
                // Close connection
            }
            else if (buffer.StartsWith("DATA", StringComparison.OrdinalIgnoreCase))
            {
                _currentState = State.Data;
                writer.WriteLine("354 Start mail input; end with <CRLF>.<CRLF>");
            }
            else
            {
                writer.WriteLine("502 Command not implemented");
            }
        }
        else if (_currentState == State.Data)
        {
            if (buffer.Equals(".".AsSpan(), StringComparison.OrdinalIgnoreCase))
            {
                _currentState = State.Authenticated;
                writer.WriteLine("250 OK");
                Console.WriteLine("250 OK");
            }
        }
    }
}