ntlmclient
==========
ntlmclient is a pure C library that supports NTLM2 authentication for
POSIX systems.  It is generally used to support authentication to
Windows-based servers that do not enable other authentication
algorithms.

🚨🚨🚨 NTLM2 support should be deprecated 🚨🚨🚨

This library is provided for compatibility with systems that do not offer
any other authentication algorithms.  NTLM2 is often enabled because it
provides simple, integrated access to Windows systems, often called "single
sign-on".  This allows authentication to remote systems with the currently
logged-in user credentials, without users being forced to re-enter their
password.  While convenient, NTLM2 is built on outdated cryptographic
systems and should not be preferred.

For "single sign-on" support, you should instead prefer
[Kerberos](https://en.wikipedia.org/wiki/Kerberos_(protocol)), as it
is an industry standard built on modern ciphers.  If you do not require
single sign-on, using a simple authentication mechanism like HTTP Basic
is adequate, provided the connection is encrypted with transport layer
security.

This library is provided since many systems are configured to support
authentication using _only_ NTLM2.  Not all systems can upgrade to
Kerberos.

**Regardless, you should be providing security at the transport layer,
using IPsec or HTTPS.**

Background
----------
NTLM is a "challenge/response" authentication mechanism that allows a
server to authenticate a client without it having to provide the actual
password.  Briefly:

1. The client creates an initial NTLM authentication negotiation message,
   called a "negotiation" message (sometimes called a "Type 1" message).

   The ntlmclient library returns the negotiation message as a raw stream
   of bytes.  If you require the message in base64 format (for example,
   to use with [SPNEGO](https://en.wikipedia.org/wiki/SPNEGO) over HTTPS),
   then you must encode it before sending it over the HTTPS connection.

2. The remote server will respond with a "challenge" message (sometimes
   called a "Type 2" message).  This message includes capabilities and
   information from the remote server that ntlmclient will use to
   complete authentication.

   The ntlmclient library expects the challenge message as a raw stream
   of bytes.  If it was provided to you in base64 format (for example,
   over HTTP) then you must decode it before providing it to the library.

3. The client creates the final message, a "response" message (sometimes
   called a "Type 3" message).  This message includes a hash of the
   challenge that was given to the client, using the password as a key.
   Given this message, the server will decide whether authentication
   succeeded or failed.

   Like the other messages, the response message is a raw stream of bytes
   and should be encoded as base64, if necessary.

Getting Started
---------------
You should read the [full
documentation](https://ethomson.github.io/ntlmclient/#HEAD), but a simple
usage example is:

1. Initialize the NTLM client context.  You can specify option flags, or
   pass `NTLM_CLIENT_DEFAULTS` (or `0`) to the option flags argument to
   accept the defaults.


   ```
   ntlm_client *ntlm;

   /* Create an NTLM client context, using the default options.  This
    * will return an NTLM context on success, or NULL on failure.
    */
   if ((ntlm = ntlm_client_init(NTLM_CLIENT_DEFAULTS)) == NULL) {
       /* Can only fail on out of memory. */
       fprintf(stderr, "out of memory");
       exit(1);
   }
   ```

2. Set the local hostname, the user's credentials to authenticate with,
   and the authentication "target" (the name of the remote machine).
   The strings provided are expected to be in UTF-8.

   (Functions return `0` on success and non-zero on error.)

   ```
   if (ntlm_client_set_hostname(ntlm, "hostname", "DOMAIN") != 0 ||
       ntlm_client_set_credentials(ntlm, "user", "DOMAIN", "secret") != 0) {
       ntlm_client_set_target(ntlm, "SERVER") != 0) {
       /* Get the error message from the NTLM context. */
       fprintf(stderr, "%s\n", ntlm_client_get_errmsg());
       exit(1);
   }
   ```

3. Compute the negotiate message and deliver it to the server.

   ```
   const unsigned char *negotiate_msg;
   size_t negotiate_len;

   if (ntlm_client_negotiate(&negotiate_msg, &negotiate_len, ntlm) != 0) {
       fprintf(stderr, "%s\n", ntlm_client_get_errmsg());
       exit(1);
   }

   /* For HTTP, base64 encode the negotiate message. */
   ```

4. Read the challenge message from the server, provide it to the library.

   ```
   /*
    * Read the NTLM challenge message from the remote host.  For HTTP,
    * this will be in the `Authorization` header, following the SPNEGO
    * mechanism name ("NTLM" or "Negotiate"), and should be base64 decoded.
    */

   if (ntlm_client_parse_challenge(ntlm, challenge, challenge_len) != 0) {
       fprintf(stderr, "%s\n", ntlm_client_get_errmsg());
       exit(1);
   }
   ```

5. Compute the response message and deliver it to the server.

   ```
   const unsigned char *response;
   size_t response_len;

   if (ntlm_client_response(&response, &response_len, ntlm) != 0) {
       fprintf(stderr, "%s\n", ntlm_client_get_errmsg());
       exit(1);
   }

   /*
    * For HTTP, base64 encode the response message and set it as the
    * `WWW-Authenticate` header.
    */
   ```

6. Determine if authentication has succeeded; for example, for HTTP
   transports, the server will return a `401` when authentication fails.
   In a failure, you should restart the authentication process, either
   with a new authentication context, or after calling:

   ```
   ntlm_client_reset(ntlm);
   ```

7. Free the NTLM context.

   ```
   ntlm_client_free(ntlm);
   ```

Support
-------
ntlmclient supports:

* NTLM2 authentication
  This is the most recent "single sign-on" authentication mechanism
  that Microsoft developed before adopting Kerberos.  This system provides
  authentication without actually transmitting the password.  However, it
  relies on outdated encryption algorithms, so this mechanism should not
  be used without transport encryption (IPsec, TLS, etc).

* LM and NTLM authentication (optionally)
  These are older "single sign-on" authentication mechanisms and rely
  on weaker encryption algorithms.  Most Windows systems (client and
  server) have disabled both LM and NTLM in favor of NTLM2.  Generally,
  these should not be used.  And even more than NTLM2, these should
  **never** be used without transport encryption.

* macOS and Linux Support
  Cryptographic primitives are provided by
  [CommonCrypto](https://developer.apple.com/security/) on macOS, and
  [OpenSSL](https://www.openssl.org) on non-macOS platforms.

  Unicode functionality (UTF8 to UTF16 conversion) is provided by
  [iconv](https://en.wikipedia.org/wiki/Iconv) when available, falling
  back to conversion routines provided by Unicode, Inc.

What's Not Supported
--------------------
ntlmclient does _not_ support:

* Session Security
  NTLM "session security", or "signing and sealing" is a message signature
  and encryption scheme.  Key exchange is performed during the NTLM
  authentication process.  There is no support for this; it should be
  not be used, and should be deprecated in favor of TLS.

* Windows Support
  ntlmclient is POSIX-only.  Windows users are encouraged to use the
  [system's NTLM support](https://msdn.microsoft.com/en-us/library/windows/desktop/aa375506(v=vs.85).aspx).

Further Reading
---------------
[MS-NLMP: NT LAN Manager (NTLM) Authentication Protocol
Specification](https://msdn.microsoft.com/en-us/library/cc207842.aspx)
Microsoft's published specification of the NTLM authentication
protocol.

[The NTLM Authentication Protocol and Security Support
Provider](http://davenport.sourceforge.net/ntlm.html)
An independent reference of the NTLM authentication system, based on the
research from the Samba team and used as the basis for jCIFS.

[Simple and Protected GSSAPI Negotiation Mechanism
(SPNEGO)](https://en.wikipedia.org/wiki/SPNEGO)
The HTTP authentication mechanism for NTLM and Kerberos.

License
---------
ntlmclient is released under the MIT license.  This software is based on
the NTLM2 implementation in [Microsoft Team Explorer
Everywhere](https://github.com/microsoft/team-explorer-everywhere).

See the [license file](LICENSE.txt) for the full license text.
