# gosoap

This library provides primitives for operating on a SOAP-based web service. The library supports encrypting the SOAP request using the WS-Security x.509 protocol, enabling SOAP calls against secured web services.

The following sub-features are currently enabled by default when WS-Security is enabled with the SignWith(...) method:
- Include a [wsse](http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd):SecurityTokenReference with the signature public key in form of a [wsu](http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd):BinarySecurityToken
- Automatically add a [wsu](http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd):Timestamp with validity 10 seconds  
- Automatically generate a wsu:Id and use this #ID as URI to reference the respective signed element(s) 
- Sign Timestamp + Body elements of the SOAP message by default
- Other elements can be signed (in theory) with the (currently unexported) addSignature() method
- C14N canonicalization is ensured by marshaling the relevant to be signed sections with the [github.com/m29h/xml](https://github.com/m29h/xml) package
- SHA256 is used as default HMAC for signing purposes. More fine grained configuration on different signing profiles is planned for future release

Of course this library can also do basic SOAP (without WS-Security x.509)

## A basic example usage would be as follows:

```go
include (
    "context"
    "github.com/m29h/gosoap"
)

main() {
    certFile := "cert.pem"
    keyFile := "key.pem"

    wsseInfo, authErr := soap.NewWSSEAuthInfo(certFile, keyFile)
    if authErr != nil {
        fmt.Printf("Auth error: %s\n", authErr.Error())
        return
    }
    
    // setup Client and inject the HeaderBuilder for the wsse header which automatically
    // signs each message body and adds a signed Timestamp to limit message validity
    soapClient := soap.NewClient("https://soap.example.org/endpoint/service/", wsseInfo.Header())

    // Setup your request structure
    // ...
    //

    // Create the SOAP request
    // call.action is the SOAP action (i.e. method name)
    // call.requestData is the structure mapping to the SOAP request
    // call.responseData is an output structure mapping to the SOAP response

    // Make the request by invoking the SOAPdoer interface of the client
    // in a real-world example the SOAPdoer interface would get passed into a service type that would implement
    // the SOAP service methods

    err := soapClient.Do(context.Background(), call.action, call.requestData, call.responseData)

    if err != nil {
        fmt.Printf("Unable to validate: %s\n", err.Error())
        return
    } 
    
    // Now we can handle the response itself.
    // Do our custom processing
    // ...
    //
    
    fmt.Printf("Done!\n")
}
```

The code is very loosely based off the SOAP client https://github.com/textnow/gosoap.
