# TLS-Attacker Connector

This is a forked version of the fork https://github.com/tlsprint/TLSAttackerConnector of the original, built this time for TLS-Attacker 3.5 to develop StateInspector.

This tool provides a connection between TLS-Attacker and StateLearner / StateInspector.

## Setup
Init + update submodules to pull custom TLS-Attacker, then follow those install instructions first.

To build the connector:
```
$ mvn clean install
```

## Example

Start OpenSSL https server

```
$ openssl s_server -key server.key -cert server.pem -CAfile CA.pem -accept 4500 -www
```

Start TLS-Attacker Connector

```
java -jar ./target/TLSAttackerConnector2.0.jar --messageDir ./messages/messages.txt --timeout 500 -l 6666 -tP 4500
```

The connector will now listen on port 6666 for symbols and communicate to the TLS server on port 4500.

## Testing

The --test argument can be added to force a particular flow of messages for debugging, this flow is specified in the main function

## Files + things

Everything is basically in one messy java file: `src/main/java/nl/cypherpunk/tlsattackerconnector/TLSAttackerConnector.java`

This sets up some default configs, loads messages to send, starts listening and when instructed talks to the TLS server.

## TODO:

 - remove hard coded paths
 - refactor to make a little more sane