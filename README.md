# SecureVaults-AuthIOT
In the context of IoT device security, mutual authentication
between devices and servers represents one of the most criti-
cal challenges. Traditional authentication mechanisms based
on a single password are vulnerable to attacks such as side-
channel and dictionary attacks, making it necessary to adopt
more robust and secure approaches. The paper ”Authenti-
cation of IoT Device and IoT Server Using Secure Vaults”
proposes an authentication protocol based on a multi-key
mechanism, in which the shared secret between the server
and the IoT device is represented by a ”secure vault,” a col-
lection of keys of equal size. This protocol ensures that, even
if one key is compromised, the remaining keys remain secure,
and the system is protected from side-channel and dictionary
attacks.
In this project, we propose to implement a proof of con-
cept of the protocol described in the paper, with the aim
of verifying its feasibility and effectiveness in a real context.
In particular, we will implement the mutual authentication
mechanism based on the secure vault, simulating the inter-
action between an IoT device and a server.
The implementation will include the generation and man-
agement of the secure vault, the challenge-response mech-
anism for mutual authentication, and the dynamic modifi-
cation of the secure vault after each communication session.
Furthermore, we will analyze the performance of the protocol
in terms of security, having it checked with Tamarin-Prover.
Through this proof of concept, we intend to validate the
effectiveness of the protocol proposed in the paper, providing
a practical basis for further research and development
