{{- if ne .Subject.CommonName .ServiceDNS }}
{{ fail "requested subject is not the fixed Strugglebus service identity" }}
{{- end }}
{
  "subject": {
    "commonName": {{ toJson .ServiceDNS }}
  },
  "sans": [
    {
      "type": "dns",
      "value": {{ toJson .ServiceDNS }}
    }
  ],
  "keyUsage": [
    "digitalSignature"
  ],
  "extKeyUsage": [
    "serverAuth"
  ]
}
