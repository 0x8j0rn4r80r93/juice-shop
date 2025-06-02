{{- /* This is a Trivy SARIF template that forces a "secret" tag. */ -}}
{
  "version": "2.1.0",
  "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "Trivy",
          "semanticVersion": "{{ .Version }}",
          "rules": [
            {{- range $idx, $v := .Results }}
            {{- if eq $idx 0 }},{{ end }}
            {
              "id": "TRIVY-SECRET-{{ $idx }}",
              "shortDescription": {
                "text": "{{ $v.Title }}"
              },
              "fullDescription": {
                "text": "{{ $v.Title }}: {{ $v.Details }}"
              },
              "helpUri": "{{ $v.PrimaryURL }}",
              "properties": {
                "tags": ["security", "secret"]
              }
            }
            {{- end }}
          ]
        }
      },
      "results": [
        {{- range $i, $v := .Results }}
        {{- if eq $i 0 }},{{ end }}
        {
          "ruleId": "TRIVY-SECRET-{{ $i }}",
          "level": "{{ if eq $v.Severity "HIGH" }}error{{ else if eq $v.Severity "CRITICAL" }}error{{ else }}warning{{ end }}",
          "message": {
            "text": "{{ $v.Title }}: {{ $v.Details }}"
          },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {
                  "uri": "{{ $v.PrimaryURL }}",
                  "uriBaseId": "%SRCROOT%"
                }
              }
            }
          ],
          "properties": {
            "severity": "{{ $v.Severity }}"
          }
        }
        {{- end }}
      ]
    }
  ]
}
