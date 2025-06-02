{{/* 
   Trivy “secret” results -> SARIF. 
   We tag everything with “secret” so GitHub knows these are Secret-Scanning alerts.
   We use `$v.Target` (the file path in your repo) for the artifact location.
*/ -}}
{
  "version": "2.1.0",
  "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "Trivy Secret Scanner",
          "semanticVersion": "{{ .Version }}",
          "rules": [
            {{- range $idx, $v := .Results -}}
            {{- if $idx }},{{ end }}
            {
              "id": "TRIVY-SECRET-{{ $idx }}",
              "shortDescription": {
                "text": "{{ $v.Title }}"
              },
              "fullDescription": {
                "text": "{{ $v.Title }}: {{ $v.Match }}"
              },
              "helpUri": "{{ $v.PrimaryURL }}",
              "properties": {
                "tags": ["security","secret"]
              }
            }
            {{- end }}
          ]
        }
      },
      "results": [
        {{- range $i, $v := .Results -}}
        {{- if $i }},{{ end }}
        {
          "ruleId": "TRIVY-SECRET-{{ $i }}",
          "level": "{{ if eq $v.Severity "HIGH" }}error{{ else }}warning{{ end }}",
          "message": {
            "text": "{{ $v.Title }}: {{ $v.Match }}"
          },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {
                  "uri": "{{ $v.Target }}",
                  "uriBaseId": "%SRCROOT%"
                },
                "region": {
                  "startLine": {{ $v.StartLine }},
                  "startColumn": {{ $v.StartColumn }},
                  "endLine": {{ $v.EndLine }},
                  "endColumn": {{ $v.EndColumn }}
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
