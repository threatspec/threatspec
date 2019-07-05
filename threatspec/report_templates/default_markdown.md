# {{ report.project.name }} Threat Model

{{ report.project.description }}

{% if image %}
# Diagram
![Threat Model Diagram]({{ image }})
{% endif %}

# Threats

| Type | Component | Threat | Description | Test Count | File | Source |
| ---- | --------- | ------ | ----------- | ---------- | ---- | ------ |
{% for exposure in report.threatmodel.exposures %}| Exposure | {{ exposure.component.name }} | {{ exposure.threat.name }} | {{ exposure.details }} | | {{ exposure.source.filename }}:{{ exposure.source.line }} | {{ exposure.source.code }} |
{% endfor %}{% for acceptance in report.threatmodel.acceptances %}| Acceptance | {{ acceptance.component.name }} | {{ acceptance.threat.name }} | {{ acceptance.details }} | | {{ acceptance.source.filename }}:{{ acceptance.source.line }} | {{ acceptance.source.code }} |
{% endfor %}{% for transfer in report.threatmodel.transfers %}| Transfer | {{ transfer.destination_component.name }} (from {{ transfer.source_component.name }}) | {{ transfer.threat.name }} | {{ transfer.details }} | | {{ transfer.source.filename }}:{{ transfer.source.line }} | {{ transfer.source.code }} |
{% endfor %}{% for mitigation in report.threatmodel.mitigations %}| Mitigation | {{ mitigation.component.name }} | {{ mitigation.threat.name }} | {{ mitigation.control.name }} | {{ mitigation.tests|count }} | {{ mitigation.source.filename }}:{{ mitigation.source.line }} | {{ mitigation.source.code }} |
{% endfor %}

# Tests

| Component | Control | Test | File |
| --------- | ------- | ---- | ---- |
{% for test in report.threatmodel.tests %}| {{ test.component.name }} | {{ test.control.name }} | {{ test.source.code }} | {{ test.source.filename }}:{{ test.source.line }} |
{% endfor %}

# Reviews

| Component | Details | Filename | Line | Code |
| --------- | ------- | -------- | ---- | ---- |
{% for review in report.threatmodel.reviews %}| {{ review.component.name }} | {{ review.details  }} | {{ review.source.filename }} | {{ review.source.line  }} | {{ review.source.code }} |
{% endfor %}

# Connections

| Source Component | Destination Component | Description | File | Source |
| ---------------- | --------------------- | ----------- | ---- | ------ |
{% for connection in report.threatmodel.connections %}| {{ connection.source_component.name }} | {{ connection.destination_component.name }} | {{ connection.details }} | {{ connection.source.filename }}:{{ connection.source.line }} | {{ connection.source.code }} |
{% endfor %}