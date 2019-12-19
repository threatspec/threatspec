# {{ report.project.name|title }} Threat Model

{{ report.project.description }}

{% if image %}
# Diagram
![Threat Model Diagram]({{ image }})
{% endif %}


# Exposures
{% for exposure in report.threatmodel.exposures %}
## {{ exposure.threat.name|capitalize }} against {{ exposure.component.name }}
{{ exposure.details|capitalize }}
{%- if exposure.custom %}
| Custom Key | Value |
| --- | --- |
{%- for k, v in exposure.custom.items() %}
| **{{ k|capitalize }}** | {{ v }} |
{% endfor %}
{% endif %}
{%- if exposure.description %}
### Description
{{ exposure.description }}
{% endif %}

```
{{ exposure.source.code }}
```
{% if report.repository_url %}
[{{ exposure.source.filename }}:{{ exposure.source.line }}]({{ report.repository_url }}/{{ exposure.source.filename }}#L{{ exposure.source.line }})
{% else %}
{{ exposure.source.filename }}:{{ exposure.source.line }}
{% endif %}
{% endfor %}

# Acceptances
{% for acceptance in report.threatmodel.acceptances %}
## {{ acceptance.threat.name|capitalize }} to {{ acceptance.component.name }}
{{ acceptance.details|capitalize }}
{%- if acceptance.custom %}
| Custom Key | Value |
| --- | --- |
{%- for k, v in acceptance.custom.items() %}
| **{{ k|capitalize }}** | {{ v }} |
{% endfor %}
{% endif %}
{%- if acceptance.description %}
### Description
{{ acceptance.description }}
{% endif %}

```
{{ acceptance.source.code }}
```
{% if report.repository_url %}
[{{ acceptance.source.filename }}:{{ acceptance.source.line }}]({{ report.repository_url }}/{{ acceptance.source.filename }}#L{{ acceptance.source.line }})
{% else %}
{{ acceptance.source.filename }}:{{ acceptance.source.line }}
{% endif %}
{% endfor %}

# Transfers
{% for transfer in report.threatmodel.tranfers %}
## {{ transfer.threat.name|capitalize }} from {{ transfer.source_component.name }} to {{ transfer.destination_component.name }}
{{ transfer.details|capitalize }}
{%- if transfer.custom %}
| Custom Key | Value |
| --- | --- |
{%- for k, v in transfer.custom.items() %}
| **{{ k|capitalize }}** | {{ v }} |
{% endfor %}
{% endif %}
{%- if transfer.description %}
### Description
{{ transfer.description }}
{% endif %}

```
{{ transfer.source.code }}
```
{% if report.repository_url %}
[{{ transfer.source.filename }}:{{ transfer.source.line }}]({{ report.repository_url }}/{{ transfer.source.filename }}#L{{ transfer.source.line }})
{% else %}
{{ transfer.source.filename }}:{{ transfer.source.line }}
{% endif %}
{% endfor %}

# Mitigations
{% for mitigation in report.threatmodel.mitigations %}
## {{ mitigation.threat.name|capitalize }} against {{ mitigation.component.name }} mitigated by {{ mitigation.control.name|capitalize}}
{{ mitigation.details|capitalize }}
{%- if mitigation.custom %}
| Custom Key | Value |
| --- | --- |
{%- for k, v in mitigation.custom.items() %}
| **{{ k|capitalize }}** | {{ v }} |
{% endfor %}
{% endif %}
{%- if mitigation.description %}
### Description
{{ mitigation.description }}
{% endif %}

```
{{ mitigation.source.code }}
```
{% if report.repository_url %}
[{{ mitigation.source.filename }}:{{ mitigation.source.line }}]({{ report.repository_url }}/{{ mitigation.source.filename }}#L{{ mitigation.source.line }})
{% else %}
{{ mitigation.source.filename }}:{{ mitigation.source.line }}
{% endif %}
{%- if mitigation.tests %}
### Tests
{% for test in mitigation.tests %}
#### {{ test.control.name|capitalize }} for {{ test.component.name }}
{%- if test.description %}
{{ test.description }}
{% endif %}

```
{{ test.source.code }}
```
{% if report.repository_url %}
[{{ test.source.filename }}:{{ test.source.line }}]({{ report.repository_url }}/{{ test.source.filename }}#L{{ test.source.line }})
{% else %}
{{ test.source.filename }}:{{ test.source.line }}
{% endif %}
{% endfor %}
{% endif %}
{% endfor %}

# Reviews
{% for review in report.threatmodel.reviews %}
## {{ review.component.name }}

{{ review.details }}

{{ review.description }}

{%- if review.custom %}
| Custom Key | Value |
| --- | --- |
{%- for k, v in review.custom.items() %}
| **{{ k|capitalize }}** | {{ v }} |
{% endfor %}
{% endif %}

```
{{ review.source.code }}
```
{% if report.repository_url %}
[{{ review.source.filename }}:{{ review.source.line }}]({{ report.repository_url }}/{{ review.source.filename }}#L{{ review.source.line }})
{% else %}
{{ review.source.filename }}:{{ review.source.line }}
{% endif %}
{% endfor %}

# Connections
{% for connection in report.threatmodel.connections %}
## {{ connection.source_component.name }} {{ connection.direction|capitalize }} {{ connection.destination_component.name }}
{{ connection.details }}
{%- if connection.custom %}
| Custom Key | Value |
| --- | --- |
{%- for k, v in connection.custom.items() %}
| **{{ k|capitalize }}** | {{ v }} |
{% endfor %}
{% endif %}

```
{{ connection.source.code }}
```
{% if report.repository_url %}
[{{ connection.source.filename }}:{{ connection.source.line }}]({{ report.repository_url }}/{{ connection.source.filename }}#L{{ connection.source.line }})
{% else %}
{{ connection.source.filename }}:{{ connection.source.line }}
{% endif %}
{% endfor %}

# Components
{% for component_id, component in report.components.items() %}
## {{ component.name }}
{%- if component.custom %}
| Custom Key | Value |
| --- | --- |
{%- for k, v in component.custom.items() %}
| **{{ k|capitalize }}** | {{ v }} |
{% endfor %}
{% endif %}
{%- if component.description %}
### Description
{{ component.description }}
{% endif %}
{% endfor %}

# Threats
{% for threat_id, threat in report.threats.items() %}
## {{ threat.name|capitalize }}
{%- if threat.custom %}
| Custom Key | Value |
| --- | --- |
{%- for k, v in threat.custom.items() %}
| **{{ k|capitalize }}** | {{ v }} |
{% endfor %}
{% endif %}
{% if threat.description %}
### Description
{{ threat.description }}
{% endif %}
{% endfor %}

# Controls
{% for control_id, control in report.controls.items() %}
## {{ control.name|capitalize }}
{%- if control.custom %}
| Custom Key | Value |
| --- | --- |
{%- for k, v in control.custom.items() %}
| **{{ k|capitalize }}** | {{ v }} |
{% endfor %}
{% endif %}
{%- if control.description %}
### Description
{{ control.description }}
{% endif %}
{% endfor %}
